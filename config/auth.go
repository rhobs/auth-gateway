package config

import (
	"fmt"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
)

var attributeNamePattern = regexp.MustCompile("^[a-z][a-z0-9_-]{0,63}$")

// Authenticator defines one named credential validator.
type Authenticator struct {
	Name string            `yaml:"name"`
	JWT  *JWTAuthenticator `yaml:"jwt,omitempty"`
}

// JWTAuthenticator validates one issuer and maps its verified claims.
type JWTAuthenticator struct {
	Issuer     string                  `yaml:"issuer"`
	JWKSURI    string                  `yaml:"jwks_uri"`
	Audiences  []string                `yaml:"audiences"`
	Attributes map[string]JWTAttribute `yaml:"attributes,omitempty"`
}

// JWTAttribute selects a literal object path and can translate source values.
type JWTAttribute struct {
	ClaimPath []string          `yaml:"claim_path"`
	Mappings  map[string]string `yaml:"mappings,omitempty"`
}

// AuthorizationPolicy contains allow grants for named APIs.
type AuthorizationPolicy struct {
	Name   string               `yaml:"name"`
	Grants []AuthorizationGrant `yaml:"grants,omitempty"`
}

// AuthorizationGrant allows selected APIs for mapped attributes from one authenticator.
type AuthorizationGrant struct {
	Authenticator string              `yaml:"authenticator"`
	APIs          []string            `yaml:"apis"`
	Attributes    map[string][]string `yaml:"attributes"`
}

// Authentication selects credential validators for a server.
type Authentication struct {
	AnyOf []string `yaml:"any_of,omitempty"`
	AllOf []string `yaml:"all_of,omitempty"`
}

// Authorization selects policies for a server.
type Authorization struct {
	AnyOf []string `yaml:"any_of,omitempty"`
	AllOf []string `yaml:"all_of,omitempty"`
}

// RouteProcessing describes optional per-route request processing.
type RouteProcessing struct {
	RequestHeaders []RequestHeaderMapping `yaml:"request_headers,omitempty"`
}

// RequestHeaderMapping sets an upstream header from a mapped identity attribute.
type RequestHeaderMapping struct {
	Name          string `yaml:"name"`
	FromAttribute string `yaml:"from_attribute"`
}

func (c Config) validateAuthentication(apis map[string]API) error {
	authenticators := make(map[string]Authenticator, len(c.Authenticators))
	for i, authenticator := range c.Authenticators {
		name := fmt.Sprintf("authenticators[%d]", i)
		if !apiNamePattern.MatchString(authenticator.Name) {
			return fmt.Errorf("%s.name must start with a lowercase letter and contain only lowercase letters, numbers, or hyphens", name)
		}
		if _, exists := authenticators[authenticator.Name]; exists {
			return fmt.Errorf("duplicate authenticator name %q", authenticator.Name)
		}
		if authenticator.JWT == nil {
			return fmt.Errorf("%s.jwt is required; only JWT authenticators are supported", name)
		}
		if err := validateJWTAuthenticator(name+".jwt", *authenticator.JWT); err != nil {
			return err
		}
		authenticators[authenticator.Name] = authenticator
	}

	policies := make(map[string]AuthorizationPolicy, len(c.AuthorizationPolicies))
	for i, policy := range c.AuthorizationPolicies {
		name := fmt.Sprintf("authorization_policies[%d]", i)
		if !apiNamePattern.MatchString(policy.Name) {
			return fmt.Errorf("%s.name must start with a lowercase letter and contain only lowercase letters, numbers, or hyphens", name)
		}
		if _, exists := policies[policy.Name]; exists {
			return fmt.Errorf("duplicate authorization policy name %q", policy.Name)
		}
		policies[policy.Name] = policy
	}

	apiNames := make(map[string]struct{}, len(apis))
	for name := range apis {
		apiNames[name] = struct{}{}
	}
	for i, policy := range c.AuthorizationPolicies {
		for j, grant := range policy.Grants {
			name := fmt.Sprintf("authorization_policies[%d].grants[%d]", i, j)
			authenticator, exists := authenticators[grant.Authenticator]
			if !exists {
				return fmt.Errorf("%s.authenticator references unknown authenticator %q", name, grant.Authenticator)
			}
			if len(grant.APIs) == 0 {
				return fmt.Errorf("%s.apis must contain at least one API", name)
			}
			if err := validateUniqueReferences(name+".apis", grant.APIs, apiNames); err != nil {
				return err
			}
			if len(grant.Attributes) == 0 {
				return fmt.Errorf("%s.attributes must contain at least one attribute allowlist", name)
			}
			for _, attribute := range sortedKeys(grant.Attributes) {
				if !attributeNamePattern.MatchString(attribute) {
					return fmt.Errorf("%s.attributes contains invalid attribute name %q", name, attribute)
				}
				if _, exists := authenticator.JWT.Attributes[attribute]; !exists {
					return fmt.Errorf("%s.attributes references attribute %q not provided by authenticator %q", name, attribute, grant.Authenticator)
				}
				values := grant.Attributes[attribute]
				if len(values) == 0 {
					return fmt.Errorf("%s.attributes.%s must contain at least one allowed value", name, attribute)
				}
				seenValues := make(map[string]struct{}, len(values))
				for _, value := range values {
					if value == "" || strings.TrimSpace(value) != value {
						return fmt.Errorf("%s.attributes.%s values must not be empty or have surrounding whitespace", name, attribute)
					}
					if _, exists := seenValues[value]; exists {
						return fmt.Errorf("%s.attributes.%s contains duplicate value %q", name, attribute, value)
					}
					seenValues[value] = struct{}{}
				}
			}
		}
	}

	for i, server := range c.Servers {
		name := fmt.Sprintf("servers[%d]", i)
		if server.Authentication != nil {
			if _, err := validateSelection(name+".authentication", server.Authentication.AnyOf, server.Authentication.AllOf, authenticatorNames(authenticators)); err != nil {
				return err
			}
			if len(server.Authentication.AllOf) > 1 {
				return fmt.Errorf("%s.authentication.all_of cannot contain more than one JWT authenticator", name)
			}
		}
		if server.Authorization != nil {
			if server.Authentication == nil {
				return fmt.Errorf("%s.authorization requires authentication", name)
			}
			if _, err := validateSelection(name+".authorization", server.Authorization.AnyOf, server.Authorization.AllOf, policyNames(policies)); err != nil {
				return err
			}
		}
		if err := validateRouteAttributeSources(name, server, apis, authenticators); err != nil {
			return err
		}
	}
	return nil
}

func (c Config) hasAuthenticationConfig() bool {
	if len(c.Authenticators) != 0 || len(c.AuthorizationPolicies) != 0 {
		return true
	}
	for _, server := range c.Servers {
		if server.Authentication != nil || server.Authorization != nil {
			return true
		}
	}
	for _, api := range c.APIs {
		for _, route := range api.Routes {
			if route.Processing != nil {
				return true
			}
		}
	}
	return false
}

func validateJWTAuthenticator(name string, jwt JWTAuthenticator) error {
	if jwt.Issuer == "" || strings.TrimSpace(jwt.Issuer) != jwt.Issuer || strings.ContainsAny(jwt.Issuer, "\r\n\t") {
		return fmt.Errorf("%s.issuer must be a nonempty issuer identifier without surrounding whitespace", name)
	}
	parsed, err := url.Parse(jwt.JWKSURI)
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" || parsed.Opaque != "" {
		return fmt.Errorf("%s.jwks_uri must be an absolute HTTPS URL without user information or a fragment", name)
	}
	if port := parsed.Port(); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 {
			return fmt.Errorf("%s.jwks_uri must use a valid port", name)
		}
	}
	if len(jwt.Audiences) == 0 {
		return fmt.Errorf("%s.audiences must contain at least one audience", name)
	}
	seenAudiences := make(map[string]struct{}, len(jwt.Audiences))
	for _, audience := range jwt.Audiences {
		if audience == "" || strings.TrimSpace(audience) != audience || strings.ContainsAny(audience, "\r\n\t") {
			return fmt.Errorf("%s.audiences must not contain empty values or surrounding whitespace", name)
		}
		if _, exists := seenAudiences[audience]; exists {
			return fmt.Errorf("%s.audiences contains duplicate value %q", name, audience)
		}
		seenAudiences[audience] = struct{}{}
	}
	for _, attribute := range sortedKeys(jwt.Attributes) {
		if !attributeNamePattern.MatchString(attribute) {
			return fmt.Errorf("%s.attributes contains invalid attribute name %q", name, attribute)
		}
		mapping := jwt.Attributes[attribute]
		if len(mapping.ClaimPath) == 0 {
			return fmt.Errorf("%s.attributes.%s.claim_path must contain at least one literal object key", name, attribute)
		}
		if slices.Contains(mapping.ClaimPath, "") {
			return fmt.Errorf("%s.attributes.%s.claim_path keys must not be empty", name, attribute)
		}

		for _, source := range sortedKeys(mapping.Mappings) {
			target := mapping.Mappings[source]
			if source == "" || target == "" || strings.TrimSpace(source) != source || strings.TrimSpace(target) != target {
				return fmt.Errorf("%s.attributes.%s.mappings keys and values must not be empty or have surrounding whitespace", name, attribute)
			}
			if strings.ContainsAny(target, "\r\n\x00") {
				return fmt.Errorf("%s.attributes.%s.mappings values must not contain line breaks or NUL", name, attribute)
			}
		}
	}
	return nil
}

func validateRouteProcessing(name string, processing *RouteProcessing) error {
	if processing == nil {
		return nil
	}
	if len(processing.RequestHeaders) == 0 {
		return fmt.Errorf("%s.request_headers must contain at least one header mapping", name)
	}
	seen := make(map[string]struct{}, len(processing.RequestHeaders))
	for i, mapping := range processing.RequestHeaders {
		mappingName := fmt.Sprintf("%s.request_headers[%d]", name, i)
		if !validHeaderFieldName(mapping.Name) {
			return fmt.Errorf("%s.name must be a valid HTTP header field name", mappingName)
		}
		lowerName := strings.ToLower(mapping.Name)
		if forbiddenIdentityHeader(lowerName) {
			return fmt.Errorf("%s.name %q is reserved for credentials, routing, connection, or message framing", mappingName, mapping.Name)
		}
		if _, exists := seen[lowerName]; exists {
			return fmt.Errorf("%s.name %q is duplicated", name, mapping.Name)
		}
		seen[lowerName] = struct{}{}
		if !attributeNamePattern.MatchString(mapping.FromAttribute) {
			return fmt.Errorf("%s.from_attribute must be a valid attribute name", mappingName)
		}
	}
	return nil
}

func validateSelection(name string, anyOf, allOf []string, known map[string]struct{}) ([]string, error) {
	if (anyOf == nil) == (allOf == nil) {
		return nil, fmt.Errorf("%s must set exactly one of any_of or all_of", name)
	}
	values := anyOf
	field := "any_of"
	if allOf != nil {
		values = allOf
		field = "all_of"
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("%s.%s must contain at least one name", name, field)
	}
	if err := validateUniqueReferences(name+"."+field, values, known); err != nil {
		return nil, err
	}
	return values, nil
}

func validateUniqueReferences(name string, values []string, known map[string]struct{}) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" || strings.TrimSpace(value) != value {
			return fmt.Errorf("%s names must not be empty or have surrounding whitespace", name)
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("%s contains duplicate name %q", name, value)
		}
		seen[value] = struct{}{}
		if _, exists := known[value]; !exists {
			return fmt.Errorf("%s references unknown name %q", name, value)
		}
	}
	return nil
}

func validateRouteAttributeSources(serverName string, server Server, apis map[string]API, authenticators map[string]Authenticator) error {
	bound, err := server.boundAPIs(apis)
	if err != nil {
		return nil // validateServers reports the API binding error with its indexed path.
	}
	for _, api := range bound {
		for routeIndex, route := range api.Routes {
			if route.Processing == nil {
				continue
			}
			if server.Authentication == nil {
				return fmt.Errorf("%s processing on API %q route %d requires authentication", serverName, api.Name, routeIndex)
			}
			selected := server.Authentication.AnyOf
			allOf := server.Authentication.AllOf != nil
			if allOf {
				selected = server.Authentication.AllOf
			}
			for _, header := range route.Processing.RequestHeaders {
				provided := false
				for _, name := range selected {
					_, exists := authenticators[name].JWT.Attributes[header.FromAttribute]
					if allOf && exists {
						provided = true
						break
					}
					if !allOf && !exists {
						return fmt.Errorf("%s authentication method %q does not provide processing attribute %q", serverName, name, header.FromAttribute)
					}
					provided = provided || exists
				}
				if !provided {
					return fmt.Errorf("%s authentication does not provide processing attribute %q", serverName, header.FromAttribute)
				}
			}
		}
	}
	return nil
}

func validHeaderFieldName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		ch := name[i]
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') {
			continue
		}
		switch ch {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		default:
			return false
		}
	}
	return true
}

func forbiddenIdentityHeader(name string) bool {
	switch name {
	case "authorization", "proxy-authorization", "cookie", "host", "connection", "keep-alive", "proxy-connection",
		"transfer-encoding", "content-length", "trailer", "te", "upgrade", "forwarded", "x-forwarded-for",
		"x-forwarded-host", "x-forwarded-proto", "x-forwarded-port", "x-envoy-original-path", "x-envoy-original-host",
		"x-envoy-upstream-cluster", "x-envoy-decorator-operation":
		return true
	default:
		return strings.HasPrefix(name, "proxy-")
	}
}

func authenticatorNames(values map[string]Authenticator) map[string]struct{} {
	return mapKeys(values)
}

func policyNames(values map[string]AuthorizationPolicy) map[string]struct{} {
	return mapKeys(values)
}

func mapKeys[V any](values map[string]V) map[string]struct{} {
	keys := make(map[string]struct{}, len(values))
	for key := range values {
		keys[key] = struct{}{}
	}
	return keys
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func cloneAuthenticators(values []Authenticator) []Authenticator {
	if values == nil {
		return nil
	}
	out := make([]Authenticator, len(values))
	for i, value := range values {
		out[i] = value
		if value.JWT != nil {
			jwt := *value.JWT
			jwt.Audiences = cloneSlice(value.JWT.Audiences)
			if value.JWT.Attributes != nil {
				jwt.Attributes = make(map[string]JWTAttribute, len(value.JWT.Attributes))
				for name, attribute := range value.JWT.Attributes {
					attribute.ClaimPath = cloneSlice(attribute.ClaimPath)
					attribute.Mappings = cloneMap(attribute.Mappings)
					jwt.Attributes[name] = attribute
				}
			}
			out[i].JWT = &jwt
		}
	}
	return out
}

func cloneAuthorizationPolicies(values []AuthorizationPolicy) []AuthorizationPolicy {
	if values == nil {
		return nil
	}
	out := make([]AuthorizationPolicy, len(values))
	for i, value := range values {
		out[i] = value
		out[i].Grants = cloneSlice(value.Grants)
		for j := range out[i].Grants {
			out[i].Grants[j].APIs = cloneSlice(value.Grants[j].APIs)
			if value.Grants[j].Attributes != nil {
				out[i].Grants[j].Attributes = make(map[string][]string, len(value.Grants[j].Attributes))
				for name, allowed := range value.Grants[j].Attributes {
					out[i].Grants[j].Attributes[name] = cloneSlice(allowed)
				}
			}
		}
	}
	return out
}

func cloneAuthentication(value *Authentication) *Authentication {
	if value == nil {
		return nil
	}
	cloned := *value
	cloned.AnyOf = cloneSlice(value.AnyOf)
	cloned.AllOf = cloneSlice(value.AllOf)
	return &cloned
}

func cloneAuthorization(value *Authorization) *Authorization {
	if value == nil {
		return nil
	}
	cloned := *value
	cloned.AnyOf = cloneSlice(value.AnyOf)
	cloned.AllOf = cloneSlice(value.AllOf)
	return &cloned
}

func cloneMap[K comparable, V any](values map[K]V) map[K]V {
	if values == nil {
		return nil
	}
	out := make(map[K]V, len(values))
	maps.Copy(out, values)
	return out
}

func cloneSlice[V any](values []V) []V {
	if values == nil {
		return nil
	}
	out := make([]V, len(values))
	copy(out, values)
	return out
}
