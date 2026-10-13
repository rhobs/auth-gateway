package config

import (
	"fmt"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	invalidJWTTextCharacters           = "\r\n\t"
	attributeNameValidationErrorFormat = "%s.attributes contains invalid attribute name %q"
	attributeMapperType                = "attribute-mapper"
	defaultAPIKeyHeader                = "X-API-Key"
	authorizationHeaderName            = "authorization"
)

var attributeNamePattern = regexp.MustCompile("^[a-z][a-z0-9_-]{0,63}$")

func validateUniqueIssuerBindings(name string, selected []string, authenticators map[string]Authenticator) error {
	seen := make(map[string]string, len(selected))
	for _, authenticatorName := range selected {
		jwt := authenticators[authenticatorName].JWT
		if jwt == nil {
			continue
		}
		issuer := jwt.Issuer
		if previous, exists := seen[issuer]; exists {
			return fmt.Errorf("%s binds authenticators %q and %q with the same issuer %q", name, previous, authenticatorName, issuer)
		}
		seen[issuer] = authenticatorName
	}
	return nil
}

func validatePermissiveJWTIssuerBindings(servers []Server, authenticators map[string]Authenticator) error {
	selected := make([]string, 0, len(authenticators))
	seen := make(map[string]struct{}, len(authenticators))
	mixedServer := -1
	for index, server := range servers {
		if server.TLSConfig != nil || server.Authentication == nil {
			continue
		}
		names := server.Authentication.AnyOf
		if names == nil {
			names = server.Authentication.AllOf
		}
		hasOther, hasJWT := false, false
		for _, name := range names {
			if authenticators[name].JWT != nil {
				hasJWT = true
				if _, exists := seen[name]; !exists {
					selected = append(selected, name)
					seen[name] = struct{}{}
				}
			} else {
				hasOther = true
			}
		}
		if server.Authentication.AnyOf != nil && hasOther && hasJWT {
			mixedServer = index
		}
	}
	if mixedServer < 0 {
		return nil
	}
	return validateUniqueIssuerBindings(fmt.Sprintf("servers[%d].authentication.any_of", mixedServer), selected, authenticators)
}

func validateAPIKeyAuthenticator(name string, apiKey APIKeyAuthenticator, requireSecret bool) error {
	if (requireSecret || apiKey.Secret != "") && len(validation.IsDNS1123Subdomain(apiKey.Secret)) != 0 {
		return fmt.Errorf("%s.secret must be a Kubernetes Secret name", name)
	}
	if !validHeaderFieldName(apiKey.Header) || strings.Contains(apiKey.Header, "_") || forbiddenIdentityHeader(strings.ToLower(apiKey.Header)) {
		return fmt.Errorf("%s.header must be a safe HTTP credential header name", name)
	}
	return nil
}

func validateJWTAuthenticator(name string, jwt JWTAuthenticator) error {
	if jwt.Issuer == "" || strings.TrimSpace(jwt.Issuer) != jwt.Issuer || strings.ContainsAny(jwt.Issuer, invalidJWTTextCharacters) {
		return fmt.Errorf("%s.issuer must be a nonempty issuer identifier without surrounding whitespace", name)
	}
	parsed, err := url.Parse(jwt.JWKS.URI)
	if err != nil || !strings.EqualFold(parsed.Scheme, httpsProtocolToken) || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" || parsed.Opaque != "" {
		return fmt.Errorf("%s.jwks.uri must be an absolute HTTPS URL without user information or a fragment", name)
	}
	if !validHost(strings.ToLower(parsed.Hostname())) || strings.HasSuffix(parsed.Host, ":") {
		return fmt.Errorf("%s.jwks.uri must use a valid DNS name or IP address and optional port", name)
	}
	if port := parsed.Port(); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 {
			return fmt.Errorf("%s.jwks.uri must use a valid port", name)
		}
	}
	seenAudiences := make(map[string]struct{}, len(jwt.Audiences))
	for _, audience := range jwt.Audiences {
		if audience == "" || strings.TrimSpace(audience) != audience || strings.ContainsAny(audience, invalidJWTTextCharacters) {
			return fmt.Errorf("%s.audiences must not contain empty values or surrounding whitespace", name)
		}
		if _, exists := seenAudiences[audience]; exists {
			return fmt.Errorf("%s.audiences contains duplicate value %q", name, audience)
		}
		seenAudiences[audience] = struct{}{}
	}
	return nil
}

func validateAuthenticatorAttributes(name string, authenticator Authenticator, apiKeyHeader string) error {
	for _, attribute := range slices.Sorted(maps.Keys(authenticator.Attributes)) {
		if !attributeNamePattern.MatchString(attribute) {
			return fmt.Errorf(attributeNameValidationErrorFormat, name, attribute)
		}
		source := authenticator.Attributes[attribute]
		field := name + ".attributes." + attribute
		if authenticator.JWT != nil {
			if source.Credential != nil || source.URISAN != nil || source.DNSSAN != nil || (source.ClaimPath == nil) == (source.Header == nil) {
				return fmt.Errorf("%s must set exactly one of claim_path or header", field)
			}
		} else if authenticator.APIKey != nil {
			if source.ClaimPath != nil || source.URISAN != nil || source.DNSSAN != nil || (source.Credential == nil) == (source.Header == nil) {
				return fmt.Errorf("%s must set exactly one of credential: true or header", field)
			}
		} else {
			sources := 0
			for _, present := range []bool{source.Header != nil, source.URISAN != nil, source.DNSSAN != nil} {
				if present {
					sources++
				}
			}
			if source.ClaimPath != nil || source.Credential != nil || sources != 1 {
				return fmt.Errorf("%s must set exactly one of uri_san: true, dns_san: true, or header", field)
			}
		}
		if source.ClaimPath != nil {
			if len(source.ClaimPath) == 0 {
				return fmt.Errorf("%s.claim_path must contain at least one literal object key", field)
			}
			if slices.Contains(source.ClaimPath, "") {
				return fmt.Errorf("%s.claim_path keys must not be empty", field)
			}
		}
		if source.Credential != nil && !*source.Credential {
			return fmt.Errorf("%s.credential must be true", field)
		}
		if source.URISAN != nil && !*source.URISAN {
			return fmt.Errorf("%s.uri_san must be true", field)
		}
		if source.DNSSAN != nil && !*source.DNSSAN {
			return fmt.Errorf("%s.dns_san must be true", field)
		}
		if source.Header != nil {
			header := *source.Header
			lower := strings.ToLower(header)
			if !validHeaderFieldName(header) || strings.Contains(header, "_") || forbiddenIdentityHeader(lower) {
				return fmt.Errorf("%s.header must be a safe HTTP request header name", field)
			}
			if strings.EqualFold(header, apiKeyHeader) {
				return fmt.Errorf("%s.header is reserved for API-key credentials", field)
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
			return fmt.Errorf("%s.name %q is duplicated", mappingName, mapping.Name)
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
			if server.Authentication.AllOf != nil {
				selected = server.Authentication.AllOf
			}
			for _, header := range route.Processing.RequestHeaders {
				provided := false
				for _, name := range selected {
					if authenticators[name].providesAttribute(header.FromAttribute) {
						provided = true
						break
					}
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
	if isRequestControlHeader(name) {
		return true
	}
	switch name {
	case authorizationHeaderName, "proxy-authorization", "cookie", "host", "connection", "keep-alive", "proxy-connection",
		"transfer-encoding", "content-length", "trailer", "te", "upgrade", "forwarded", "x-forwarded-for",
		"x-forwarded-host", "x-forwarded-proto", "x-forwarded-port", "x-envoy-original-path", "x-envoy-original-host",
		"x-envoy-upstream-cluster", "x-envoy-decorator-operation":
		return true
	default:
		return strings.HasPrefix(name, "proxy-") || strings.HasPrefix(name, "x-auth-gateway-")
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
