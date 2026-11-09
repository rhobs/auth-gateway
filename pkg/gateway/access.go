package gateway

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
)

func resolveServerAccess(c *resolvedConfig, index int) error {
	server := &c.servers[index]
	field := fmt.Sprintf("servers[%d]", index)
	if server.TLSConfig != nil && server.TLSConfig.MTLS != nil {
		name := server.TLSConfig.MTLS.Authenticator
		authenticator, ok := c.authenticatorIndex[name]
		if !ok || authenticator.MTLS == nil {
			return fmt.Errorf("%s.tls_config.mtls.authenticator must reference an mTLS authenticator", field)
		}
		server.mtls = authenticator
	}
	apiKeyHeader := ""
	if c.apiKey.APIKey != nil {
		apiKeyHeader = c.apiKey.APIKey.Header
	}
	used := make(map[string]bool)
	for i := range server.APIs {
		binding := &server.APIs[i]
		bindingField := fmt.Sprintf("%s.apis[%d]", field, i)
		resolved := resolvedAPIBinding{APIBinding: binding, api: c.apiIndex[binding.Name]}
		if binding.Public {
			if binding.Access != nil || server.usesMTLS() {
				return fmt.Errorf("%s.public cannot be combined with access or server mTLS", bindingField)
			}
			if hasRequestHeaderProcessing([]gatewayapi.API{resolved.api}) {
				return fmt.Errorf("%s.public cannot forward authenticated attributes", bindingField)
			}
		} else if len(binding.Access) == 0 {
			return fmt.Errorf("%s.access must contain at least one entry (or set public: true)", bindingField)
		}
		labels := make(map[string]bool)
		for j := range binding.Access {
			entry := &binding.Access[j]
			entryField := fmt.Sprintf("%s.access[%d]", bindingField, j)
			if err := validateAccessMatch(entryField, *entry, apiKeyHeader); err != nil {
				return err
			}
			label := entry.Name + entry.Tenant
			if labels[label] {
				return fmt.Errorf("%s duplicates access label %q", entryField, label)
			}
			labels[label] = true
			for previous := range binding.Access[:j] {
				if accessMatchesOverlap(binding.Access[previous].Match, entry.Match) {
					return fmt.Errorf("%s.match overlaps access[%d]", entryField, previous)
				}
				if tenantHeadersOverlap(binding.Access[previous].Match, entry.Match) {
					return fmt.Errorf("%s.match overlaps tenant values in access[%d]", entryField, previous)
				}
			}
			selected, err := resolveAccessAuthenticators(c.authenticatorIndex, *server, entry.Authentication, entry.Authorization.ExtAuthz != nil, entryField)
			if err != nil {
				return err
			}
			access := resolvedAccess{Access: entry, id: fmt.Sprintf("server-%d-api-%d-access-%d", index, i, j), authenticators: selected}
			if err := validateAccessGrants(entryField, access); err != nil {
				return err
			}
			if err := validateExtAuthzAccess(entryField, access, c.extAuthzIndex); err != nil {
				return err
			}
			if err := validateAccessForwarding(entryField, resolved.api, access); err != nil {
				return err
			}
			for _, authenticator := range selected {
				if !used[authenticator.Name] {
					server.authenticators = append(server.authenticators, authenticator)
					used[authenticator.Name] = true
				}
				server.hasJWT = server.hasJWT || authenticator.JWT != nil
				server.hasAPIKey = server.hasAPIKey || authenticator.APIKey != nil
			}
			resolved.access = append(resolved.access, access)
		}
		server.bindings = append(server.bindings, resolved)
	}
	return nil
}

func resolveAccessAuthenticators(known map[string]gatewayapi.Authenticator, server resolvedServer, authentication *gatewayapi.Authentication, external bool, field string) ([]gatewayapi.Authenticator, error) {
	if server.usesMTLS() {
		if authentication != nil {
			return nil, fmt.Errorf("%s.authentication is forbidden on a dedicated mTLS server", field)
		}
		return []gatewayapi.Authenticator{server.mtls}, nil
	}
	if authentication == nil && external {
		return nil, nil
	}
	if authentication == nil || (authentication.JWT == nil) == (authentication.APIKey == nil) {
		return nil, fmt.Errorf("%s.authentication must select exactly one of jwt or api_key", field)
	}
	var names []string
	if authentication.JWT != nil {
		names = authentication.JWT.Providers
		field += ".authentication.jwt.providers"
	} else {
		names = []string{authentication.APIKey.Authenticator}
		field += ".authentication.api_key.authenticator"
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("%s must not be empty", field)
	}
	if err := validateUniqueReferences(field, names, known); err != nil {
		return nil, err
	}
	var selected []gatewayapi.Authenticator
	for _, name := range names {
		authenticator := known[name]
		if authentication.JWT != nil && authenticator.JWT == nil || authentication.APIKey != nil && authenticator.APIKey == nil {
			return nil, fmt.Errorf("%s references authenticator %q of the wrong type", field, name)
		}
		selected = append(selected, authenticator)
	}
	if err := validateUniqueIssuerBindings(field, names, known); err != nil {
		return nil, err
	}
	return selected, nil
}

func validateAccessMatch(field string, entry gatewayapi.Access, apiKeyHeader string) error {
	if (entry.Tenant == "") == (entry.Name == "") {
		return fmt.Errorf("%s must set exactly one of tenant or name", field)
	}
	if entry.Name != "" {
		if err := validateGatewayName(field, entry.Name); err != nil {
			return err
		}
	} else if !validCredentialText(entry.Tenant) || strings.Contains(entry.Tenant, ",") {
		return fmt.Errorf("%s.tenant must be a nonempty single value", field)
	}
	seen := make(map[string]bool)
	for _, header := range slices.Sorted(maps.Keys(entry.Match.Headers)) {
		lower := strings.ToLower(header)
		if !validHeaderFieldName(header) || strings.Contains(header, "_") || forbiddenIdentityHeader(lower) || strings.EqualFold(header, apiKeyHeader) {
			return fmt.Errorf("%s.match.headers contains unsafe header %q", field, header)
		}
		if seen[lower] {
			return fmt.Errorf("%s.match.headers duplicates header %q ignoring case", field, header)
		}
		seen[lower] = true
		matcher := entry.Match.Headers[header]
		if (matcher.Exact == nil) == (matcher.In == nil) {
			return fmt.Errorf("%s.match.headers.%s must select exactly one of exact or in", field, header)
		}
		values := headerMatchValues(matcher)
		if len(values) == 0 {
			return fmt.Errorf("%s.match.headers.%s.in must not be empty", field, header)
		}
		unique := make(map[string]bool)
		for _, value := range values {
			if !validCredentialText(value) || strings.Contains(value, ",") || unique[value] {
				return fmt.Errorf("%s.match.headers.%s must contain distinct nonempty values without commas or controls", field, header)
			}
			unique[value] = true
		}
	}
	return nil
}

func headerMatchValues(match gatewayapi.HeaderMatch) []string {
	if match.Exact != nil {
		return []string{*match.Exact}
	}
	return match.In
}

func accessMatchesOverlap(first, second gatewayapi.AccessMatch) bool {
	for name, firstMatch := range first.Headers {
		for other, secondMatch := range second.Headers {
			if strings.EqualFold(name, other) && !headerMatchesOverlap(firstMatch, secondMatch) {
				return false
			}
		}
	}
	return true
}

func headerMatchesOverlap(first, second gatewayapi.HeaderMatch) bool {
	for _, value := range headerMatchValues(first) {
		if slices.Contains(headerMatchValues(second), value) {
			return true
		}
	}
	return false
}

func tenantHeadersOverlap(first, second gatewayapi.AccessMatch) bool {
	for name, firstMatch := range first.Headers {
		if !strings.EqualFold(name, "X-Tenant") {
			continue
		}
		for other, secondMatch := range second.Headers {
			if strings.EqualFold(name, other) {
				return headerMatchesOverlap(firstMatch, secondMatch)
			}
		}
	}
	return false
}

func validateAccessGrants(field string, access resolvedAccess) error {
	if access.Authorization.ExtAuthz != nil {
		if access.Authorization.Grants != nil {
			return fmt.Errorf("%s.authorization must select exactly one of grants or ext_authz", field)
		}
		return nil
	}
	if len(access.Authorization.Grants) == 0 {
		return fmt.Errorf("%s.authorization.grants must not be empty", field)
	}
	selected := make(map[string]gatewayapi.Authenticator)
	for _, authenticator := range access.authenticators {
		selected[authenticator.Name] = authenticator
	}
	for index, grant := range access.Authorization.Grants {
		grantField := fmt.Sprintf("%s.authorization.grants[%d]", field, index)
		authenticator, exists := selected[grant.Authenticator]
		if !exists {
			return fmt.Errorf("%s.authenticator %q is not enabled by this access entry", grantField, grant.Authenticator)
		}
		if len(grant.Attributes) == 0 && authenticator.MTLS == nil {
			return fmt.Errorf("%s.attributes must not be empty", grantField)
		}
		for _, name := range slices.Sorted(maps.Keys(grant.Attributes)) {
			condition := grant.Attributes[name]
			attributeField := grantField + ".attributes." + name
			if condition == nil {
				return fmt.Errorf("%s must contain values or equals_attribute", attributeField)
			}
			source, ok := authenticator.Attributes[name]
			if !ok || !attributeNamePattern.MatchString(name) {
				return fmt.Errorf("%s is not declared by authenticator %q", attributeField, authenticator.Name)
			}
			if source.Header != nil {
				return fmt.Errorf("%s must use a verified credential attribute, not a header source", attributeField)
			}
			if condition.EqualsAttribute != "" {
				if condition.Values != nil {
					return fmt.Errorf("%s cannot combine values and equals_attribute", attributeField)
				}
				other, ok := authenticator.Attributes[condition.EqualsAttribute]
				if !ok {
					return fmt.Errorf("%s.equals_attribute references undeclared attribute %q", attributeField, condition.EqualsAttribute)
				}
				if other.Header != nil && !accessMatchesHeader(access.Match, *other.Header) {
					return fmt.Errorf("%s.equals_attribute header %q must be selected in match.headers", attributeField, *other.Header)
				}
				continue
			}
			if len(condition.Values) == 0 {
				return fmt.Errorf("%s must contain values or equals_attribute", attributeField)
			}
			seen := make(map[string]bool)
			for _, value := range condition.Values {
				if !validCredentialText(value) || seen[value] {
					return fmt.Errorf("%s must contain distinct nonempty values without controls", attributeField)
				}
				seen[value] = true
			}
		}
	}
	return nil
}

func accessMatchesHeader(match gatewayapi.AccessMatch, header string) bool {
	for name := range match.Headers {
		if strings.EqualFold(name, header) {
			return true
		}
	}
	return false
}

func validateAccessForwarding(field string, api gatewayapi.API, access resolvedAccess) error {
	for _, route := range api.Routes {
		if route.Processing == nil {
			continue
		}
		for _, mapping := range route.Processing.RequestHeaders {
			if access.Authorization.ExtAuthz != nil {
				if _, ok := access.Authorization.ExtAuthz.ResponseAttributes[mapping.FromAttribute]; ok {
					continue
				}
			}
			if len(access.authenticators) == 0 {
				return fmt.Errorf("%s does not provide processing attribute %q", field, mapping.FromAttribute)
			}
			for _, authenticator := range access.authenticators {
				if !providesAttributeAuthenticator(authenticator, mapping.FromAttribute) {
					return fmt.Errorf("%s authenticator %q does not provide processing attribute %q", field, authenticator.Name, mapping.FromAttribute)
				}
			}
		}
	}
	return nil
}

func validateUniqueReferences[V any](field string, names []string, known map[string]V) error {
	seen := make(map[string]bool)
	for _, name := range names {
		if _, ok := known[name]; !ok {
			return fmt.Errorf("%s references unknown name %q", field, name)
		}
		if seen[name] {
			return fmt.Errorf("%s duplicates name %q", field, name)
		}
		seen[name] = true
	}
	return nil
}

func cloneAPIBinding(binding gatewayapi.APIBinding) gatewayapi.APIBinding {
	binding.Access = cloneSlice(binding.Access, cloneAccess)
	return binding
}

func cloneAccess(access gatewayapi.Access) gatewayapi.Access {
	access.Match.Headers = maps.Clone(access.Match.Headers)
	for name, match := range access.Match.Headers {
		match.Exact = clonePointer(match.Exact)
		match.In = slices.Clone(match.In)
		access.Match.Headers[name] = match
	}
	access.Authentication = cloneConfigPointer(access.Authentication, cloneAuthentication)
	access.Authorization.Grants = cloneSlice(access.Authorization.Grants, cloneAuthorizationGrant)
	access.Authorization.ExtAuthz = cloneConfigPointer(access.Authorization.ExtAuthz, cloneExternalAuthorization)
	return access
}

func cloneAuthentication(authentication gatewayapi.Authentication) gatewayapi.Authentication {
	if authentication.JWT != nil {
		authentication.JWT = &gatewayapi.JWTAuthentication{Providers: slices.Clone(authentication.JWT.Providers)}
	}
	authentication.APIKey = clonePointer(authentication.APIKey)
	return authentication
}

func cloneAuthorizationGrant(grant gatewayapi.AuthorizationGrant) gatewayapi.AuthorizationGrant {
	grant.Attributes = maps.Clone(grant.Attributes)
	for name, condition := range grant.Attributes {
		condition = clonePointer(condition)
		if condition != nil {
			condition.Values = slices.Clone(condition.Values)
		}
		grant.Attributes[name] = condition
	}
	return grant
}
