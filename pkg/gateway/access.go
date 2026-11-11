package gateway

import (
	"fmt"
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
		resolved := resolvedAPIBinding{APIBinding: binding, index: i, api: c.apiIndex[binding.Name]}
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
				if credentialSelectorsDisjoint(binding.Access[previous].Match, entry.Match, apiKeyHeader) {
					continue
				}
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
			if err := validateAccessForwarding(entryField, resolved.api, access, c.extAuthzIndex); err != nil {
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
	for index, condition := range entry.Match.Headers {
		header := condition.Name
		conditionField := fmt.Sprintf("%s.match.headers[%d]", field, index)
		lower := strings.ToLower(header)
		isAPIKeyHeader := apiKeyHeader != "" && strings.EqualFold(header, apiKeyHeader)
		credentialHeader := lower == authorizationHeaderName || isAPIKeyHeader
		reserved := forbiddenIdentityHeader(lower) || isAPIKeyHeader
		allowCredentialPresence := credentialHeader && condition.Expression == gatewayapi.ExpressionPresent
		if !validHeaderFieldName(header) || strings.Contains(header, "_") ||
			reserved && !allowCredentialPresence {
			return fmt.Errorf("%s contains unsafe header %q", conditionField, header)
		}
		if lower == authorizationHeaderName && (entry.Authentication == nil || entry.Authentication.JWT == nil) {
			return fmt.Errorf("%s Authorization presence requires JWT authentication", conditionField)
		}
		if isAPIKeyHeader && (entry.Authentication == nil || entry.Authentication.APIKey == nil) {
			return fmt.Errorf("%s API-key header presence requires API-key authentication", conditionField)
		}
		if seen[lower] {
			return fmt.Errorf("%s duplicates header %q ignoring case", conditionField, header)
		}
		seen[lower] = true
		if err := validateMatchExpression(conditionField, condition, false); err != nil {
			return err
		}
		for _, value := range matchValues(condition) {
			if strings.Contains(value, ",") {
				return fmt.Errorf("%s.value must not contain commas", conditionField)
			}
		}
	}
	return nil
}

func validateMatchExpression(field string, condition gatewayapi.MatchExpression, allowAttribute bool) error {
	switch condition.Expression {
	case gatewayapi.ExpressionPresent:
		if condition.Value.Text != "" || condition.Value.IsList || len(condition.Value.Items) != 0 {
			return fmt.Errorf("%s.value must be omitted for present", field)
		}
	case gatewayapi.ExpressionEquals, gatewayapi.ExpressionEqualsAttribute, gatewayapi.ExpressionHas:
		if condition.Expression == gatewayapi.ExpressionEqualsAttribute && !allowAttribute {
			return fmt.Errorf("%s.expression equals-attribute is only valid for attributes", field)
		}
		if condition.Expression == gatewayapi.ExpressionHas && !allowAttribute {
			return fmt.Errorf("%s.expression has is only valid for attributes", field)
		}
		if condition.Value.IsList || len(condition.Value.Items) != 0 || !validCredentialText(condition.Value.Text) {
			return fmt.Errorf("%s.value must be a nonempty string without controls", field)
		}
	case gatewayapi.ExpressionIn, gatewayapi.ExpressionHasOneOf:
		if condition.Expression == gatewayapi.ExpressionHasOneOf && !allowAttribute {
			return fmt.Errorf("%s.expression has-one-of is only valid for attributes", field)
		}
		if !condition.Value.IsList || condition.Value.Text != "" || len(condition.Value.Items) == 0 {
			return fmt.Errorf("%s.value must be a nonempty list of strings", field)
		}
		seen := make(map[string]bool)
		for _, value := range condition.Value.Items {
			if !validCredentialText(value) || seen[value] {
				return fmt.Errorf("%s.value must contain distinct nonempty strings without controls", field)
			}
			seen[value] = true
		}
	default:
		return fmt.Errorf("%s.expression must be equals, equals-attribute, has, has-one-of, in, or present", field)
	}
	return nil
}

func matchValues(condition gatewayapi.MatchExpression) []string {
	if condition.Expression == gatewayapi.ExpressionIn || condition.Expression == gatewayapi.ExpressionHasOneOf {
		return condition.Value.Items
	}
	if condition.Expression == gatewayapi.ExpressionPresent {
		return nil
	}
	return []string{condition.Value.Text}
}

func credentialSelectorsDisjoint(first, second gatewayapi.AccessMatch, apiKeyHeader string) bool {
	if apiKeyHeader == "" {
		return false
	}
	// The first HTTP filter rejects requests carrying both credential headers.
	return accessHasPresentHeader(first, authorizationHeaderName) && accessHasPresentHeader(second, apiKeyHeader) ||
		accessHasPresentHeader(first, apiKeyHeader) && accessHasPresentHeader(second, authorizationHeaderName)
}

func accessHasPresentHeader(match gatewayapi.AccessMatch, header string) bool {
	for _, condition := range match.Headers {
		if strings.EqualFold(condition.Name, header) && condition.Expression == gatewayapi.ExpressionPresent {
			return true
		}
	}
	return false
}

func accessMatchesOverlap(first, second gatewayapi.AccessMatch) bool {
	for _, firstMatch := range first.Headers {
		for _, secondMatch := range second.Headers {
			if strings.EqualFold(firstMatch.Name, secondMatch.Name) && !headerMatchesOverlap(firstMatch, secondMatch) {
				return false
			}
		}
	}
	return true
}

func headerMatchesOverlap(first, second gatewayapi.MatchExpression) bool {
	if first.Expression == gatewayapi.ExpressionPresent || second.Expression == gatewayapi.ExpressionPresent {
		return true
	}
	for _, value := range matchValues(first) {
		if slices.Contains(matchValues(second), value) {
			return true
		}
	}
	return false
}

func tenantHeadersOverlap(first, second gatewayapi.AccessMatch) bool {
	for _, firstMatch := range first.Headers {
		if !strings.EqualFold(firstMatch.Name, "X-Tenant") {
			continue
		}
		for _, secondMatch := range second.Headers {
			if strings.EqualFold(secondMatch.Name, "X-Tenant") {
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
		seen := make(map[string]bool)
		for attributeIndex, condition := range grant.Attributes {
			name := condition.Name
			attributeField := fmt.Sprintf(attributeIndexFieldFormat, grantField, attributeIndex)
			if seen[name] {
				return fmt.Errorf("%s duplicates attribute %q", attributeField, name)
			}
			seen[name] = true
			source, ok := authenticatorAttribute(authenticator, name)
			if !ok || !attributeNamePattern.MatchString(name) {
				return fmt.Errorf("%s is not declared by authenticator %q", attributeField, authenticator.Name)
			}
			if source.FromSource == attributeSourceHeader {
				return fmt.Errorf("%s must use a verified credential attribute, not a header source", attributeField)
			}
			if err := validateMatchExpression(attributeField, condition, true); err != nil {
				return err
			}
			if (condition.Expression == gatewayapi.ExpressionHas || condition.Expression == gatewayapi.ExpressionHasOneOf) && source.FromSource != "claim" {
				return fmt.Errorf("%s.expression %s requires a JWT claim source", attributeField, condition.Expression)
			}
			if condition.Expression == gatewayapi.ExpressionEqualsAttribute {
				other, ok := authenticatorAttribute(authenticator, condition.Value.Text)
				if !ok {
					return fmt.Errorf("%s.value references undeclared attribute %q", attributeField, condition.Value.Text)
				}
				if other.FromSource == attributeSourceHeader && !accessMatchesHeader(access.Match, other.Value.Text) {
					return fmt.Errorf("%s.value header %q must be selected in match.headers", attributeField, other.Value.Text)
				}
			}
		}
	}
	return nil
}

func accessMatchesHeader(match gatewayapi.AccessMatch, header string) bool {
	for _, condition := range match.Headers {
		if strings.EqualFold(condition.Name, header) {
			return true
		}
	}
	return false
}

func validateAccessForwarding(field string, api gatewayapi.API, access resolvedAccess, services map[string]gatewayapi.ExternalAuthorizationService) error {
	for _, route := range api.Routes {
		if route.Processing == nil {
			continue
		}
		for _, mapping := range route.Processing.RequestHeaders {
			if access.Authorization.ExtAuthz != nil {
				service := services[access.Authorization.ExtAuthz.Service]
				if extAuthzProvidesAttribute(access, service, mapping.FromAttribute) {
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
	binding.FaultInjection = cloneConfigPointer(binding.FaultInjection, cloneFaultInjectionConfig)
	return binding
}

func cloneAccess(access gatewayapi.Access) gatewayapi.Access {
	access.Match.Headers = cloneMatchExpressions(access.Match.Headers)
	access.Authentication = cloneConfigPointer(access.Authentication, cloneAuthentication)
	access.Authorization.Grants = cloneSlice(access.Authorization.Grants, cloneAuthorizationGrant)
	access.Authorization.ExtAuthz = clonePointer(access.Authorization.ExtAuthz)
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
	grant.Attributes = cloneMatchExpressions(grant.Attributes)
	return grant
}

func cloneMatchExpressions(expressions []gatewayapi.MatchExpression) []gatewayapi.MatchExpression {
	cloned := slices.Clone(expressions)
	for index := range cloned {
		cloned[index].Value.Items = slices.Clone(cloned[index].Value.Items)
	}
	return cloned
}
