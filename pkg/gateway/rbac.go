package gateway

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	rbac "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	httpRBAC "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rbac/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	mtlsauthenticated "github.com/envoyproxy/go-control-plane/envoy/extensions/rbac/principals/mtls_authenticated/v3"
	matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	expr "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	authenticatorFieldPathFormat   = "authenticators[%d]"
	mtlsPrincipalName              = "envoy.rbac.principals.mtls_authenticated"
	authenticationFilterName       = "auth_gateway.authentication"
	authorizationFilterName        = "envoy.filters.http.rbac"
	requiredHeaderFilterName       = "auth_gateway.required_headers"
	localResponsePolicyName        = "local-responses"
	mtlsSANCardinalityFilterName   = "auth_gateway.mtls.san_cardinality"
	mtlsSharedAttributesFilterName = "auth_gateway.mtls.shared_attributes"
)

func selectedAuthenticatorNames(server gatewayapi.Server) []string {
	if server.Authentication == nil {
		return nil
	}
	if server.Authentication.AnyOf != nil {
		return server.Authentication.AnyOf
	}
	return server.Authentication.AllOf
}

func validateSelection[V any](name string, anyOf, allOf []string, known map[string]V) ([]string, error) {
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

func validateUniqueReferences[V any](name string, values []string, known map[string]V) error {
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

func authenticatorPriority(authenticator gatewayapi.Authenticator) int {
	switch {
	case authenticator.JWT != nil:
		return 3
	case authenticator.MTLS != nil:
		return 2
	default:
		return 1
	}
}

func withDefaultsAuthenticator(authenticator gatewayapi.Authenticator) gatewayapi.Authenticator {
	if authenticator.JWT != nil {
		authenticator.JWT.JWKS = withDefaultsJWKSConfig(authenticator.JWT.JWKS)
	}
	if authenticator.APIKey != nil {
		apiKey := withDefaultsAPIKeyAuthenticator(*authenticator.APIKey)
		authenticator.APIKey = &apiKey
	}
	return authenticator
}

func cloneAuthenticator(authenticator gatewayapi.Authenticator) gatewayapi.Authenticator {
	if authenticator.Attributes != nil {
		attributes := make(map[string]gatewayapi.AttributeSource, len(authenticator.Attributes))
		for name, source := range authenticator.Attributes {
			attributes[name] = cloneAttributeSource(source)
		}
		authenticator.Attributes = attributes
	}
	authenticator.JWT = cloneConfigPointer(authenticator.JWT, cloneJWTAuthenticator)
	authenticator.APIKey = clonePointer(authenticator.APIKey)
	authenticator.MTLS = cloneConfigPointer(authenticator.MTLS, cloneMTLSAuthenticator)
	return authenticator
}

func cloneAuthentication(a gatewayapi.Authentication) gatewayapi.Authentication {
	a.AnyOf = slices.Clone(a.AnyOf)
	a.AllOf = slices.Clone(a.AllOf)
	return a
}

func providesAttributeAuthenticator(authenticator gatewayapi.Authenticator, name string) bool {
	_, exists := authenticator.Attributes[name]
	return exists
}

func credentialAttributeNamesAuthenticator(authenticator gatewayapi.Authenticator) []string {
	var names []string
	for name, source := range authenticator.Attributes {
		if source.Credential != nil && *source.Credential {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

func validateAuthorizationGrant(name string, grant gatewayapi.AuthorizationGrant, apis map[string]gatewayapi.API, authenticators map[string]gatewayapi.Authenticator) error {
	authenticator, exists := authenticators[grant.Authenticator]
	if !exists {
		return fmt.Errorf("%s.authenticator references unknown authenticator %q", name, grant.Authenticator)
	}
	if len(grant.APIs) == 0 {
		return fmt.Errorf("%s.apis must contain at least one API", name)
	}
	if err := validateUniqueReferences(name+".apis", grant.APIs, apis); err != nil {
		return err
	}
	if len(grant.Attributes) == 0 && authenticator.MTLS == nil {
		return fmt.Errorf("%s.attributes must contain at least one attribute allowlist", name)
	}
	for _, attribute := range slices.Sorted(maps.Keys(grant.Attributes)) {
		if err := validateGrantAttribute(name, grant.Authenticator, attribute, grant.Attributes[attribute], authenticator); err != nil {
			return err
		}
	}
	return nil
}

func validateGrantAttribute(name, authenticatorName, attribute string, values []string, authenticator gatewayapi.Authenticator) error {
	if !attributeNamePattern.MatchString(attribute) {
		return fmt.Errorf(attributeNameValidationErrorFormat, name, attribute)
	}
	if !providesAttributeAuthenticator(authenticator, attribute) {
		return fmt.Errorf("%s.attributes references attribute %q not provided by authenticator %q", name, attribute, authenticatorName)
	}
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
	return nil
}

func cloneAuthorizationPolicy(p gatewayapi.AuthorizationPolicy) gatewayapi.AuthorizationPolicy {
	p.Grants = cloneSlice(p.Grants, cloneAuthorizationGrant)
	return p
}

func cloneAuthorizationGrant(g gatewayapi.AuthorizationGrant) gatewayapi.AuthorizationGrant {
	g.APIs = slices.Clone(g.APIs)
	if g.Attributes != nil {
		attributes := make(map[string][]string, len(g.Attributes))
		for name, allowed := range g.Attributes {
			attributes[name] = slices.Clone(allowed)
		}
		g.Attributes = attributes
	}
	return g
}

func cloneAuthorization(a gatewayapi.Authorization) gatewayapi.Authorization {
	a.AnyOf = slices.Clone(a.AnyOf)
	a.AllOf = slices.Clone(a.AllOf)
	return a
}

func validateAuthenticators(c gatewayapi.Config) (map[string]gatewayapi.Authenticator, string, error) {
	authenticators := make(map[string]gatewayapi.Authenticator, len(c.Authenticators))
	apiKeyCount := 0
	apiKeyHeader := ""
	for i, authenticator := range c.Authenticators {
		name := fmt.Sprintf(authenticatorFieldPathFormat, i)
		if err := validateGatewayName(name, authenticator.Name); err != nil {
			return nil, "", err
		}
		if _, exists := authenticators[authenticator.Name]; exists {
			return nil, "", fmt.Errorf("duplicate authenticator name %q", authenticator.Name)
		}
		types := 0
		for _, present := range []bool{authenticator.JWT != nil, authenticator.APIKey != nil, authenticator.MTLS != nil} {
			if present {
				types++
			}
		}
		if types != 1 {
			return nil, "", fmt.Errorf("%s must set exactly one of jwt, api_key, or mtls", name)
		}
		if authenticator.JWT != nil {
			if err := validateJWTAuthenticator(name+".jwt", *authenticator.JWT); err != nil {
				return nil, "", err
			}
			if err := validateJWKSConfig(authenticator.JWT.JWKS, name+".jwt.jwks", c.Kubernetes != nil); err != nil {
				return nil, "", err
			}
		} else if authenticator.APIKey != nil {
			apiKeyCount++
			if apiKeyCount > 1 {
				return nil, "", fmt.Errorf("%s.api_key: only one API-key authenticator is supported", name)
			}
			if err := validateAPIKeyAuthenticator(name+".api_key", *authenticator.APIKey, c.Kubernetes != nil); err != nil {
				return nil, "", err
			}
			apiKeyHeader = authenticator.APIKey.Header
		} else {
			if authenticator.MTLS.TrustedCA == nil {
				return nil, "", fmt.Errorf("%s.mtls.trusted_ca is required", name)
			}
			if err := validateTrustedCA(name+".mtls.trusted_ca", authenticator.MTLS.TrustedCA, c.Kubernetes != nil); err != nil {
				return nil, "", err
			}
		}
		authenticators[authenticator.Name] = authenticator
	}
	return authenticators, apiKeyHeader, nil
}

func hasAuthenticationConfig(c gatewayapi.Config) bool {
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

func validateAuthorizationPolicies(c gatewayapi.Config) (map[string]gatewayapi.AuthorizationPolicy, error) {
	policies := make(map[string]gatewayapi.AuthorizationPolicy, len(c.AuthorizationPolicies))
	for i, policy := range c.AuthorizationPolicies {
		name := fmt.Sprintf("authorization_policies[%d]", i)
		if err := validateGatewayName(name, policy.Name); err != nil {
			return nil, err
		}
		if _, exists := policies[policy.Name]; exists {
			return nil, fmt.Errorf("duplicate authorization policy name %q", policy.Name)
		}
		policies[policy.Name] = policy
	}
	return policies, nil
}

func validateAuthorizationPolicyGrants(c gatewayapi.Config, apis map[string]gatewayapi.API, authenticators map[string]gatewayapi.Authenticator) error {
	for i, policy := range c.AuthorizationPolicies {
		for j, grant := range policy.Grants {
			name := fmt.Sprintf("authorization_policies[%d].grants[%d]", i, j)
			if err := validateAuthorizationGrant(name, grant, apis, authenticators); err != nil {
				return err
			}
		}
	}
	return nil
}

func mtlsValidatedPrincipal() (*rbac.Principal, error) {
	packed, err := packEnvoy(&mtlsauthenticated.Config{AnyValidatedClientCertificate: true})
	if err != nil {
		return nil, err
	}
	return &rbac.Principal{Identifier: &rbac.Principal_Custom{Custom: &core.TypedExtensionConfig{
		Name: mtlsPrincipalName, TypedConfig: packed,
	}}}, nil
}

func serverAuthenticationRBACRules(c resolvedConfig, server resolvedServer) (*rbac.RBAC, error) {
	var principal *rbac.Principal
	if server.hasAPIKey {
		principal = apiKeyIdentityPrincipal()
	}
	if server.usesMTLS() {
		mtlsPrincipal, err := mtlsValidatedPrincipal()
		if err != nil {
			return nil, err
		}
		if server.Authentication.AnyOf != nil && server.mixedAnyOf() {
			if principal == nil {
				principal = mtlsPrincipal
			} else {
				principal = &rbac.Principal{Identifier: &rbac.Principal_OrIds{OrIds: &rbac.Principal_Set{Ids: []*rbac.Principal{principal, mtlsPrincipal}}}}
			}
		} else if principal == nil {
			principal = mtlsPrincipal
		} else {
			principal = andPrincipals(principal, mtlsPrincipal)
		}
	}
	policy := &rbac.Policy{Permissions: []*rbac.Permission{{Rule: &rbac.Permission_Any{Any: true}}}}
	if server.mixedAnyOf() {
		var alternatives []*rbac.Principal
		if principal != nil {
			if ids := principal.GetOrIds(); ids != nil {
				alternatives = append(alternatives, ids.Ids...)
			} else {
				alternatives = append(alternatives, principal)
			}
		}
		for _, authenticator := range server.authenticators {
			if authenticator.JWT != nil {
				alternatives = append(alternatives, jwtMarkerPrincipal(authenticator))
			}
		}
		principal = &rbac.Principal{Identifier: &rbac.Principal_OrIds{OrIds: &rbac.Principal_Set{Ids: alternatives}}}
	} else if server.Authentication != nil && len(server.Authentication.AllOf) > 1 {
		selected := server.authenticators
		if !server.usesMTLS() {
			principals := []*rbac.Principal{principal}
			sharedPrincipals, condition := sharedAttributeConditions(selected...)
			principals = append(principals, sharedPrincipals...)
			principal = andPrincipals(principals...)
			if condition != nil {
				policy.Condition = condition
			}
		}
	}
	policy.Principals = []*rbac.Principal{principal}
	return &rbac.RBAC{Action: rbac.RBAC_ALLOW, Policies: map[string]*rbac.Policy{"authenticated": policy}}, nil
}

func serverMTLSSharedAttributeRBACRules(c resolvedConfig, server resolvedServer) *rbac.RBAC {
	if !server.usesMTLS() || server.Authentication == nil || len(server.Authentication.AllOf) < 2 {
		return nil
	}
	selected := server.authenticators
	principals, condition := sharedAttributeConditions(selected...)
	if condition == nil {
		return nil
	}
	policy := &rbac.Policy{
		Permissions: []*rbac.Permission{{Rule: &rbac.Permission_Any{Any: true}}},
		Principals:  principals,
		Condition:   condition,
	}
	return &rbac.RBAC{Action: rbac.RBAC_ALLOW, Policies: map[string]*rbac.Policy{"shared-attributes": policy}}
}

func addServerAuthenticationConfig(c resolvedConfig, host *route.VirtualHost, index int, server resolvedServer) error {
	if !server.hasAPIKey && !server.usesMTLS() {
		return nil
	}
	rules, err := serverAuthenticationRBACRules(c, server)
	if err != nil {
		return fmt.Errorf("servers[%d] authentication rules: %w", index, err)
	}
	authentication, err := packEnvoy(&httpRBAC.RBACPerRoute{Rbac: &httpRBAC.RBAC{Rules: rules}})
	if err != nil {
		return fmt.Errorf("servers[%d] authentication rules: %w", index, err)
	}
	host.TypedPerFilterConfig[authenticationFilterName] = authentication
	return nil
}

func addServerMTLSSharedAttributeConfig(c resolvedConfig, host *route.VirtualHost, index int, server resolvedServer) error {
	rules := serverMTLSSharedAttributeRBACRules(c, server)
	if rules == nil {
		return nil
	}
	config, err := packEnvoy(&httpRBAC.RBACPerRoute{Rbac: &httpRBAC.RBAC{Rules: rules}})
	if err != nil {
		return fmt.Errorf("servers[%d] mTLS shared attribute rules: %w", index, err)
	}
	host.TypedPerFilterConfig[mtlsSharedAttributesFilterName] = config
	return nil
}

func appendAuthenticationRBAC(filters []*hcm.HttpFilter) ([]*hcm.HttpFilter, error) {
	authentication, err := packEnvoy(&httpRBAC.RBAC{})
	if err != nil {
		return nil, fmt.Errorf("encode authentication RBAC filter: %w", err)
	}
	return append(filters, &hcm.HttpFilter{Name: authenticationFilterName, ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: authentication}}), nil
}

func appendRequiredHeaderRBAC(filters []*hcm.HttpFilter) ([]*hcm.HttpFilter, error) {
	headerRBACConfig, err := packEnvoy(&httpRBAC.RBAC{})
	if err != nil {
		return nil, fmt.Errorf("encode required-header RBAC filter: %w", err)
	}
	return append(filters, &hcm.HttpFilter{Name: requiredHeaderFilterName, ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: headerRBACConfig}}), nil
}

func serverRBACRules(c resolvedConfig, server resolvedServer) *rbac.RBAC {
	policies := map[string]*rbac.Policy{
		localResponsePolicyName: {
			Permissions: []*rbac.Permission{apiPermission(localResponseAPIName)},
			Principals:  []*rbac.Principal{{Identifier: &rbac.Principal_Any{Any: true}}},
		},
	}
	if server.Authorization != nil {
		for _, apiName := range server.APIs {
			var principal *rbac.Principal
			if len(server.Authorization.AnyOf) > 0 {
				var grants []*rbac.Principal
				for _, policy := range server.policies {
					grants = append(grants, grantPrincipalsForAPI(c, server, apiName, policy)...)
				}
				if len(grants) > 0 {
					principal = &rbac.Principal{Identifier: &rbac.Principal_OrIds{OrIds: &rbac.Principal_Set{Ids: grants}}}
				}
			} else {
				var policyPrincipals []*rbac.Principal
				allowed := true
				for _, policy := range server.policies {
					grants := grantPrincipalsForAPI(c, server, apiName, policy)
					if len(grants) == 0 {
						allowed = false
						break
					}
					policyPrincipals = append(policyPrincipals, &rbac.Principal{Identifier: &rbac.Principal_OrIds{OrIds: &rbac.Principal_Set{Ids: grants}}})
				}
				if allowed {
					principal = &rbac.Principal{Identifier: &rbac.Principal_AndIds{AndIds: &rbac.Principal_Set{Ids: policyPrincipals}}}
				}
			}
			if principal != nil {
				policies["api-"+apiName] = &rbac.Policy{Permissions: []*rbac.Permission{apiPermission(apiName)}, Principals: []*rbac.Principal{principal}}
			}
		}
	}
	return &rbac.RBAC{Action: rbac.RBAC_ALLOW, Policies: policies}
}

func grantPrincipalsForAPI(c resolvedConfig, server resolvedServer, apiName string, policy gatewayapi.AuthorizationPolicy) []*rbac.Principal {
	var grants []*rbac.Principal
	for _, grant := range policy.Grants {
		if slices.Contains(grant.APIs, apiName) && (!c.usesAPIKeys() && !c.usesMTLS() || server.selectsAuthenticator(grant.Authenticator)) {
			grants = append(grants, grantPrincipalForServer(c, server, grant))
		}
	}
	return grants
}

func requiredHeaderRBACRules(mappings []gatewayapi.RequestHeaderMapping) (*rbac.RBAC, error) {
	attributes := make(map[string]struct{}, len(mappings))
	for _, mapping := range mappings {
		attributes[mapping.FromAttribute] = struct{}{}
	}
	principals := make([]*rbac.Principal, 0, len(attributes))
	for _, attribute := range slices.Sorted(maps.Keys(attributes)) {
		principals = append(principals, &rbac.Principal{Identifier: &rbac.Principal_FilterState{FilterState: &matcher.FilterStateMatcher{
			Key: filterStateKey(attribute),
			Matcher: &matcher.FilterStateMatcher_StringMatch{StringMatch: &matcher.StringMatcher{MatchPattern: &matcher.StringMatcher_SafeRegex{SafeRegex: &matcher.RegexMatcher{
				Regex: headerValuePattern,
			}}}},
		}}})
	}
	if len(principals) == 0 {
		return nil, fmt.Errorf("at least one request header mapping is required")
	}
	principal := principals[0]
	if len(principals) > 1 {
		principal = &rbac.Principal{Identifier: &rbac.Principal_AndIds{AndIds: &rbac.Principal_Set{Ids: principals}}}
	}
	return &rbac.RBAC{Action: rbac.RBAC_ALLOW, Policies: map[string]*rbac.Policy{
		"required-attributes": {
			Permissions: []*rbac.Permission{{Rule: &rbac.Permission_Any{Any: true}}},
			Principals:  []*rbac.Principal{principal},
		},
	}}, nil
}

func mtlsSANCardinalityFilter() (*hcm.HttpFilter, error) {
	principals := make([]*rbac.Principal, 0, 2)
	for _, name := range []string{mtlsURIHeaderName, mtlsDNSHeaderName} {
		principals = append(principals, &rbac.Principal{Identifier: &rbac.Principal_Header{Header: &route.HeaderMatcher{
			Name: name,
			HeaderMatchSpecifier: &route.HeaderMatcher_StringMatch{StringMatch: &matcher.StringMatcher{
				MatchPattern: &matcher.StringMatcher_SafeRegex{SafeRegex: &matcher.RegexMatcher{Regex: ".*,.*"}},
			}},
		}}})
	}
	rules := &rbac.RBAC{Action: rbac.RBAC_DENY, Policies: map[string]*rbac.Policy{
		"multiple-san": {
			Permissions: []*rbac.Permission{{Rule: &rbac.Permission_Any{Any: true}}},
			Principals:  []*rbac.Principal{{Identifier: &rbac.Principal_OrIds{OrIds: &rbac.Principal_Set{Ids: principals}}}},
		},
	}}
	packed, err := packEnvoy(&httpRBAC.RBAC{Rules: rules})
	if err != nil {
		return nil, err
	}
	return &hcm.HttpFilter{Name: mtlsSANCardinalityFilterName, ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: packed}}, nil
}

func mtlsSharedAttributesHTTPFilter() (*hcm.HttpFilter, error) {
	sharedAttributesConfig, err := packEnvoy(&httpRBAC.RBAC{})
	if err != nil {
		return nil, fmt.Errorf("encode mTLS shared attribute filter: %w", err)
	}
	return &hcm.HttpFilter{
		Name:       mtlsSharedAttributesFilterName,
		Disabled:   true,
		ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: sharedAttributesConfig},
	}, nil
}

func authorizationHTTPFilter() (*hcm.HttpFilter, error) {
	rbacConfig, err := packEnvoy(&httpRBAC.RBAC{})
	if err != nil {
		return nil, fmt.Errorf("encode RBAC filter: %w", err)
	}
	return &hcm.HttpFilter{Name: authorizationFilterName, ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: rbacConfig}}, nil
}

func serverAuthorizationPerRouteConfig(c resolvedConfig, server resolvedServer) (*anypb.Any, error) {
	return packEnvoy(&httpRBAC.RBACPerRoute{Rbac: &httpRBAC.RBAC{Rules: serverRBACRules(c, server)}})
}

func requiredHeaderPerRouteConfig(routeName string, mappings []gatewayapi.RequestHeaderMapping) (*anypb.Any, error) {
	rules, err := requiredHeaderRBACRules(mappings)
	if err != nil {
		return nil, fmt.Errorf("build required-header RBAC rules for route %q: %w", routeName, err)
	}
	headerRBACConfig, err := packEnvoy(&httpRBAC.RBACPerRoute{Rbac: &httpRBAC.RBAC{Rules: rules}})
	if err != nil {
		return nil, fmt.Errorf("encode required-header RBAC rules for route %q: %w", routeName, err)
	}
	return headerRBACConfig, nil
}

func jwtMarkerPrincipal(authenticator gatewayapi.Authenticator) *rbac.Principal {
	return &rbac.Principal{Identifier: &rbac.Principal_Header{Header: &route.HeaderMatcher{
		Name:                 jwtVerifiedHeaderName(authenticator.Name),
		HeaderMatchSpecifier: &route.HeaderMatcher_StringMatch{StringMatch: &matcher.StringMatcher{MatchPattern: &matcher.StringMatcher_Exact{Exact: authenticator.JWT.Issuer}}},
	}}}
}

func keyGrantPrincipal(authenticator gatewayapi.Authenticator, grant gatewayapi.AuthorizationGrant) *rbac.Principal {
	conditions := []*rbac.Principal{apiKeyIdentityPrincipal()}
	for _, attribute := range slices.Sorted(maps.Keys(grant.Attributes)) {
		namespace, path := attributeMetadataPath(authenticator, attribute)
		conditions = append(conditions, dynamicMetadataPrincipal(namespace, path, allowedStringValueMatcher(grant.Attributes[attribute])))
	}
	return andPrincipals(conditions...)
}

func apiKeyIdentityPrincipal() *rbac.Principal {
	return apiKeyMetadataPrincipal([]string{apiKeyMetadataKey}, &matcher.ValueMatcher{MatchPattern: &matcher.ValueMatcher_StringMatch{StringMatch: &matcher.StringMatcher{MatchPattern: &matcher.StringMatcher_Exact{Exact: apiKeyVerifiedIdentity}}}})
}

func apiKeyMetadataPrincipal(keys []string, value *matcher.ValueMatcher) *rbac.Principal {
	return dynamicMetadataPrincipal(apiKeyMetadataNamespace, keys, value)
}

func grantPrincipalForServer(c resolvedConfig, server resolvedServer, grant gatewayapi.AuthorizationGrant) *rbac.Principal {
	principal := grantPrincipal(c, grant)
	if !server.mixedAnyOf() {
		return principal
	}
	authenticator := c.authenticatorIndex[grant.Authenticator]
	if authenticator.JWT != nil {
		return andPrincipals(principal, jwtMarkerPrincipal(authenticator))
	}
	if !server.usesMTLS() {
		return principal
	}
	for _, higher := range server.authenticators {
		if higher.JWT != nil {
			principal = andPrincipals(principal, &rbac.Principal{Identifier: &rbac.Principal_NotId{NotId: jwtMarkerPrincipal(higher)}})
		}
	}
	if authenticator.APIKey != nil && server.usesMTLS() {
		principal = andPrincipals(principal, &rbac.Principal{Identifier: &rbac.Principal_NotId{NotId: mtlsPresentPrincipal()}})
	}
	return principal
}

func andPrincipals(values ...*rbac.Principal) *rbac.Principal {
	if len(values) == 1 {
		return values[0]
	}
	return &rbac.Principal{Identifier: &rbac.Principal_AndIds{AndIds: &rbac.Principal_Set{Ids: values}}}
}

func nonemptyScalarValueMatcher() *matcher.ValueMatcher {
	return &matcher.ValueMatcher{MatchPattern: &matcher.ValueMatcher_StringMatch{StringMatch: &matcher.StringMatcher{MatchPattern: &matcher.StringMatcher_SafeRegex{SafeRegex: &matcher.RegexMatcher{
		Regex: headerValuePattern,
	}}}}}
}

func sharedAttributeConditions(authenticators ...gatewayapi.Authenticator) ([]*rbac.Principal, *expr.Expr) {
	builder := &celExpressionBuilder{}
	var principals []*rbac.Principal
	var equality []*expr.Expr
	for first := range authenticators {
		for second := first + 1; second < len(authenticators); second++ {
			for _, attribute := range slices.Sorted(maps.Keys(authenticators[second].Attributes)) {
				if _, shared := authenticators[first].Attributes[attribute]; !shared {
					continue
				}
				firstNamespace, firstPath := attributeMetadataPath(authenticators[first], attribute)
				secondNamespace, secondPath := attributeMetadataPath(authenticators[second], attribute)
				valueMatcher := nonemptyScalarValueMatcher()
				principals = append(principals,
					dynamicMetadataPrincipal(firstNamespace, firstPath, valueMatcher),
					dynamicMetadataPrincipal(secondNamespace, secondPath, valueMatcher))
				equality = append(equality, builder.call("_==_",
					builder.metadataValue(firstNamespace, firstPath),
					builder.metadataValue(secondNamespace, secondPath)))
			}
		}
	}
	if len(equality) == 0 {
		return principals, nil
	}
	condition := equality[0]
	for _, next := range equality[1:] {
		condition = builder.call("_&&_", condition, next)
	}
	return principals, condition
}

func apiPermission(api string) *rbac.Permission {
	return &rbac.Permission{Rule: &rbac.Permission_SourcedMetadata{SourcedMetadata: &rbac.SourcedMetadata{MetadataSource: rbac.MetadataSource_ROUTE, MetadataMatcher: &matcher.MetadataMatcher{
		Filter: authorizationFilterName, Path: []*matcher.MetadataMatcher_PathSegment{metadataPathSegment(apiMetadataName)},
		Value: &matcher.ValueMatcher{MatchPattern: &matcher.ValueMatcher_StringMatch{StringMatch: &matcher.StringMatcher{MatchPattern: &matcher.StringMatcher_Exact{Exact: api}}}},
	}}}}
}

func grantPrincipal(c resolvedConfig, grant gatewayapi.AuthorizationGrant) *rbac.Principal {
	authenticator := c.authenticatorIndex[grant.Authenticator]
	if authenticator.APIKey != nil {
		return keyGrantPrincipal(authenticator, grant)
	}
	if authenticator.MTLS != nil {
		conditions := []*rbac.Principal{mtlsPresentPrincipal()}
		for _, attribute := range slices.Sorted(maps.Keys(grant.Attributes)) {
			namespace, path := attributeMetadataPath(authenticator, attribute)
			conditions = append(conditions, dynamicMetadataPrincipal(namespace, path, allowedStringValueMatcher(grant.Attributes[attribute])))
		}
		return andPrincipals(conditions...)
	}
	conditions := make([]*rbac.Principal, 0, len(grant.Attributes)+1)
	hasClaim := false
	for _, attribute := range slices.Sorted(maps.Keys(grant.Attributes)) {
		source := authenticator.Attributes[attribute]
		if source.Header != nil {
			namespace, path := attributeMetadataPath(authenticator, attribute)
			conditions = append(conditions, dynamicMetadataPrincipal(namespace, path, allowedStringValueMatcher(grant.Attributes[attribute])))
		} else {
			hasClaim = true
			claimPath := append([]string{grant.Authenticator}, source.ClaimPath...)
			conditions = append(conditions, jwtClaimPrincipal(claimPath, claimValueMatcher(grant.Attributes[attribute])))
		}
	}
	if !hasClaim {
		conditions = append(conditions, jwtClaimPrincipal([]string{authenticator.Name, jwtIssuerClaimName}, exactStringValueMatcher(authenticator.JWT.Issuer)))
	}
	return andPrincipals(conditions...)
}

func exactStringValueMatcher(value string) *matcher.ValueMatcher {
	return &matcher.ValueMatcher{MatchPattern: &matcher.ValueMatcher_StringMatch{StringMatch: &matcher.StringMatcher{MatchPattern: &matcher.StringMatcher_Exact{Exact: value}}}}
}

func allowedStringValueMatcher(allowedValues []string) *matcher.ValueMatcher {
	values := make([]*matcher.ValueMatcher, 0, len(allowedValues))
	for _, value := range allowedValues {
		values = append(values, exactStringValueMatcher(value))
	}
	if len(values) == 1 {
		return values[0]
	}
	return &matcher.ValueMatcher{MatchPattern: &matcher.ValueMatcher_OrMatch{OrMatch: &matcher.OrMatcher{ValueMatchers: values}}}
}

// claimValueMatcher accepts a scalar claim or any allowed member of a list claim.
func claimValueMatcher(allowedValues []string) *matcher.ValueMatcher {
	allowedMatcher := allowedStringValueMatcher(allowedValues)
	listMatcher := &matcher.ValueMatcher{MatchPattern: &matcher.ValueMatcher_ListMatch{ListMatch: &matcher.ListMatcher{MatchPattern: &matcher.ListMatcher_OneOf{OneOf: allowedMatcher}}}}
	return &matcher.ValueMatcher{MatchPattern: &matcher.ValueMatcher_OrMatch{OrMatch: &matcher.OrMatcher{ValueMatchers: []*matcher.ValueMatcher{allowedMatcher, listMatcher}}}}
}

func jwtClaimPrincipal(claimPath []string, value *matcher.ValueMatcher) *rbac.Principal {
	return dynamicMetadataPrincipal(jwtAuthnFilterName, claimPath, value)
}

func dynamicMetadataPrincipal(namespace string, path []string, value *matcher.ValueMatcher) *rbac.Principal {
	metadataPath := make([]*matcher.MetadataMatcher_PathSegment, 0, len(path))
	for _, key := range path {
		metadataPath = append(metadataPath, metadataPathSegment(key))
	}
	return &rbac.Principal{Identifier: &rbac.Principal_SourcedMetadata{SourcedMetadata: &rbac.SourcedMetadata{MetadataSource: rbac.MetadataSource_DYNAMIC, MetadataMatcher: &matcher.MetadataMatcher{
		Filter: namespace, Path: metadataPath, Value: value,
	}}}}
}

func metadataPathSegment(key string) *matcher.MetadataMatcher_PathSegment {
	return &matcher.MetadataMatcher_PathSegment{Segment: &matcher.MetadataMatcher_PathSegment_Key{Key: key}}
}

func mtlsHeaderPrincipal(name, value string) *rbac.Principal {
	return &rbac.Principal{Identifier: &rbac.Principal_Header{Header: &route.HeaderMatcher{
		Name: name,
		HeaderMatchSpecifier: &route.HeaderMatcher_StringMatch{StringMatch: &matcher.StringMatcher{
			MatchPattern: &matcher.StringMatcher_Exact{Exact: value}, IgnoreCase: true,
		}},
	}}}
}

func mtlsPresentPrincipal() *rbac.Principal {
	return &rbac.Principal{Identifier: &rbac.Principal_Header{Header: &route.HeaderMatcher{
		Name: mtlsFingerprintHeaderName,
		HeaderMatchSpecifier: &route.HeaderMatcher_StringMatch{StringMatch: &matcher.StringMatcher{
			MatchPattern: &matcher.StringMatcher_SafeRegex{SafeRegex: &matcher.RegexMatcher{Regex: mtlsFingerprintPattern}},
		}},
	}}}
}
