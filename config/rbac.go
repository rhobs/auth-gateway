package config

import (
	"fmt"
	"maps"
	"slices"

	rbac "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	httpRBAC "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rbac/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	authenticationFilterName       = "auth_gateway.authentication"
	authorizationFilterName        = "envoy.filters.http.rbac"
	requiredHeaderFilterName       = "auth_gateway.required_headers"
	localResponsePolicyName        = "local-responses"
	mtlsSANCardinalityFilterName   = "auth_gateway.mtls.san_cardinality"
	mtlsSharedAttributesFilterName = "auth_gateway.mtls.shared_attributes"
)

func toServerAuthenticationRBACRules(c effectiveConfig, server resolvedServer) (*rbac.RBAC, error) {
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
				alternatives = append(alternatives, authenticator.toJWTMarkerPrincipal())
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

func toServerMTLSSharedAttributeRBACRules(c effectiveConfig, server resolvedServer) *rbac.RBAC {
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

func addServerAuthenticationConfig(c effectiveConfig, host *route.VirtualHost, index int, server resolvedServer) error {
	if !server.hasAPIKey && !server.usesMTLS() {
		return nil
	}
	rules, err := toServerAuthenticationRBACRules(c, server)
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

func addServerMTLSSharedAttributeConfig(c effectiveConfig, host *route.VirtualHost, index int, server resolvedServer) error {
	rules := toServerMTLSSharedAttributeRBACRules(c, server)
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

func toServerRBACRules(c effectiveConfig, server resolvedServer) *rbac.RBAC {
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

func grantPrincipalsForAPI(c effectiveConfig, server resolvedServer, apiName string, policy AuthorizationPolicy) []*rbac.Principal {
	var grants []*rbac.Principal
	for _, grant := range policy.Grants {
		if slices.Contains(grant.APIs, apiName) && (!c.usesAPIKeys() && !c.usesMTLS() || server.selectsAuthenticator(grant.Authenticator)) {
			grants = append(grants, toGrantPrincipalForServer(c, server, grant))
		}
	}
	return grants
}

func requiredHeaderRBACRules(mappings []RequestHeaderMapping) (*rbac.RBAC, error) {
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

func serverAuthorizationPerRouteConfig(c effectiveConfig, server resolvedServer) (*anypb.Any, error) {
	return packEnvoy(&httpRBAC.RBACPerRoute{Rbac: &httpRBAC.RBAC{Rules: toServerRBACRules(c, server)}})
}

func requiredHeaderPerRouteConfig(routeName string, mappings []RequestHeaderMapping) (*anypb.Any, error) {
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
