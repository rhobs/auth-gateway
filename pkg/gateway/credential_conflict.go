package gateway

import (
	"strings"

	rbac "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	httpRBAC "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rbac/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
)

const credentialConflictFilterName = "auth_gateway.credential_conflict"

func credentialConflictHTTPFilter(c resolvedConfig) (*hcm.HttpFilter, error) {
	authenticator, exists := c.apiKeyAuthenticator()
	if !exists {
		return nil, nil
	}
	permissions := make([]*rbac.Permission, 0, 2)
	for _, name := range []string{authorizationHeaderName, strings.ToLower(authenticator.APIKey.Header)} {
		permissions = append(permissions, &rbac.Permission{Rule: &rbac.Permission_Header{Header: &route.HeaderMatcher{
			Name: name, HeaderMatchSpecifier: &route.HeaderMatcher_PresentMatch{PresentMatch: true},
		}}})
	}
	rules := &rbac.RBAC{Action: rbac.RBAC_DENY, Policies: map[string]*rbac.Policy{
		"mixed-credentials": {
			Permissions: []*rbac.Permission{{Rule: &rbac.Permission_AndRules{AndRules: &rbac.Permission_Set{Rules: permissions}}}},
			Principals:  []*rbac.Principal{{Identifier: &rbac.Principal_Any{Any: true}}},
		},
	}}
	packed, err := packEnvoy(&httpRBAC.RBAC{Rules: rules})
	if err != nil {
		return nil, err
	}
	return &hcm.HttpFilter{Name: credentialConflictFilterName, ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: packed}}, nil
}
