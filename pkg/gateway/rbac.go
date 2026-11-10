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
	authenticatorFieldPathFormat = "authenticators[%d]"
	mtlsPrincipalName            = "envoy.rbac.principals.mtls_authenticated"
	authorizationFilterName      = "envoy.filters.http.rbac"
	requiredHeaderFilterName     = "auth_gateway.required_headers"
	mtlsSANCardinalityFilterName = "auth_gateway.mtls.san_cardinality"
	requestValidationFilterName  = "auth_gateway.request_validation"
	invalidRequestPolicyName     = "invalid-request-headers"
)

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
		attributes := make([]gatewayapi.AttributeSource, len(authenticator.Attributes))
		for i, source := range authenticator.Attributes {
			attributes[i] = cloneAttributeSource(source)
		}
		authenticator.Attributes = attributes
	}
	authenticator.JWT = cloneConfigPointer(authenticator.JWT, cloneJWTAuthenticator)
	authenticator.APIKey = clonePointer(authenticator.APIKey)
	authenticator.MTLS = cloneConfigPointer(authenticator.MTLS, cloneMTLSAuthenticator)
	return authenticator
}

func providesAttributeAuthenticator(authenticator gatewayapi.Authenticator, name string) bool {
	_, exists := authenticatorAttribute(authenticator, name)
	return exists
}

func credentialAttributeNamesAuthenticator(authenticator gatewayapi.Authenticator) []string {
	var names []string
	for _, source := range authenticator.Attributes {
		if source.FromSource == "credential" && !slices.Contains(names, source.Value.Text) {
			names = append(names, source.Value.Text)
		}
	}
	slices.Sort(names)
	return names
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

func mtlsValidatedPrincipal() (*rbac.Principal, error) {
	packed, err := packEnvoy(&mtlsauthenticated.Config{AnyValidatedClientCertificate: true})
	if err != nil {
		return nil, err
	}
	return &rbac.Principal{Identifier: &rbac.Principal_Custom{Custom: &core.TypedExtensionConfig{
		Name: mtlsPrincipalName, TypedConfig: packed,
	}}}, nil
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

func appendRequiredHeaderRBAC(filters []*hcm.HttpFilter) ([]*hcm.HttpFilter, error) {
	headerRBACConfig, err := packEnvoy(&httpRBAC.RBAC{})
	if err != nil {
		return nil, fmt.Errorf("encode required-header RBAC filter: %w", err)
	}
	return append(filters, &hcm.HttpFilter{Name: requiredHeaderFilterName, ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: headerRBACConfig}}), nil
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

func apiKeyIdentityPrincipal() *rbac.Principal {
	return apiKeyMetadataPrincipal([]string{apiKeyMetadataKey}, &matcher.ValueMatcher{MatchPattern: &matcher.ValueMatcher_StringMatch{StringMatch: &matcher.StringMatcher{MatchPattern: &matcher.StringMatcher_Exact{Exact: apiKeyVerifiedIdentity}}}})
}

func apiKeyMetadataPrincipal(keys []string, value *matcher.ValueMatcher) *rbac.Principal {
	return dynamicMetadataPrincipal(apiKeyMetadataNamespace, keys, value)
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

func authorizationHTTPFilter() (*hcm.HttpFilter, error) {
	packed, err := packEnvoy(&httpRBAC.RBAC{Rules: &rbac.RBAC{Action: rbac.RBAC_ALLOW}})
	if err != nil {
		return nil, err
	}
	return &hcm.HttpFilter{Name: authorizationFilterName, ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: packed}}, nil
}

func authorizationPerRouteConfig(c resolvedConfig, access resolvedAccess) (*anypb.Any, error) {
	policies := make(map[string]*rbac.Policy)
	for index, grant := range access.Authorization.Grants {
		policy, err := grantPolicy(c.authenticatorIndex[grant.Authenticator], grant)
		if err != nil {
			return nil, err
		}
		policies[fmt.Sprintf("grant-%d", index)] = policy
	}
	return packEnvoy(&httpRBAC.RBACPerRoute{Rbac: &httpRBAC.RBAC{Rules: &rbac.RBAC{Action: rbac.RBAC_ALLOW, Policies: policies}}})
}

func grantPolicy(authenticator gatewayapi.Authenticator, grant gatewayapi.AuthorizationGrant) (*rbac.Policy, error) {
	var verified *rbac.Principal
	switch {
	case authenticator.JWT != nil:
		verified = jwtClaimPrincipal([]string{authenticator.Name, jwtIssuerClaimName}, exactStringValueMatcher(authenticator.JWT.Issuer))
	case authenticator.APIKey != nil:
		verified = apiKeyIdentityPrincipal()
	default:
		var err error
		verified, err = mtlsValidatedPrincipal()
		if err != nil {
			return nil, err
		}
	}
	principals := []*rbac.Principal{verified}
	builder := &celExpressionBuilder{}
	var equality *expr.Expr
	for _, condition := range sortedMatchExpressions(grant.Attributes) {
		namespace, path := attributeMetadataPath(authenticator, condition.Name)
		if condition.Expression != gatewayapi.ExpressionEqualsAttribute {
			value := allowedStringValueMatcher(matchValues(condition))
			principals = append(principals, dynamicMetadataPrincipal(namespace, path, value))
			continue
		}
		otherNamespace, otherPath := attributeMetadataPath(authenticator, condition.Value.Text)
		principals = append(principals,
			dynamicMetadataPrincipal(namespace, path, nonemptyScalarValueMatcher()),
			dynamicMetadataPrincipal(otherNamespace, otherPath, nonemptyScalarValueMatcher()))
		comparison := builder.call("_==_", builder.metadataValue(namespace, path), builder.metadataValue(otherNamespace, otherPath))
		if equality == nil {
			equality = comparison
		} else {
			equality = builder.call("_&&_", equality, comparison)
		}
	}
	return &rbac.Policy{
		Permissions: []*rbac.Permission{{Rule: &rbac.Permission_Any{Any: true}}},
		Principals:  []*rbac.Principal{andPrincipals(principals...)}, Condition: equality,
	}, nil
}

func requestValidationHTTPFilter() (*hcm.HttpFilter, error) {
	packed, err := packEnvoy(&httpRBAC.RBAC{})
	if err != nil {
		return nil, err
	}
	return &hcm.HttpFilter{Name: requestValidationFilterName, ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: packed}}, nil
}

func requestValidationPerRouteConfig(headers []string) (*anypb.Any, error) {
	builder := &celExpressionBuilder{}
	var repeated *expr.Expr
	for _, name := range headers {
		condition := builder.repeatedHeader(strings.ToLower(name))
		if repeated == nil {
			repeated = condition
		} else {
			repeated = builder.call("_||_", repeated, condition)
		}
	}
	config := &httpRBAC.RBACPerRoute{}
	if repeated != nil {
		config.Rbac = &httpRBAC.RBAC{Rules: &rbac.RBAC{Action: rbac.RBAC_DENY, Policies: map[string]*rbac.Policy{
			invalidRequestPolicyName: {
				Permissions: []*rbac.Permission{{Rule: &rbac.Permission_Any{Any: true}}},
				Principals:  []*rbac.Principal{{Identifier: &rbac.Principal_Any{Any: true}}}, Condition: repeated,
			},
		}}}
	}
	return packEnvoy(config)
}
