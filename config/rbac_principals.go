package config

import (
	"maps"
	"slices"

	rbac "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	expr "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

func apiKeyIdentityPrincipal() *rbac.Principal {
	return apiKeyMetadataPrincipal([]string{apiKeyMetadataKey}, &matcher.ValueMatcher{MatchPattern: &matcher.ValueMatcher_StringMatch{StringMatch: &matcher.StringMatcher{MatchPattern: &matcher.StringMatcher_Exact{Exact: apiKeyVerifiedIdentity}}}})
}

func apiKeyMetadataPrincipal(keys []string, value *matcher.ValueMatcher) *rbac.Principal {
	return dynamicMetadataPrincipal(apiKeyMetadataNamespace, keys, value)
}

func toGrantPrincipalForServer(c effectiveConfig, server resolvedServer, grant AuthorizationGrant) *rbac.Principal {
	principal := toGrantPrincipal(c, grant)
	if !server.mixedAnyOf() {
		return principal
	}
	authenticator := c.authenticatorIndex[grant.Authenticator]
	if authenticator.JWT != nil {
		return andPrincipals(principal, authenticator.toJWTMarkerPrincipal())
	}
	if !server.usesMTLS() {
		return principal
	}
	for _, higher := range server.authenticators {
		if higher.JWT != nil {
			principal = andPrincipals(principal, &rbac.Principal{Identifier: &rbac.Principal_NotId{NotId: higher.toJWTMarkerPrincipal()}})
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

func sharedAttributeConditions(authenticators ...Authenticator) ([]*rbac.Principal, *expr.Expr) {
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

func toGrantPrincipal(c effectiveConfig, grant AuthorizationGrant) *rbac.Principal {
	authenticator := c.authenticatorIndex[grant.Authenticator]
	if authenticator.APIKey != nil {
		return authenticator.toKeyGrantPrincipal(grant)
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
