package config

import (
	"slices"
	"strings"
	"testing"

	rbac "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	setfilterstate "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	expr "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

func TestJWTAttributesUseStaticFilterConfiguration(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-with-attributes")
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	manager := firstHTTPManager(t, files.EnvoyBootstrap.Contents)
	var attributeFilter *hcm.HttpFilter
	for _, filter := range manager.HttpFilters {
		if filter.Name == attributeFilterName {
			attributeFilter = filter
		}
	}
	if attributeFilter == nil || attributeFilter.GetTypedConfig() == nil || attributeFilter.GetConfigDiscovery() != nil {
		t.Fatalf("attribute filter = %#v, want static configuration", attributeFilter)
	}
	var attributes setfilterstate.Config
	if err := attributeFilter.GetTypedConfig().UnmarshalTo(&attributes); err != nil {
		t.Fatal(err)
	}
	wantKeys := []string{
		filterStateKey("tenant_id"), filterStateKey("writer_id"),
		filterStateKey("tenant_id"), filterStateKey("writer_id"),
	}
	if len(attributes.OnRequestHeaders) != len(wantKeys) {
		t.Fatalf("attribute updates = %d, want %d", len(attributes.OnRequestHeaders), len(wantKeys))
	}
	for index, update := range attributes.OnRequestHeaders {
		if update.GetObjectKey() != wantKeys[index] || !update.SkipIfEmpty {
			t.Fatalf("attribute update %d key/skip behavior = %#v/%t", index, update.GetKey(), update.SkipIfEmpty)
		}
		format := update.GetFormatString()
		if format == nil || !format.OmitEmptyValues {
			t.Fatalf("attribute formatter = %#v", update.GetValue())
		}
		expression := format.GetTextFormatSource().GetInlineString()
		if !strings.HasPrefix(expression, "%CEL(") || !strings.HasSuffix(expression, ")%") || !strings.Contains(expression, "metadata.filter_metadata") {
			t.Fatalf("attribute expression = %q, want a verified source", expression)
		}
	}
}

func TestJWTExpressionsUseEnvoyCELVariablesAndGuardMissingAttributes(t *testing.T) {
	claim := jwtClaimExpression([]string{"issuer-one", "organization", "id"})
	claimMetadata := `metadata.filter_metadata["envoy.filters.http.jwt_authn"]`
	claimValue := claimMetadata + `["issuer-one"]["organization"]["id"]`
	if !strings.Contains(claim, `"issuer-one" in `+claimMetadata) || !strings.Contains(claim, `"organization" in `+claimMetadata+`["issuer-one"]`) || !strings.Contains(claim, `"id" in `+claimMetadata+`["issuer-one"]["organization"]`) || !strings.Contains(claim, "type("+claimValue+") == string") || !strings.Contains(claim, claimValue+` != ""`) || strings.Contains(claim, "dynamicMetadata(") || strings.Contains(claim, "dynamic_metadata[") {
		t.Fatalf("JWT claim expression does not use Envoy CEL metadata: %s", claim)
	}
}

func TestAPIKeyRawAuthorizationAndSharedAttributeEquality(t *testing.T) {
	c := loadConfigCase(t, "api-key-auth")
	keyOnly := testServerAuthenticationRules(t, c, 1).Policies["authenticated"].Principals[0]
	if matcher := keyOnly.GetSourcedMetadata().GetMetadataMatcher(); matcher == nil || matcher.Filter != apiKeyMetadataNamespace ||
		!slices.Equal(metadataMatcherPath(matcher.GetPath()), []string{"identity"}) ||
		matcher.GetValue().GetStringMatch().GetExact() != "verified" {
		t.Fatalf("key-only authentication principal = %#v", keyOnly)
	}
	mixed := testServerAuthenticationRules(t, c, 2).Policies["authenticated"].Principals[0].GetOrIds().GetIds()
	if len(mixed) != 2 || mixed[0].GetSourcedMetadata() == nil || mixed[1].GetHeader().GetName() != jwtVerifiedHeaderName("issuer-one") {
		t.Fatalf("mixed any_of authentication principal = %#v", mixed)
	}
	dualPolicy := testServerAuthenticationRules(t, c, 3).Policies["authenticated"]
	principals := dualPolicy.Principals[0].GetAndIds().GetIds()
	if len(principals) != 5 || dualPolicy.Condition.GetCallExpr().GetFunction() != "_&&_" {
		t.Fatalf("all_of authentication policy = %#v", dualPolicy)
	}
	for _, equality := range dualPolicy.Condition.GetCallExpr().GetArgs() {
		if equality.GetCallExpr().GetFunction() != "_==_" {
			t.Fatalf("shared attribute condition is not exact equality: %#v", equality)
		}
	}
	for _, principal := range principals[1:] {
		value := principal.GetSourcedMetadata().GetMetadataMatcher().GetValue()
		if value.GetStringMatch().GetSafeRegex().GetRegex() != headerValuePattern {
			t.Fatalf("shared attribute was not restricted to a nonempty scalar: %#v", principal)
		}
	}
	grant := resolveTestConfig(t, c).toGrantPrincipal(c.AuthorizationPolicies[1].Grants[0])
	parts := grant.GetAndIds().GetIds()
	if len(parts) != 2 || parts[1].GetSourcedMetadata().GetMetadataMatcher().GetFilter() != apiKeyMetadataNamespace ||
		!slices.Equal(metadataMatcherPath(parts[1].GetSourcedMetadata().GetMetadataMatcher().GetPath()), []string{"attribute.tenant_id"}) {
		t.Fatalf("API-key grant reads unprocessed Secret attributes: %#v", grant)
	}
	c.Servers[1].Authorization.AnyOf = []string{"jwt-writers", "key-writers"}
	effective := resolveTestConfig(t, c)
	grants := effective.toServerRBACRules(effective.servers[1]).Policies["api-ingest"].Principals[0].GetOrIds().GetIds()
	if len(grants) != 1 || grants[0].GetAndIds() == nil {
		t.Fatalf("key-only host used an unselected JWT grant: %#v", grants)
	}
}

func TestAPIKeyInitializersAreHostScoped(t *testing.T) {
	c := loadConfigCase(t, "api-key-auth")
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	manager := firstHTTPManager(t, files.EnvoyBootstrap.Contents)
	for _, test := range []struct {
		index int
		want  int
	}{
		{index: 1, want: 2},
		{index: 2, want: 6},
	} {
		filter := apiKeyHTTPFilter(t, manager, attributeInitializationFilterName(test.index))
		if !filter.Disabled {
			t.Fatalf("server %d initializer is not host-scoped", test.index)
		}
		var initialized setfilterstate.Config
		if err := filter.GetTypedConfig().UnmarshalTo(&initialized); err != nil {
			t.Fatal(err)
		}
		if len(initialized.OnRequestHeaders) != test.want {
			t.Fatalf("server %d initializes %d attributes, want %d", test.index, len(initialized.OnRequestHeaders), test.want)
		}
		for _, value := range initialized.OnRequestHeaders {
			format := value.GetFormatString().GetTextFormatSource()
			if !value.SkipIfEmpty || format == nil || !strings.Contains(format.GetInlineString(), "metadata.filter_metadata") {
				t.Fatalf("server %d initializer reads an unsafe source: %#v", test.index, value)
			}
		}
	}
}

func TestHeaderWorkingAttributesRequireVerifiedAuthenticator(t *testing.T) {
	c := loadConfigCase(t, "api-key-auth")
	c.Authenticators[0].Attributes["requested_tenant"] = AttributeSource{Header: new("X-Tenant")}
	c.Authenticators[1].Attributes["requested_tenant"] = AttributeSource{Header: new("X-Tenant")}
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	manager := firstHTTPManager(t, files.EnvoyBootstrap.Contents)
	filter := apiKeyHTTPFilter(t, manager, attributeInitializationFilterName(2))
	var initialization setfilterstate.Config
	if err := filter.GetTypedConfig().UnmarshalTo(&initialization); err != nil {
		t.Fatal(err)
	}
	var sources []string
	for _, value := range initialization.OnRequestHeaders {
		if value.GetObjectKey() == "auth_gateway.attributes.requested_tenant" {
			sources = append(sources, value.GetFormatString().GetTextFormatSource().GetInlineString())
		}
	}
	if len(sources) != 2 ||
		!strings.Contains(sources[0], `metadata.filter_metadata["auth_gateway.api_key"]["identity"]`) ||
		!strings.Contains(sources[1], `metadata.filter_metadata["envoy.filters.http.jwt_authn"]["issuer-one"]["iss"] == "https://issuer-one.jwt.test"`) {
		t.Fatalf("mixed any_of header initializers lack credential guards: %v", sources)
	}
}

func TestMixedAllOfComparesHeaderAndVerifiedAttributeSources(t *testing.T) {
	c := loadConfigCase(t, "api-key-auth")
	c.Authenticators[0].Attributes["writer_id"] = AttributeSource{Header: new("X-Writer")}
	c.Authenticators[1].Attributes["tenant_id"] = AttributeSource{Header: new("X-Tenant")}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	policy := testServerAuthenticationRules(t, c, 3).Policies["authenticated"]
	if len(policy.Principals[0].GetAndIds().GetIds()) != 5 {
		t.Fatalf("all_of shared-attribute principals = %#v", policy.Principals)
	}
	conjunction := policy.Condition.GetCallExpr()
	if conjunction.GetFunction() != "_&&_" || len(conjunction.GetArgs()) != 2 {
		t.Fatalf("all_of equality condition = %#v", policy.Condition)
	}
	for index, want := range [][][]string{
		{{"metadata", "filter_metadata", "envoy.filters.http.jwt_authn", "issuer-one", "organization", "id"}, {"metadata", "filter_metadata", "auth_gateway.request_headers", "x-tenant"}},
		{{"metadata", "filter_metadata", "auth_gateway.request_headers", "x-writer"}, {"metadata", "filter_metadata", "auth_gateway.api_key", "attribute.writer_id"}},
	} {
		equality := conjunction.GetArgs()[index].GetCallExpr()
		if equality.GetFunction() != "_==_" || len(equality.GetArgs()) != 2 ||
			!slices.Equal(metadataReference(equality.GetArgs()[0]), want[0]) ||
			!slices.Equal(metadataReference(equality.GetArgs()[1]), want[1]) {
			t.Fatalf("shared attribute %d compares %v, want %v", index, equality, want)
		}
	}
}

func testServerAuthenticationRules(t *testing.T, c Config, serverIndex int) *rbac.RBAC {
	t.Helper()
	effective := resolveTestConfig(t, c)
	rules, err := effective.toServerAuthenticationRBACRules(effective.servers[serverIndex])
	if err != nil {
		t.Fatal(err)
	}
	return rules
}

func metadataReference(value *expr.Expr) []string {
	if call := value.GetCallExpr(); call != nil && call.Function == "_[_]" && len(call.Args) == 2 {
		return append(metadataReference(call.Args[0]), call.Args[1].GetConstExpr().GetStringValue())
	}
	if selectExpr := value.GetSelectExpr(); selectExpr != nil {
		return append(metadataReference(selectExpr.Operand), selectExpr.Field)
	}
	if identifier := value.GetIdentExpr(); identifier != nil {
		return []string{identifier.Name}
	}
	return nil
}
