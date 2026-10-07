package config

import (
	"slices"
	"strings"
	"testing"

	headertometadata "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/header_to_metadata/v3"
	setfilterstate "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"
	expr "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

func TestHeaderMetadataCapturePreservesRequestHeader(t *testing.T) {
	c := loadAuthExample(t)
	c.Authenticators[2].Attributes["requested_tenant"] = AttributeSource{Header: testStringPointer("x-TENANT")}
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	manager := firstHTTPManager(t, files[envoyConfigFilename])
	names := httpFilterNames(manager)
	headerFilter := slices.Index(names, "envoy.filters.http.header_to_metadata")
	if headerFilter < 0 || headerFilter <= slices.Index(names, "envoy.filters.http.api_key_auth") ||
		headerFilter >= slices.Index(names, "auth_gateway.authentication") ||
		headerFilter >= slices.Index(names, "envoy.filters.http.rbac") ||
		headerFilter >= slices.Index(names, "envoy.filters.http.header_mutation") {
		t.Fatalf("header capture is not before authentication, grants, and mutation: %v", names)
	}
	var metadata headertometadata.Config
	if err := manager.HttpFilters[headerFilter].GetTypedConfig().UnmarshalTo(&metadata); err != nil {
		t.Fatal(err)
	}
	var captured []*headertometadata.Config_Rule
	for _, rule := range metadata.GetRequestRules() {
		if rule.GetOnHeaderPresent().GetMetadataNamespace() == "auth_gateway.request_headers" {
			captured = append(captured, rule)
		}
	}
	if len(captured) != 1 || captured[0].Header != "x-tenant" || captured[0].Remove ||
		captured[0].OnHeaderMissing != nil || captured[0].GetOnHeaderPresent().GetKey() != "x-tenant" ||
		captured[0].GetOnHeaderPresent().GetType() != headertometadata.Config_STRING ||
		captured[0].GetOnHeaderPresent().GetEncode() != headertometadata.Config_NONE {
		t.Fatalf("header capture rules = %#v", captured)
	}
}

func TestJWTHeaderOnlyGrantRequiresNamedVerifiedIssuer(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-multiple-issuers")
	c.Authenticators[0].Attributes["requested_tenant"] = AttributeSource{Header: testStringPointer("X-Tenant")}
	c.AuthorizationPolicies[0].Grants[0].Attributes = map[string][]string{"requested_tenant": {"customer-a"}}
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	manager := firstHTTPManager(t, files[envoyConfigFilename])
	names := httpFilterNames(manager)
	if slices.Index(names, "envoy.filters.http.header_to_metadata") < 0 ||
		slices.Index(names, "envoy.filters.http.set_filter_state") >= 0 {
		t.Fatalf("header-only grant needs capture but no working attributes: %v", names)
	}
	grant := grantPrincipal(c, c.AuthorizationPolicies[0].Grants[0]).GetAndIds().GetIds()
	if len(grant) != 2 {
		t.Fatalf("header-only JWT grant principals = %#v", grant)
	}
	header := grant[0].GetSourcedMetadata().GetMetadataMatcher()
	issuer := grant[1].GetSourcedMetadata().GetMetadataMatcher()
	if header.GetFilter() != "auth_gateway.request_headers" ||
		!slices.Equal(metadataMatcherPath(header.GetPath()), []string{"x-tenant"}) ||
		header.GetValue().GetStringMatch().GetExact() != "customer-a" ||
		issuer.GetFilter() != "envoy.filters.http.jwt_authn" ||
		!slices.Equal(metadataMatcherPath(issuer.GetPath()), []string{"issuer-one", "iss"}) ||
		issuer.GetValue().GetStringMatch().GetExact() != "https://issuer-one.jwt.test" {
		t.Fatalf("header-only JWT grant does not bind the named issuer: %#v", grant)
	}
}

func TestHeaderWorkingAttributesRequireVerifiedAuthenticator(t *testing.T) {
	c := loadConfigCase(t, "api-key-auth")
	c.Authenticators[0].Attributes["requested_tenant"] = AttributeSource{Header: testStringPointer("X-Tenant")}
	c.Authenticators[1].Attributes["requested_tenant"] = AttributeSource{Header: testStringPointer("X-Tenant")}
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	manager := firstHTTPManager(t, files[envoyConfigFilename])
	filter := apiKeyHTTPFilter(t, manager, attributeInitializationFilterName(2))
	var initialization setfilterstate.Config
	if err := filter.GetTypedConfig().UnmarshalTo(&initialization); err != nil {
		t.Fatal(err)
	}
	var sources []string
	for _, value := range initialization.OnRequestHeaders {
		if value.GetObjectKey() == "auth_gateway.attributes.requested_tenant" {
			sources = append(sources, value.GetFormatString().GetTextFormat()) //nolint:staticcheck // Assert the generated Envoy wire format.
		}
	}
	if len(sources) != 2 ||
		!strings.Contains(sources[0], `metadata.filter_metadata["auth_gateway.api_key"]["identity"]`) ||
		!strings.Contains(sources[1], `metadata.filter_metadata["envoy.filters.http.jwt_authn"]["issuer-one"]["iss"] == "https://issuer-one.jwt.test"`) {
		t.Fatalf("mixed any_of header initializers lack credential guards: %v", sources)
	}
	processing := decodeProcessingECDSConfig(t, files[processingConfigFilename])
	if len(processing.OnRequestHeaders) != 1 || strings.Contains(processing.OnRequestHeaders[0].GetFormatString().GetTextFormat(), "auth_gateway.request_headers") { //nolint:staticcheck // Assert the generated Envoy wire format.
		t.Fatalf("mapping ECDS contains header extraction: %#v", processing.OnRequestHeaders)
	}
}

func TestMixedAllOfComparesHeaderAndVerifiedAttributeSources(t *testing.T) {
	c := loadConfigCase(t, "api-key-auth")
	c.Authenticators[0].Attributes["writer_id"] = AttributeSource{Header: testStringPointer("X-Writer")}
	c.Authenticators[1].Attributes["tenant_id"] = AttributeSource{Header: testStringPointer("X-Tenant")}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	policy := serverAuthenticationRBACRules(c, c.Servers[3]).Policies["authenticated"]
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
