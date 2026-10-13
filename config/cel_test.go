package config

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	rbac "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	setfilterstatecommon "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/common/set_filter_state/v3"
	setfilterstate "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"go.yaml.in/yaml/v3"
	expr "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestJWTProcessingUsesFileBasedECDSConfiguration(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-with-mappings")
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	manager := firstHTTPManager(t, files.EnvoyBootstrap.Contents)
	if files.ProcessingConfig == nil {
		t.Fatal("mapping configuration is missing its ECDS response file")
	}
	var processingFilter *hcm.HttpFilter
	for _, filter := range manager.HttpFilters {
		if filter.Name != attributeFilterName {
			continue
		}
		processingFilter = filter
	}
	if processingFilter == nil || processingFilter.GetTypedConfig() != nil || processingFilter.GetConfigDiscovery() == nil {
		t.Fatalf("attribute processing filter = %#v, want file-based ECDS", processingFilter)
	}
	configDiscovery := processingFilter.GetConfigDiscovery()
	if got := configDiscovery.GetConfigSource().GetPathConfigSource().GetPath(); got != ProcessingConfigPath {
		t.Fatalf("ECDS config path = %q", got)
	}
	wantTypeURL := string((&setfilterstate.Config{}).ProtoReflect().Descriptor().FullName())
	if !reflect.DeepEqual(configDiscovery.GetTypeUrls(), []string{wantTypeURL}) {
		t.Fatalf("ECDS type URLs = %v, want %q", configDiscovery.GetTypeUrls(), wantTypeURL)
	}
	processing := decodeProcessingECDSConfig(t, files.ProcessingConfig.Contents)
	if got := len(processing.OnRequestHeaders); got == 0 {
		t.Fatal("ECDS set_filter_state config has no updates")
	}
	wantKeys := []string{
		filterStateKey("tenant_id"), filterStateKey("writer_id"),
		filterStateKey("tenant_id"), filterStateKey("writer_id"), filterStateKey("tenant_id"),
	}
	if len(processing.OnRequestHeaders) != len(wantKeys) {
		t.Fatalf("attribute processing updates = %d, want %d", len(processing.OnRequestHeaders), len(wantKeys))
	}
	for i, update := range processing.OnRequestHeaders {
		key, ok := update.GetKey().(*setfilterstatecommon.FilterStateValue_ObjectKey)
		if !ok || key.ObjectKey != wantKeys[i] || !update.SkipIfEmpty {
			t.Fatalf("attribute processing update %d key/skip behavior = %#v/%t", i, update.GetKey(), update.SkipIfEmpty)
		}
	}
	update := processing.OnRequestHeaders[len(processing.OnRequestHeaders)-1]
	value, ok := update.GetValue().(*setfilterstatecommon.FilterStateValue_FormatString)
	if !ok {
		t.Fatalf("mapping value = %#v, want a format string", update.GetValue())
	}
	format := value.FormatString
	if format == nil || !format.OmitEmptyValues {
		t.Fatalf("mapping formatter = %#v", update.GetValue())
	}
	textFormat := format.GetTextFormatSource()
	if textFormat == nil || !strings.HasPrefix(textFormat.GetInlineString(), "%CEL(") || !strings.HasSuffix(textFormat.GetInlineString(), ")%") {
		t.Fatalf("mapping formatter = %#v", update.GetValue())
	}
}

func TestOrderedAttributeMappersGenerateSequentialECDSUpdates(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-with-mappings")
	first := c.Processing[0]
	first.Attributes["order_id"] = AttributeMappings{Mappings: map[string]string{"first": "second"}}
	c.Processing[0] = first
	c.Processing = append(c.Processing, Processor{
		Name: "later-mappings",
		Type: "attribute-mapper",
		Attributes: map[string]AttributeMappings{
			"order_id": {Mappings: map[string]string{"second": "final"}},
		},
	})

	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	processing := decodeProcessingECDSConfig(t, files.ProcessingConfig.Contents)
	var expressions []string
	for _, update := range processing.OnRequestHeaders {
		if update.GetObjectKey() != filterStateKey("order_id") {
			continue
		}
		format := update.GetFormatString().GetTextFormatSource()
		if format == nil {
			t.Fatal("ordered mapper update has no CEL expression")
		}
		expressions = append(expressions, format.GetInlineString())
	}
	if len(expressions) != 2 {
		t.Fatalf("order_id mapping updates = %d, want two: %v", len(expressions), expressions)
	}
	for index, want := range []string{"== b\"first\" ? \"second\"", "== b\"second\" ? \"final\""} {
		if !strings.Contains(expressions[index], want) {
			t.Errorf("mapper %d expression = %q, want it to contain %q", index, expressions[index], want)
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

	mapping := attributeMappingExpression("tenant_id", map[string]string{"client-123": "team-a"})
	key := `"auth_gateway.attributes.tenant_id"`
	if !strings.Contains(mapping, key+" in filter_state") || !strings.Contains(mapping, "filter_state["+key+"]") || strings.Contains(mapping, "filterState(") {
		t.Fatalf("attribute mapping expression does not safely read Envoy CEL filter state: %s", mapping)
	}
	if strings.Contains(mapping, "string(") || !strings.Contains(mapping, `? "team-a" : ""`) {
		t.Fatalf("unmatched mapping must skip the update without converting bytes: %s", mapping)
	}
}

func TestAPIKeyRawAuthorizationAndSharedAttributeEquality(t *testing.T) {
	c := loadConfigCase(t, "api-key-auth")
	keyOnly := testServerAuthenticationRules(t, c, c.Servers[1]).Policies["authenticated"].Principals[0]
	if matcher := keyOnly.GetSourcedMetadata().GetMetadataMatcher(); matcher == nil || matcher.Filter != apiKeyMetadataNamespace ||
		!slices.Equal(metadataMatcherPath(matcher.GetPath()), []string{"identity"}) ||
		matcher.GetValue().GetStringMatch().GetSafeRegex().GetRegex() != apiKeyClientPattern(c.Authenticators[1].credentialAttributeNames(), "") {
		t.Fatalf("key-only authentication principal = %#v", keyOnly)
	}
	mixed := testServerAuthenticationRules(t, c, c.Servers[2]).Policies["authenticated"].Principals[0].GetOrIds().GetIds()
	if len(mixed) != 2 || mixed[0].GetSourcedMetadata() == nil || mixed[1].GetHeader().GetName() != jwtVerifiedHeaderName("issuer-one") {
		t.Fatalf("mixed any_of authentication principal = %#v", mixed)
	}
	dualPolicy := testServerAuthenticationRules(t, c, c.Servers[3]).Policies["authenticated"]
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
	grant := c.toGrantPrincipal(c.AuthorizationPolicies[1].Grants[0])
	parts := grant.GetAndIds().GetIds()
	if len(parts) != 2 || parts[1].GetSourcedMetadata().GetMetadataMatcher().GetFilter() != apiKeyMetadataNamespace ||
		!slices.Equal(metadataMatcherPath(parts[1].GetSourcedMetadata().GetMetadataMatcher().GetPath()), []string{"attribute.tenant_id"}) {
		t.Fatalf("API-key grant reads unprocessed Secret attributes: %#v", grant)
	}
	c.Servers[1].Authorization.AnyOf = []string{"jwt-writers", "key-writers"}
	grants := c.toServerRBACRules(c.Servers[1]).Policies["api-ingest"].Principals[0].GetOrIds().GetIds()
	if len(grants) != 1 || grants[0].GetAndIds() == nil {
		t.Fatalf("key-only host used an unselected JWT grant: %#v", grants)
	}
}

func TestAPIKeyInitializersKeepMappingECDSSeparate(t *testing.T) {
	c := loadConfigCase(t, "api-key-auth")
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	processing := decodeProcessingECDSConfig(t, files.ProcessingConfig.Contents)
	if len(processing.OnRequestHeaders) != 1 || processing.OnRequestHeaders[0].GetObjectKey() != filterStateKey("tenant_id") {
		t.Fatalf("processing ECDS contains credential extraction: %#v", processing.OnRequestHeaders)
	}
	manager := firstHTTPManager(t, files.EnvoyBootstrap.Contents)
	for _, test := range []struct {
		index int
		want  int
	}{
		{index: 1, want: 2},
		{index: 2, want: 4},
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
	processing := decodeProcessingECDSConfig(t, files.ProcessingConfig.Contents)
	if len(processing.OnRequestHeaders) != 1 || strings.Contains(processing.OnRequestHeaders[0].GetFormatString().GetTextFormatSource().GetInlineString(), "auth_gateway.request_headers") {
		t.Fatalf("mapping ECDS contains header extraction: %#v", processing.OnRequestHeaders)
	}
}

func TestMixedAllOfComparesHeaderAndVerifiedAttributeSources(t *testing.T) {
	c := loadConfigCase(t, "api-key-auth")
	c.Authenticators[0].Attributes["writer_id"] = AttributeSource{Header: new("X-Writer")}
	c.Authenticators[1].Attributes["tenant_id"] = AttributeSource{Header: new("X-Tenant")}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	policy := testServerAuthenticationRules(t, c, c.Servers[3]).Policies["authenticated"]
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

func testServerAuthenticationRules(t *testing.T, c Config, server Server) *rbac.RBAC {
	t.Helper()
	rules, err := c.toServerAuthenticationRBACRules(server)
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

func decodeProcessingECDSConfig(t testing.TB, data []byte) *setfilterstate.Config {
	t.Helper()
	var document map[string]any
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatalf("decode ECDS response YAML: %v", err)
	}
	resources, ok := document["resources"].([]any)
	if !ok || len(resources) != 1 {
		t.Fatalf("processing ECDS resources = %#v, want one resource", document["resources"])
	}
	resourceJSON, err := json.Marshal(resources[0])
	if err != nil {
		t.Fatalf("encode processing ECDS resource: %v", err)
	}
	var packed anypb.Any
	if err := protojson.Unmarshal(resourceJSON, &packed); err != nil {
		t.Fatalf("decode packed processing ECDS resource: %v", err)
	}
	var extension core.TypedExtensionConfig
	if err := packed.UnmarshalTo(&extension); err != nil {
		t.Fatalf("decode processing extension config: %v", err)
	}
	if extension.Name != attributeFilterName {
		t.Fatalf("ECDS resource name = %q, want %q", extension.Name, attributeFilterName)
	}
	var processing setfilterstate.Config
	if err := extension.TypedConfig.UnmarshalTo(&processing); err != nil {
		t.Fatalf("decode processing filter config: %v", err)
	}
	return &processing
}
