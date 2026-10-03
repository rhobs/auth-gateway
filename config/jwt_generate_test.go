package config

import (
	"encoding/json"
	"path"
	"reflect"
	"strings"
	"testing"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	rbac "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	setfilterstatecommon "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/common/set_filter_state/v3"
	headermutation "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/header_mutation/v3"
	jwt "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/jwt_authn/v3"
	httpRBAC "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rbac/v3"
	setfilterstate "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"go.yaml.in/yaml/v3"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"
)

func loadConfigCase(t testing.TB, name string) Config {
	t.Helper()
	config, err := Load(strings.NewReader(readFixture(t, name+"/config.yaml")))
	if err != nil {
		t.Fatalf("load %s case: %v", name, err)
	}
	return config
}

func TestJWTFilterOrderAndNativeProviders(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-multiple-issuers")
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	generated := decodeBootstrap(t, files["envoy.yaml"])
	manager := decodeHTTPManager(t, generated.StaticResources.Listeners[0].FilterChains[0])
	if got, want := httpFilterNames(manager), []string{
		requestControlsFilterName, "envoy.filters.http.jwt_authn", authorizationFilterName, "envoy.filters.http.router",
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("plain JWT filter order = %v, want %v", got, want)
	}

	var jwtConfig jwt.JwtAuthentication
	if err := manager.HttpFilters[1].GetTypedConfig().UnmarshalTo(&jwtConfig); err != nil {
		t.Fatal(err)
	}
	if len(jwtConfig.Providers) != 2 || len(jwtConfig.RequirementMap) != 2 {
		t.Fatalf("JWT provider/requirement counts = %d/%d", len(jwtConfig.Providers), len(jwtConfig.RequirementMap))
	}
	for name, issuer := range map[string]string{
		"issuer-one": "https://issuer-one.jwt.test",
		"issuer-two": "https://issuer-two.jwt.test",
	} {
		provider := jwtConfig.Providers[name]
		if provider == nil || provider.Issuer != issuer || provider.PayloadInMetadata != name ||
			!provider.RequireExpiration || provider.Forward || len(provider.FromHeaders) != 1 ||
			provider.FromHeaders[0].Name != "Authorization" || provider.FromHeaders[0].ValuePrefix != "Bearer " {
			t.Fatalf("JWT provider %q = %#v", name, provider)
		}
		remote := provider.GetRemoteJwks()
		if remote == nil || remote.HttpUri == nil || remote.HttpUri.GetCluster() != jwksClusterName(name) {
			t.Fatalf("JWT provider %q has no dedicated JWKS cluster", name)
		}
	}
	if jwtConfig.RequirementMap[serverJWTRequirementName(1)].GetProviderName() != "issuer-one" {
		t.Fatalf("issuer-restricted server JWT requirement = %#v", jwtConfig.RequirementMap[serverJWTRequirementName(1)])
	}

	clusters := make(map[string]*cluster.Cluster, len(generated.StaticResources.Clusters))
	for _, item := range generated.StaticResources.Clusters {
		clusters[item.Name] = item
	}
	for _, name := range []string{"issuer-one", "issuer-two"} {
		jwks := clusters[jwksClusterName(name)]
		if jwks == nil || jwks.TransportSocket == nil {
			t.Fatalf("missing TLS JWKS cluster for %q", name)
		}
		var upstream tls.UpstreamTlsContext
		if err := jwks.TransportSocket.GetTypedConfig().UnmarshalTo(&upstream); err != nil {
			t.Fatal(err)
		}
		if upstream.GetSni() == "" || upstream.GetCommonTlsContext().GetValidationContext().GetTrustedCa().GetFilename() == "" {
			t.Fatalf("JWKS TLS validation is not enabled for %q", name)
		}
	}
}

func TestJWTAuthorizationReadsOriginalClaimsFromNamedProvider(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-multiple-issuers")
	rules := serverRBACRules(c, c.Servers[0])
	policy := rules.Policies["api-metrics"]
	if policy == nil || len(policy.Principals) != 1 {
		t.Fatalf("API authorization policy = %#v", policy)
	}
	grants := policy.Principals[0].GetOrIds().Ids
	if len(grants) != 2 {
		t.Fatalf("provider grant count = %d, want one for each issuer", len(grants))
	}
	gotValues := make(map[string]string, len(grants))
	for _, grant := range grants {
		claim := grant.GetSourcedMetadata()
		if claim == nil || claim.MetadataSource != rbac.MetadataSource_DYNAMIC || claim.GetMetadataMatcher().GetFilter() != "envoy.filters.http.jwt_authn" {
			t.Fatalf("grant does not use verified JWT metadata: %#v", grant)
		}
		var path []string
		for _, segment := range claim.GetMetadataMatcher().GetPath() {
			path = append(path, segment.GetKey())
		}
		if len(path) != 3 || path[1] != "organization" || path[2] != "id" {
			t.Fatalf("grant claim path = %v, want provider.organization.id", path)
		}
		value := claim.GetMetadataMatcher().GetValue().GetStringMatch().GetExact()
		gotValues[path[0]] = value
	}
	if !reflect.DeepEqual(gotValues, map[string]string{"issuer-one": "customer-a", "issuer-two": "customer-b"}) {
		t.Fatalf("raw provider grants = %v", gotValues)
	}

	config, err := jwtFilterConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	any := config.RequirementMap[serverJWTRequirementName(0)].GetRequiresAny().Requirements
	if len(any) != 2 || any[0].GetProviderName() != "issuer-one" || any[1].GetProviderName() != "issuer-two" {
		t.Fatalf("alternative issuer requirement = %#v", any)
	}
}

func TestJWTProcessingAndHeaderFilterOrder(t *testing.T) {
	plain := loadConfigCase(t, "jwt-auth")
	plainFiles, err := Generate(plain)
	if err != nil {
		t.Fatal(err)
	}
	plainManager := firstHTTPManager(t, plainFiles["envoy.yaml"])
	if got, want := httpFilterNames(plainManager), []string{
		requestControlsFilterName, "envoy.filters.http.jwt_authn", authorizationFilterName, "envoy.filters.http.router",
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("plain JWT filters = %v, want %v", got, want)
	}
	if len(plainFiles) != 1 {
		t.Fatalf("plain JWT files = %v, want only the bootstrap", fileNames(plainFiles))
	}

	directHeaders := loadConfigCase(t, "jwt-auth-with-headers")
	directFiles, err := Generate(directHeaders)
	if err != nil {
		t.Fatal(err)
	}
	directManager := firstHTTPManager(t, directFiles["envoy.yaml"])
	wantDirect := []string{
		requestControlsFilterName, "envoy.filters.http.jwt_authn", authorizationFilterName, attributeFilterName,
		requiredHeaderFilterName, "envoy.filters.http.header_mutation", "envoy.filters.http.router",
	}
	if got := httpFilterNames(directManager); !reflect.DeepEqual(got, wantDirect) {
		t.Fatalf("direct header filter order = %v, want %v", got, wantDirect)
	}
	if len(directFiles) != 1 {
		t.Fatalf("direct header files = %v, want only the Envoy bootstrap", fileNames(directFiles))
	}
	assertNoLuaResources(t, plainFiles, plainManager)
	assertNoLuaResources(t, directFiles, directManager)

	resources, err := GenerateKubernetes(directHeaders)
	if err != nil {
		t.Fatal(err)
	}
	if len(resources.Deployment.Spec.Template.Spec.Volumes) != 2 {
		t.Fatalf("direct header volumes = %v, want config and metrics only", resources.Deployment.Spec.Template.Spec.Volumes)
	}
}

func TestJWTRequiredHeadersAreRouteScopedAndManaged(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-with-headers")
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	manager := firstHTTPManager(t, files["envoy.yaml"])
	var globalMutation headermutation.HeaderMutation
	for _, filter := range manager.HttpFilters {
		if filter.Name == "envoy.filters.http.header_mutation" {
			if err := filter.GetTypedConfig().UnmarshalTo(&globalMutation); err != nil {
				t.Fatal(err)
			}
		}
	}
	removed := make(map[string]bool)
	for _, mutation := range globalMutation.GetMutations().GetRequestMutations() {
		removed[mutation.GetRemove()] = mutation.GetRemove() != ""
	}
	if len(removed) != 2 || !removed["x-scope-orgid"] || !removed["x-writer-id"] {
		t.Fatalf("managed headers removed = %v", removed)
	}
	var initialized setfilterstate.Config
	for _, filter := range manager.HttpFilters {
		if filter.Name == attributeFilterName {
			if err := filter.GetTypedConfig().UnmarshalTo(&initialized); err != nil {
				t.Fatal(err)
			}
		}
	}
	if len(initialized.OnRequestHeaders) != 2 {
		t.Fatalf("initialized attribute count = %d, want tenant_id and writer_id", len(initialized.OnRequestHeaders))
	}
	for i, name := range []string{"tenant_id", "writer_id"} {
		update := initialized.OnRequestHeaders[i]
		key, ok := update.GetKey().(*setfilterstatecommon.FilterStateValue_ObjectKey)
		value, valueOK := update.GetValue().(*setfilterstatecommon.FilterStateValue_FormatString)
		if !ok || key.ObjectKey != filterStateKey(name) || !valueOK || update.FactoryKey != "envoy.string" || !update.SkipIfEmpty || !value.FormatString.OmitEmptyValues {
			t.Fatalf("initialized attribute %q has unsafe or incomplete filter-state settings: %#v", name, update)
		}
	}

	host := manager.GetRouteConfig().GetVirtualHosts()[0]
	var protected, methodFallback, notFound bool
	for _, generatedRoute := range host.GetRoutes() {
		switch generatedRoute.Name {
		case "api-0-metrics-route-0-method-0":
			protected = true
			headerConfig := generatedRoute.TypedPerFilterConfig["envoy.filters.http.header_mutation"]
			if headerConfig == nil {
				t.Fatal("protected route has no per-route header values")
			}
			var perRoute headermutation.HeaderMutationPerRoute
			if err := headerConfig.UnmarshalTo(&perRoute); err != nil {
				t.Fatal(err)
			}
			values := make(map[string]string)
			for _, mutation := range perRoute.GetMutations().GetRequestMutations() {
				append := mutation.GetAppend()
				if append != nil && append.GetHeader() != nil {
					values[append.GetHeader().GetKey()] = append.GetHeader().GetValue()
				}
			}
			if !reflect.DeepEqual(values, map[string]string{
				"X-Scope-OrgID": "%FILTER_STATE(auth_gateway.attributes.tenant_id:PLAIN)%",
				"X-Writer-ID":   "%FILTER_STATE(auth_gateway.attributes.writer_id:PLAIN)%",
			}) {
				t.Fatalf("per-route header values = %v", values)
			}
			rbacConfig := generatedRoute.TypedPerFilterConfig[requiredHeaderFilterName]
			if rbacConfig == nil {
				t.Fatal("protected route has no required-attribute check")
			}
			var required httpRBAC.RBACPerRoute
			if err := rbacConfig.UnmarshalTo(&required); err != nil {
				t.Fatal(err)
			}
			policy := required.GetRbac().GetRules().GetPolicies()["required-attributes"]
			if policy == nil || len(policy.Principals) != 1 {
				t.Fatalf("required header policy = %#v", policy)
			}
			principals := policy.Principals[0].GetAndIds().Ids
			if len(principals) != 2 {
				t.Fatalf("required header attribute count = %d", len(principals))
			}
			keys := make([]string, 0, len(principals))
			for _, principal := range principals {
				filterState := principal.GetFilterState()
				if filterState.GetStringMatch().GetSafeRegex().GetRegex() != headerValuePattern {
					t.Fatalf("required attribute matcher = %#v", filterState.GetStringMatch())
				}
				keys = append(keys, filterState.GetKey())
			}
			if !reflect.DeepEqual(keys, []string{filterStateKey("tenant_id"), filterStateKey("writer_id")}) {
				t.Fatalf("required header filter-state keys = %v", keys)
			}
		case "method-not-allowed-0":
			methodFallback = true
			if generatedRoute.TypedPerFilterConfig[requiredHeaderFilterName] != nil {
				t.Fatal("method fallback incorrectly requires upstream header values")
			}
		case "not-found":
			notFound = true
			if generatedRoute.TypedPerFilterConfig[requiredHeaderFilterName] != nil {
				t.Fatal("not-found route incorrectly requires upstream header values")
			}
		}
	}
	if !protected || !methodFallback || !notFound {
		t.Fatalf("route cases protected/fallback/not-found = %t/%t/%t", protected, methodFallback, notFound)
	}
}

func TestJWTProcessingUsesFileBasedECDSConfiguration(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-with-mappings")
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	manager := firstHTTPManager(t, files["envoy.yaml"])
	assertNoLuaResources(t, files, manager)
	want := []string{
		requestControlsFilterName, "envoy.filters.http.jwt_authn", authorizationFilterName, attributeFilterName,
		requiredHeaderFilterName, "envoy.filters.http.header_mutation", "envoy.filters.http.router",
	}
	if got := httpFilterNames(manager); !reflect.DeepEqual(got, want) {
		t.Fatalf("mapping filter order = %v, want %v", got, want)
	}
	if files[processingConfigFilename] == nil {
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
	if got := configDiscovery.GetConfigSource().GetPathConfigSource().GetPath(); got != path.Join(processingDirectory, processingConfigFilename) {
		t.Fatalf("ECDS config path = %q", got)
	}
	wantTypeURL := string((&setfilterstate.Config{}).ProtoReflect().Descriptor().FullName())
	if !reflect.DeepEqual(configDiscovery.GetTypeUrls(), []string{wantTypeURL}) {
		t.Fatalf("ECDS type URLs = %v, want %q", configDiscovery.GetTypeUrls(), wantTypeURL)
	}
	processing := decodeProcessingECDSConfig(t, files[processingConfigFilename])
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
	if format == nil || !format.OmitEmptyValues || !strings.HasPrefix(format.GetTextFormat(), "%CEL(") || !strings.HasSuffix(format.GetTextFormat(), ")%") {
		t.Fatalf("mapping formatter = %#v", update.GetValue())
	}
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

func TestJWTExpressionsUseEnvoyCELVariablesAndGuardMissingAttributes(t *testing.T) {
	claim := jwtClaimExpression([]string{"issuer-one", "organization", "id"})
	if !strings.Contains(claim, `"issuer-one" in metadata.filter_metadata["envoy.filters.http.jwt_authn"]`) || strings.Contains(claim, "dynamicMetadata(") || strings.Contains(claim, "dynamic_metadata[") {
		t.Fatalf("JWT claim expression does not use Envoy CEL metadata: %s", claim)
	}

	mapping := attributeMappingExpression("tenant_id", map[string]string{"client-123": "team-a"})
	key := celStringLiteral(filterStateKey("tenant_id"))
	if !strings.Contains(mapping, key+" in filter_state") || !strings.Contains(mapping, "filter_state["+key+"]") || strings.Contains(mapping, "filterState(") {
		t.Fatalf("attribute mapping expression does not safely read Envoy CEL filter state: %s", mapping)
	}
	if strings.Contains(mapping, "string(") || !strings.Contains(mapping, `? "team-a" : ""`) {
		t.Fatalf("unmatched mapping must skip the update without converting bytes: %s", mapping)
	}
}

func TestJWTAuthorizationPolicyCombinationsAreAPIScoped(t *testing.T) {
	c := loadAuthExample(t)
	rules := serverRBACRules(c, c.Servers[0])
	if rules.Policies["api-metrics-write"] == nil || rules.Policies["api-logs"] == nil {
		t.Fatalf("any_of policies did not generate both granted API rules: %#v", rules.Policies)
	}
	metricsGrants := rules.Policies["api-metrics-write"].Principals[0].GetOrIds().Ids
	if len(metricsGrants) != 2 {
		t.Fatalf("metrics API grant principals = %d, want one grant from each issuer", len(metricsGrants))
	}

	c.Servers[0].Authorization = &Authorization{AllOf: []string{"metrics-writers", "logs-writers"}}
	rules = serverRBACRules(c, c.Servers[0])
	if rules.Policies["api-metrics-write"] != nil || rules.Policies["api-logs"] != nil {
		t.Fatalf("all_of policies for disjoint APIs granted access: %#v", rules.Policies)
	}
	if rules.Policies["local-responses"] == nil {
		t.Fatal("all_of denied APIs but removed local 404/405 responses")
	}
}

func firstHTTPManager(t testing.TB, data []byte) *hcm.HttpConnectionManager {
	t.Helper()
	generated := decodeBootstrap(t, data)
	for _, chain := range generated.StaticResources.Listeners[0].FilterChains {
		manager := decodeHTTPManager(t, chain)
		if containsFilter(manager, "envoy.filters.http.jwt_authn") {
			return manager
		}
	}
	t.Fatal("no protected HTTP manager was generated")
	return nil
}

func httpFilterNames(manager *hcm.HttpConnectionManager) []string {
	names := make([]string, len(manager.HttpFilters))
	for i, filter := range manager.HttpFilters {
		names[i] = filter.Name
	}
	return names
}

func containsFilter(manager *hcm.HttpConnectionManager, name string) bool {
	for _, filter := range manager.HttpFilters {
		if filter.Name == name {
			return true
		}
	}
	return false
}

func assertNoLuaResources(t *testing.T, files map[string][]byte, manager *hcm.HttpConnectionManager) {
	t.Helper()
	for name := range files {
		if strings.Contains(strings.ToLower(name), "lua") {
			t.Fatalf("generated obsolete Lua resource %q", name)
		}
	}
	for _, filter := range manager.HttpFilters {
		if strings.Contains(strings.ToLower(filter.Name), "lua") {
			t.Fatalf("generated obsolete Lua filter %q", filter.Name)
		}
	}
}

func fileNames(files map[string][]byte) []string {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	return names
}

func TestGenerateJWKSProviderClusterCount(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth")
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	generated := decodeBootstrap(t, files["envoy.yaml"])
	if got, want := len(generated.StaticResources.Clusters), len(c.APIs)+1; got != want {
		t.Fatalf("cluster count = %d, want %d", got, want)
	}
}

func TestJWTProcessingIsDeterministic(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-with-mappings")
	first, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range first {
		if !reflect.DeepEqual(data, second[name]) {
			t.Fatalf("%s generation is not deterministic", name)
		}
	}
}
