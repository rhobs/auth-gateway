package config

import (
	"path"
	"slices"
	"strings"
	"testing"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	matching "github.com/envoyproxy/go-control-plane/envoy/extensions/common/matching/v3"
	headermutation "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/header_mutation/v3"
	headertometadata "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/header_to_metadata/v3"
	jwt "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/jwt_authn/v3"
	setfilterstate "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
)

func TestAPIKeyPipelineUsesFileECDSAndHostScopedFilters(t *testing.T) {
	c := loadConfigCase(t, "api-key-auth")
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	manager := firstHTTPManager(t, files[envoyConfigFilename])
	wantOrder := []string{
		requestControlsFilterName, requestMetricsFilterName, jwtAuthnFilterName, apiKeyFilterName,
		headerToMetadataFilterName, authenticationFilterName,
		attributeInitializationFilterName(1), attributeInitializationFilterName(2), attributeFilterName,
		authorizationFilterName, requiredHeaderFilterName, credentialCleanupFilterName,
		headerMutationFilterName, routerFilterName,
	}
	if got := httpFilterNames(manager); !slices.Equal(got, wantOrder) {
		t.Fatalf("HTTP filter order = %v, want %v", got, wantOrder)
	}
	keyFilter := apiKeyHTTPFilter(t, manager, apiKeyFilterName)
	discovery := keyFilter.GetConfigDiscovery()
	if !keyFilter.Disabled || discovery == nil || keyFilter.GetTypedConfig() != nil ||
		discovery.GetConfigSource().GetPathConfigSource().GetPath() != path.Join(apiKeyDirectory, apiKeySecretFilename) ||
		discovery.GetConfigSource().GetPathConfigSource().GetWatchedDirectory().GetPath() != apiKeyDirectory ||
		!slices.Equal(discovery.GetTypeUrls(), []string{"envoy.extensions.common.matching.v3.ExtensionWithMatcher"}) {
		t.Fatalf("API-key ECDS filter = %#v", keyFilter)
	}
	metadataFilter := apiKeyHTTPFilter(t, manager, headerToMetadataFilterName)
	var metadata headertometadata.Config
	if err := metadataFilter.GetTypedConfig().UnmarshalTo(&metadata); err != nil {
		t.Fatal(err)
	}
	rules := metadata.GetRequestRules()
	if len(rules) != 1 || rules[0].Header != apiKeyClientHeader || !rules[0].Remove ||
		rules[0].GetOnHeaderPresent().GetMetadataNamespace() != apiKeyMetadataNamespace ||
		rules[0].GetOnHeaderPresent().GetType() != headertometadata.Config_PROTOBUF_VALUE ||
		rules[0].GetOnHeaderPresent().GetEncode() != headertometadata.Config_BASE64 {
		t.Fatalf("API-key identity extraction = %#v", rules)
	}
	cleanupFilter := apiKeyHTTPFilter(t, manager, credentialCleanupFilterName)
	if cleanupFilter.Disabled {
		t.Fatal("credential removal was disabled on public routes")
	}
	var cleanup headermutation.HeaderMutation
	if err := cleanupFilter.GetTypedConfig().UnmarshalTo(&cleanup); err != nil {
		t.Fatal(err)
	}
	removed := make(map[string]bool)
	for _, mutation := range cleanup.GetMutations().GetRequestMutations() {
		removed[mutation.GetRemove()] = true
	}
	for _, name := range []string{"authorization", "x-partner-key", apiKeyClientHeader, jwtVerifiedHeaderName("issuer-one")} {
		if !removed[name] {
			t.Fatalf("credential cleanup does not remove %q: %v", name, removed)
		}
	}

	hosts := manager.GetRouteConfig().GetVirtualHosts()
	if len(hosts) != 3 || hosts[0].TypedPerFilterConfig[apiKeyFilterName] != nil ||
		hosts[0].TypedPerFilterConfig[authenticationFilterName] != nil {
		t.Fatalf("public host selected a credential filter: %#v", hosts[0].TypedPerFilterConfig)
	}
	keyRoute := apiKeyPerHostMatcher(t, hosts[1])
	if keyRoute.XdsMatcher != nil || hosts[1].TypedPerFilterConfig[jwtAuthnFilterName] != nil {
		t.Fatalf("key-only host has unexpected JWT or skip rules: %#v", hosts[1].TypedPerFilterConfig)
	}
	mixedRoute := apiKeyPerHostMatcher(t, hosts[2])
	matchers := mixedRoute.GetXdsMatcher().GetMatcherList().GetMatchers()
	if len(matchers) != 1 || matchers[0].GetPredicate().GetSinglePredicate().GetInput().GetName() != "envoy.matching.inputs.request_headers" {
		t.Fatalf("JWT-first API-key skip matcher = %#v", mixedRoute.GetXdsMatcher())
	}
	var marker jwt.JwtAuthentication
	if err := apiKeyHTTPFilter(t, manager, jwtAuthnFilterName).GetTypedConfig().UnmarshalTo(&marker); err != nil {
		t.Fatal(err)
	}
	if marker.RequirementMap[serverJWTRequirementName(2)].GetAllowMissingOrFailed() == nil ||
		len(marker.Providers["issuer-one"].ClaimToHeaders) != 1 ||
		marker.Providers["issuer-one"].ClaimToHeaders[0].HeaderName != jwtVerifiedHeaderName("issuer-one") {
		t.Fatalf("mixed any_of JWT marker and requirement = %#v", &marker)
	}
	bootstrap := decodeBootstrap(t, files[envoyConfigFilename])
	tlsManager := decodeHTTPManager(t, bootstrap.StaticResources.Listeners[0].FilterChains[1])
	var strict jwt.JwtAuthentication
	if err := apiKeyHTTPFilter(t, tlsManager, jwtAuthnFilterName).GetTypedConfig().UnmarshalTo(&strict); err != nil {
		t.Fatal(err)
	}
	if strict.RequirementMap[serverJWTRequirementName(3)].GetProviderName() != "issuer-one" ||
		apiKeyPerHostMatcher(t, tlsManager.GetRouteConfig().GetVirtualHosts()[0]).XdsMatcher != nil {
		t.Fatal("all_of server did not require JWT and API key without a skip matcher")
	}
}

func TestAPIKeyRawAuthorizationAndSharedAttributeEquality(t *testing.T) {
	c := loadConfigCase(t, "api-key-auth")
	keyOnly := serverAuthenticationRBACRules(c, c.Servers[1]).Policies["authenticated"].Principals[0]
	if matcher := keyOnly.GetSourcedMetadata().GetMetadataMatcher(); matcher == nil || matcher.Filter != apiKeyMetadataNamespace ||
		!slices.Equal(metadataMatcherPath(matcher.GetPath()), []string{"identity", "authenticator"}) ||
		matcher.GetValue().GetStringMatch().GetExact() != "partner-key" {
		t.Fatalf("key-only authentication principal = %#v", keyOnly)
	}
	mixed := serverAuthenticationRBACRules(c, c.Servers[2]).Policies["authenticated"].Principals[0].GetOrIds().GetIds()
	if len(mixed) != 2 || mixed[0].GetSourcedMetadata() == nil || mixed[1].GetHeader().GetName() != jwtVerifiedHeaderName("issuer-one") {
		t.Fatalf("mixed any_of authentication principal = %#v", mixed)
	}
	dualPolicy := serverAuthenticationRBACRules(c, c.Servers[3]).Policies["authenticated"]
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
	grant := grantPrincipal(c, c.AuthorizationPolicies[1].Grants[0])
	parts := grant.GetAndIds().GetIds()
	if len(parts) != 2 || parts[1].GetSourcedMetadata().GetMetadataMatcher().GetFilter() != apiKeyMetadataNamespace ||
		!slices.Equal(metadataMatcherPath(parts[1].GetSourcedMetadata().GetMetadataMatcher().GetPath()), []string{"identity", "attributes", "tenant_id"}) {
		t.Fatalf("API-key grant reads unprocessed Secret attributes: %#v", grant)
	}
	c.Servers[1].Authorization.AnyOf = []string{"jwt-writers", "key-writers"}
	grants := serverRBACRules(c, c.Servers[1]).Policies["api-ingest"].Principals[0].GetOrIds().GetIds()
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
	processing := decodeProcessingECDSConfig(t, files[processingConfigFilename])
	if len(processing.OnRequestHeaders) != 1 || processing.OnRequestHeaders[0].GetObjectKey() != filterStateKey("tenant_id") {
		t.Fatalf("processing ECDS contains credential extraction: %#v", processing.OnRequestHeaders)
	}
	manager := firstHTTPManager(t, files[envoyConfigFilename])
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
			format, ok := value.GetFormatString().GetFormat().(*core.SubstitutionFormatString_TextFormat)
			if !value.SkipIfEmpty || !ok || !strings.Contains(format.TextFormat, "metadata.filter_metadata") { //nolint:staticcheck // Assert the existing Envoy wire format.
				t.Fatalf("server %d initializer reads an unsafe source: %#v", test.index, value)
			}
		}
	}
}

func TestPublicOnlyChainRemovesConfiguredCredentials(t *testing.T) {
	c := loadConfigCase(t, "api-key-auth")
	c.Servers = []Server{c.Servers[0], c.Servers[3]}
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := decodeBootstrap(t, files[envoyConfigFilename])
	manager := decodeHTTPManager(t, bootstrap.StaticResources.Listeners[0].FilterChains[0])
	if got, want := httpFilterNames(manager), []string{requestControlsFilterName, credentialCleanupFilterName, routerFilterName}; !slices.Equal(got, want) {
		t.Fatalf("public-only HTTP filter order = %v, want %v", got, want)
	}
}

func apiKeyHTTPFilter(t *testing.T, manager *hcm.HttpConnectionManager, name string) *hcm.HttpFilter {
	t.Helper()
	for _, filter := range manager.HttpFilters {
		if filter.Name == name {
			return filter
		}
	}
	t.Fatalf("HTTP filter %q is missing", name)
	return nil
}

func apiKeyPerHostMatcher(t *testing.T, host *route.VirtualHost) *matching.ExtensionWithMatcherPerRoute {
	t.Helper()
	packed := host.TypedPerFilterConfig[apiKeyFilterName]
	if packed == nil {
		t.Fatalf("host %q did not enable the API-key filter", host.Name)
	}
	var enabled route.FilterConfig
	if err := packed.UnmarshalTo(&enabled); err != nil {
		t.Fatal(err)
	}
	if enabled.Config == nil || enabled.Disabled {
		t.Fatalf("host %q API-key enable config = %#v", host.Name, &enabled)
	}
	var perRoute matching.ExtensionWithMatcherPerRoute
	if err := enabled.Config.UnmarshalTo(&perRoute); err != nil {
		t.Fatal(err)
	}
	return &perRoute
}

func metadataMatcherPath(segments []*matcher.MetadataMatcher_PathSegment) []string {
	keys := make([]string, 0, len(segments))
	for _, segment := range segments {
		keys = append(keys, segment.GetKey())
	}
	return keys
}
