package envoy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	matching "github.com/envoyproxy/go-control-plane/envoy/extensions/common/matching/v3"
	apikey "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/api_key_auth/v3"
	headermutation "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/header_mutation/v3"
	headertometadata "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/header_to_metadata/v3"
	jwt "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/jwt_authn/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	configuration "github.com/rhobs/auth-gateway/pkg/config"
	"go.yaml.in/yaml/v3"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestAPIKeyClientIncludesMissingAttributesInNameOrder(t *testing.T) {
	c := loadConfigCase(t, "api-key-auth")
	authenticator := c.Authenticators[1]
	file, err := GenerateAPIKeyECDS(authenticator, []gatewayapi.APIKeyCredential{{
		Key: "key-a", Attributes: map[string]string{"writer_id": "writer-a"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	credentials := decodeAPIKeySecret(t, file).Credentials
	if len(credentials) != 1 || credentials[0].Client != "tenant_id=;writer_id=writer-a" {
		t.Fatalf("client with a missing attribute = %#v", credentials)
	}
}

func TestAPIKeyHeaderAttributesStayOutOfCredentialIdentity(t *testing.T) {
	c := loadConfigCase(t, "api-key-auth")
	authenticator := c.Authenticators[1]
	authenticator.Attributes["requested_tenant"] = gatewayapi.AttributeSource{Header: new("X-Tenant")}
	credential := []gatewayapi.APIKeyCredential{{Key: "key-a", Attributes: map[string]string{"tenant_id": "client-a"}}}
	file, err := GenerateAPIKeyECDS(authenticator, credential)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := decodeAPIKeySecret(t, file).Credentials[0].Client, "tenant_id=client-a;writer_id="; got != want {
		t.Fatalf("credential identity = %q, want %q", got, want)
	}
	credential[0].Attributes["requested_tenant"] = "client-a"
	if _, err := GenerateAPIKeyECDS(authenticator, credential); err == nil || !strings.Contains(err.Error(), "undeclared attribute") {
		t.Fatalf("header attribute in credentials was accepted: %v", err)
	}

	authenticator.Attributes = map[string]gatewayapi.AttributeSource{"requested_tenant": {Header: new("X-Tenant")}}
	file, err = GenerateAPIKeyECDS(authenticator, []gatewayapi.APIKeyCredential{{Key: "key-a"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := decodeAPIKeySecret(t, file).Credentials[0].Client; got != apiKeyClientNoAttributes {
		t.Fatalf("header-only credential identity = %q", got)
	}
}

func decodeAPIKeySecret(t *testing.T, data []byte) *apikey.ApiKeyAuth {
	t.Helper()
	var document map[string]any
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	resources, ok := document["resources"].([]any)
	if !ok || len(resources) != 1 {
		t.Fatalf("ECDS resources = %#v", document["resources"])
	}
	encoded, err := json.Marshal(resources[0])
	if err != nil {
		t.Fatal(err)
	}
	var resource anypb.Any
	if err := protojson.Unmarshal(encoded, &resource); err != nil {
		t.Fatal(err)
	}
	var extension core.TypedExtensionConfig
	if err := resource.UnmarshalTo(&extension); err != nil {
		t.Fatal(err)
	}
	if extension.Name != apiKeyFilterName {
		t.Fatalf("ECDS resource name = %q", extension.Name)
	}
	var wrapped matching.ExtensionWithMatcher
	if err := extension.TypedConfig.UnmarshalTo(&wrapped); err != nil {
		t.Fatal(err)
	}
	if wrapped.ExtensionConfig == nil || wrapped.ExtensionConfig.Name != apiKeyFilterName {
		t.Fatalf("wrapped API-key config = %#v", wrapped.ExtensionConfig)
	}
	var native apikey.ApiKeyAuth
	if err := wrapped.ExtensionConfig.TypedConfig.UnmarshalTo(&native); err != nil {
		t.Fatal(err)
	}
	return &native
}

func TestAPIKeyPipelineUsesFileECDSAndHostScopedFilters(t *testing.T) {
	c := loadConfigCase(t, "api-key-auth")
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	manager := firstHTTPManager(t, files.EnvoyBootstrap.Contents)
	wantOrder := []string{
		configuration.JwtAuthnFilterName, apiKeyFilterName, headerToMetadataFilterName, authenticationFilterName,
		attributeInitializationFilterName(1), attributeInitializationFilterName(2),
		authorizationFilterName, requiredHeaderFilterName, credentialCleanupFilterName,
		headerMutationFilterName, routerFilterName,
	}
	got := httpFilterNames(manager)
	start := slices.Index(got, configuration.JwtAuthnFilterName)
	if start < 0 {
		t.Fatal("JWT authentication filter is missing")
	}
	if !slices.Equal(got[start:], wantOrder) {
		t.Fatalf("HTTP authentication filter order = %v, want %v", got[start:], wantOrder)
	}
	keyFilter := apiKeyHTTPFilter(t, manager, apiKeyFilterName)
	discovery := keyFilter.GetConfigDiscovery()
	if !keyFilter.Disabled || discovery == nil || keyFilter.GetTypedConfig() != nil ||
		discovery.GetConfigSource().GetPathConfigSource().GetPath() != configuration.APIKeyECDSPath ||
		discovery.GetConfigSource().GetPathConfigSource().GetWatchedDirectory().GetPath() != configuration.APIKeyConfigDirectory ||
		!slices.Equal(discovery.GetTypeUrls(), []string{"envoy.extensions.common.matching.v3.ExtensionWithMatcher"}) {
		t.Fatalf("API-key ECDS filter = %#v", keyFilter)
	}
	metadataFilter := apiKeyHTTPFilter(t, manager, headerToMetadataFilterName)
	var metadata headertometadata.Config
	if err := metadataFilter.GetTypedConfig().UnmarshalTo(&metadata); err != nil {
		t.Fatal(err)
	}
	rules := metadata.GetRequestRules()
	if len(rules) != 3 || rules[0].Header != configuration.ApiKeyClientHeader || rules[0].Remove ||
		rules[0].GetOnHeaderPresent().GetMetadataNamespace() != configuration.ApiKeyMetadataNamespace ||
		rules[0].GetOnHeaderPresent().GetKey() != configuration.ApiKeyMetadataKey ||
		rules[0].GetOnHeaderPresent().GetValue() != "verified" ||
		rules[0].GetOnHeaderPresent().GetType() != headertometadata.Config_STRING ||
		rules[0].GetOnHeaderPresent().GetEncode() != headertometadata.Config_NONE {
		t.Fatalf("API-key identity extraction = %#v", rules)
	}
	for index, attribute := range []string{"tenant_id", "writer_id"} {
		rule := rules[index+1]
		value := rule.GetOnHeaderPresent()
		if rule.Header != configuration.ApiKeyClientHeader || rule.Remove != (index == 1) ||
			value.GetMetadataNamespace() != configuration.ApiKeyMetadataNamespace ||
			value.GetKey() != configuration.ApiKeyAttributeMetadataKey(attribute) ||
			value.GetRegexValueRewrite().GetPattern().GetRegex() != `^(?:(?:[^;]*;)*`+attribute+`=([^;]*)(?:;[^;]*)*|.*)$` ||
			value.GetRegexValueRewrite().GetSubstitution() != `\1` {
			t.Fatalf("API-key attribute %q extraction = %#v", attribute, rule)
		}
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
	for _, name := range []string{"authorization", "x-partner-key", configuration.ApiKeyClientHeader, jwtVerifiedHeaderName("issuer-one")} {
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
	if keyRoute.XdsMatcher != nil || hosts[1].TypedPerFilterConfig[configuration.JwtAuthnFilterName] != nil {
		t.Fatalf("key-only host has unexpected JWT or skip rules: %#v", hosts[1].TypedPerFilterConfig)
	}
	mixedRoute := apiKeyPerHostMatcher(t, hosts[2])
	matchers := mixedRoute.GetXdsMatcher().GetMatcherList().GetMatchers()
	if len(matchers) != 1 || matchers[0].GetPredicate().GetSinglePredicate().GetInput().GetName() != "envoy.matching.inputs.request_headers" {
		t.Fatalf("JWT-first API-key skip matcher = %#v", mixedRoute.GetXdsMatcher())
	}
	var marker jwt.JwtAuthentication
	if err := apiKeyHTTPFilter(t, manager, configuration.JwtAuthnFilterName).GetTypedConfig().UnmarshalTo(&marker); err != nil {
		t.Fatal(err)
	}
	if marker.RequirementMap[serverJWTRequirementName(2)].GetAllowMissingOrFailed() == nil ||
		len(marker.Providers["issuer-one"].ClaimToHeaders) != 1 ||
		marker.Providers["issuer-one"].ClaimToHeaders[0].HeaderName != jwtVerifiedHeaderName("issuer-one") {
		t.Fatalf("mixed any_of JWT marker and requirement = %#v", &marker)
	}
	bootstrap := decodeBootstrap(t, files.EnvoyBootstrap.Contents)
	tlsManager := decodeHTTPManager(t, bootstrap.StaticResources.Listeners[0].FilterChains[1])
	var strict jwt.JwtAuthentication
	if err := apiKeyHTTPFilter(t, tlsManager, configuration.JwtAuthnFilterName).GetTypedConfig().UnmarshalTo(&strict); err != nil {
		t.Fatal(err)
	}
	if strict.RequirementMap[serverJWTRequirementName(3)].GetProviderName() != "issuer-one" ||
		apiKeyPerHostMatcher(t, tlsManager.GetRouteConfig().GetVirtualHosts()[0]).XdsMatcher != nil {
		t.Fatal("all_of server did not require JWT and API key without a skip matcher")
	}
}

func TestPublicOnlyChainRemovesConfiguredCredentials(t *testing.T) {
	c := loadConfigCase(t, "api-key-auth")
	c.Servers = []gatewayapi.Server{c.Servers[0], c.Servers[3]}
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := decodeBootstrap(t, files.EnvoyBootstrap.Contents)
	manager := decodeHTTPManager(t, bootstrap.StaticResources.Listeners[0].FilterChains[0])
	if got, want := httpFilterNames(manager), []string{requestControlsFilterName, credentialCleanupFilterName, routerFilterName}; !slices.Equal(got, want) {
		t.Fatalf("public-only HTTP filter order = %v, want %v", got, want)
	}
}

func TestHeaderMetadataCapturePreservesRequestHeader(t *testing.T) {
	c := loadConfigCase(t, "api-key-auth")
	c.Authenticators[1].Attributes["requested_tenant"] = gatewayapi.AttributeSource{Header: new("x-TENANT")}
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	manager := firstHTTPManager(t, files.EnvoyBootstrap.Contents)
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

func TestAPIKeyCredentialAttributeByteLimit(t *testing.T) {
	c := loadConfigCase(t, "api-key-auth")
	for _, test := range []struct {
		name  string
		value string
		valid bool
	}{
		{name: "maximum bytes", value: strings.Repeat("v", 8191), valid: true},
		{name: "too many bytes", value: strings.Repeat("v", 8192)},
		{name: "UTF-8 byte count", value: strings.Repeat("\u00e9", 4096)},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := GenerateAPIKeyECDS(c.Authenticators[1], []gatewayapi.APIKeyCredential{{Key: "key", Attributes: map[string]string{"tenant_id": test.value}}})
			if test.valid {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "credentials[0].attributes.tenant_id must be at most 8191 bytes") {
				t.Fatalf("credential validation = %v, want the attribute byte limit", err)
			}
		})
	}
}

func TestAPIKeyAttributeGenerationIsDeterministic(t *testing.T) {
	c := apiKeyAttributesConfig(t, 20)
	values := make(map[string]string)
	for index := range 20 {
		values[fmt.Sprintf("attribute%02d", index)] = fmt.Sprintf("value%02d", index)
	}
	first, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	firstECDS, err := GenerateAPIKeyECDS(c.Authenticators[0], []gatewayapi.APIKeyCredential{{Key: "key", Attributes: values}})
	if err != nil {
		t.Fatal(err)
	}
	sources := c.Authenticators[0].Attributes
	c.Authenticators[0].Attributes = map[string]gatewayapi.AttributeSource{"requested_tenant": sources["requested_tenant"]}
	reversedValues := make(map[string]string)
	for index := 19; index >= 0; index-- {
		name := fmt.Sprintf("attribute%02d", index)
		c.Authenticators[0].Attributes[name] = sources[name]
		reversedValues[name] = values[name]
	}
	second, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	assertGeneratedFilesEqual(t, first, second)
	secondECDS, err := GenerateAPIKeyECDS(c.Authenticators[0], []gatewayapi.APIKeyCredential{{Key: "key", Attributes: reversedValues}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstECDS, secondECDS) {
		t.Fatal("credential attribute insertion order changed the ECDS resource")
	}
}

func apiKeyAttributesConfig(t *testing.T, count int) gatewayapi.Config {
	t.Helper()
	const filename = "testdata/api-key-attributes.yaml"
	c := loadTestConfig(t, readTestFile(t, filename), filename)
	for index := count; index < 20; index++ {
		delete(c.Authenticators[0].Attributes, fmt.Sprintf("attribute%02d", index))
	}
	if count == 0 {
		c.APIs[0].Routes[0].Processing = nil
	} else {
		c.APIs[0].Routes[0].Processing.RequestHeaders = c.APIs[0].Routes[0].Processing.RequestHeaders[:count]
	}
	return c
}

func TestHTTPManagerPreservesServerHostPairing(t *testing.T) {
	c := resolveTestConfig(t, loadConfigCase(t, "api-key-auth"))
	publicHost := &route.VirtualHost{Name: "unmatched.public.gateway.test"}
	keyHost := &route.VirtualHost{
		Name: "key.gateway.test",
		TypedPerFilterConfig: map[string]*anypb.Any{
			authorizationFilterName: &anypb.Any{},
		},
	}

	if _, err := toHTTPManager(c, []indexedVirtualHost{
		{serverIndex: 0, host: publicHost},
		{serverIndex: 1, host: keyHost},
	}); err != nil {
		t.Fatal(err)
	}
	if publicHost.TypedPerFilterConfig != nil {
		t.Fatalf("unmatched public host received per-filter config: %#v", publicHost.TypedPerFilterConfig)
	}
	if keyHost.TypedPerFilterConfig[attributeInitializationFilterName(1)] == nil {
		t.Fatal("API-key attribute initialization was not attached to its server host")
	}
}

func TestAPIKeyAttributeFilterInitializesMissingHostConfigMap(t *testing.T) {
	c := resolveTestConfig(t, loadConfigCase(t, "api-key-auth"))
	host := &route.VirtualHost{Name: "key.gateway.test"}
	if _, err := apiKeyAttributeFilters(c, nil, []indexedVirtualHost{{serverIndex: 1, host: host}}); err != nil {
		t.Fatal(err)
	}
	if host.TypedPerFilterConfig[attributeInitializationFilterName(1)] == nil {
		t.Fatal("API-key attribute initialization was not added to the host")
	}
}

func metadataMatcherPath(segments []*matcher.MetadataMatcher_PathSegment) []string {
	keys := make([]string, 0, len(segments))
	for _, segment := range segments {
		keys = append(keys, segment.GetKey())
	}
	return keys
}

func TestAPIKeyAttributeExtractionPreservesCredentialValues(t *testing.T) {
	authenticator := gatewayapi.Authenticator{
		Name: "partner-key", APIKey: &gatewayapi.APIKeyAuthenticator{},
		Attributes: map[string]gatewayapi.AttributeSource{
			"a":                     {Credential: new(true)},
			"attribute0":            {Credential: new(true)},
			"attribute00":           {Credential: new(true)},
			"hyphen-name":           {Credential: new(true)},
			"missing":               {Credential: new(true)},
			"under_score":           {Credential: new(true)},
			strings.Repeat("z", 64): {Credential: new(true)},
		},
	}
	values := map[string]string{
		"a":                     "attribute0=not-a-binding",
		"attribute0":            `equals=percent%3B+slash/quote"backslash\`,
		"attribute00":           "prefix names stay separate",
		"hyphen-name":           `literal\1$1`,
		"under_score":           "caf\u00e9",
		strings.Repeat("z", 64): "last-value",
	}
	data, err := GenerateAPIKeyECDS(authenticator, []gatewayapi.APIKeyCredential{{Key: "key", Attributes: values}})
	if err != nil {
		t.Fatal(err)
	}
	identity := decodeAPIKeySecret(t, data).Credentials[0].Client
	filter, err := requestMetadataFilter(authenticator, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	var metadata headertometadata.Config
	if err := filter.GetTypedConfig().UnmarshalTo(&metadata); err != nil {
		t.Fatal(err)
	}
	for _, rule := range metadata.RequestRules[1:] {
		attribute := strings.TrimPrefix(rule.OnHeaderPresent.Key, "attribute.")
		rewrite := rule.OnHeaderPresent.RegexValueRewrite
		pattern, err := regexp.Compile(rewrite.Pattern.Regex)
		if err != nil {
			t.Fatal(err)
		}
		matches := pattern.FindStringSubmatch(identity)
		if len(matches) != 2 || matches[1] != values[attribute] {
			t.Errorf("attribute %s: extraction = %q, want %q", attribute, matches, values[attribute])
		}
		for _, withoutAttribute := range []string{"api-key", "other=value", "other=" + attribute + "=not-a-binding"} {
			matches := pattern.FindStringSubmatch(withoutAttribute)
			if len(matches) != 2 || matches[1] != "" {
				t.Errorf("attribute %s: extraction from %q = %q, want an empty value", attribute, withoutAttribute, matches)
			}
		}
		if rule.OnHeaderMissing != nil {
			t.Errorf("attribute %s supplies a value without a verified identity", attribute)
		}
	}
}
