package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
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
	"go.yaml.in/yaml/v3"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestLoadAPIKeyCredentials(t *testing.T) {
	credentials, err := LoadAPIKeyCredentials(strings.NewReader("credentials:\n  - key: example-key\n    attributes:\n      tenant_id: client-a\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(credentials) != 1 || credentials[0].Key != "example-key" || credentials[0].Attributes["tenant_id"] != "client-a" {
		t.Fatalf("credentials = %#v", credentials)
	}
	credentials, err = LoadAPIKeyCredentials(strings.NewReader("credentials: []\n"))
	if err != nil || len(credentials) != 0 {
		t.Fatalf("empty credentials = %#v, error = %v", credentials, err)
	}
	for _, test := range []struct {
		name string
		yaml string
		want string
	}{
		{name: "missing list", yaml: "{}\n", want: "must set credentials"},
		{name: "unknown field", yaml: "credentials:\n  - key: example-key\n    extra: value\n", want: "field extra not found"},
		{name: "multiple documents", yaml: "credentials: []\n---\ncredentials: []\n", want: "exactly one YAML document"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := LoadAPIKeyCredentials(strings.NewReader(test.yaml)); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("LoadAPIKeyCredentials error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestLoadAPIKeyAuthenticatorUsesDefaultHeader(t *testing.T) {
	input := `version: 1
authenticators:
  - name: partner-key
    api_key:
      secret: shared-keys
    attributes:
      tenant_id: {credential: true}
apis:
  - name: ingest
    upstream:
      address: httpbin
      port: 8080
    routes:
      - methods: [POST]
        path:
          exact: /ingest
servers:
  - hostname: key.gateway.test
    authentication:
      any_of: [partner-key]
    apis: [ingest]
`
	c, err := Load(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if key := c.Authenticators[0].APIKey; key == nil || key.Secret != "shared-keys" || key.Header != "X-API-Key" ||
		!slices.Equal(credentialAttributeNamesAuthenticator(c.Authenticators[0]), []string{"tenant_id"}) {
		t.Fatalf("loaded API-key authenticator = %#v", key)
	}
	unknownField := `version: 1
authenticators:
  - name: partner-key
    api_key:
      secret: shared-keys
      credentials: []
`
	if _, err := Load(strings.NewReader(unknownField)); err == nil || !strings.Contains(err.Error(), "field credentials not found") {
		t.Fatalf("inline credentials were accepted: %v", err)
	}
}

func TestValidateAPIKeyConfiguration(t *testing.T) {
	tests := []struct {
		name string
		want string
		edit func(*gatewayapi.Config)
	}{
		{name: "missing Secret name", want: "authenticators[1].api_key.secret", edit: func(c *gatewayapi.Config) { c.Authenticators[1].APIKey.Secret = "" }},
		{name: "invalid Secret name", want: "authenticators[1].api_key.secret", edit: func(c *gatewayapi.Config) { c.Authenticators[1].APIKey.Secret = "Bad_Name" }},
		{name: "reserved header", want: "authenticators[1].api_key.header", edit: func(c *gatewayapi.Config) { c.Authenticators[1].APIKey.Header = "Authorization" }},
		{name: "internal header", want: "authenticators[1].api_key.header", edit: func(c *gatewayapi.Config) { c.Authenticators[1].APIKey.Header = "X-Auth-Gateway-Identity" }},
		{name: "underscore header", want: "authenticators[1].api_key.header", edit: func(c *gatewayapi.Config) { c.Authenticators[1].APIKey.Header = "X_Partner_Key" }},
		{name: "invalid attribute", want: "authenticators[1].attributes", edit: func(c *gatewayapi.Config) {
			source := c.Authenticators[1].Attributes["tenant_id"]
			delete(c.Authenticators[1].Attributes, "tenant_id")
			c.Authenticators[1].Attributes["Tenant.ID"] = source
		}},
		{name: "undeclared grant attribute", want: "authorization_policies[1].grants[0].attributes references", edit: func(c *gatewayapi.Config) {
			c.AuthorizationPolicies[1].Grants[0].Attributes["undeclared"] = []string{"value"}
		}},
		{name: "credential header as route output", want: "apis[0].routes[0].processing.request_headers[0].name", edit: func(c *gatewayapi.Config) {
			c.APIs[0].Routes[0].Processing.RequestHeaders[0].Name = "x-partner-key"
		}},
		{name: "second key authenticator", want: "only one API-key authenticator", edit: func(c *gatewayapi.Config) {
			c.Authenticators = append(c.Authenticators, gatewayapi.Authenticator{Name: "other-key", APIKey: &gatewayapi.APIKeyAuthenticator{Secret: "other-keys"}})
		}},
		{name: "ambiguous authenticator type", want: "authenticators[0] must set exactly one", edit: func(c *gatewayapi.Config) {
			c.Authenticators[0].APIKey = &gatewayapi.APIKeyAuthenticator{Secret: "shared-keys"}
		}},
		{name: "two JWTs in all_of", want: "servers[3].authentication.all_of", edit: func(c *gatewayapi.Config) {
			copy := *c.Authenticators[0].JWT
			copy.Issuer = "https://issuer-two.jwt.test"
			c.Authenticators = append(c.Authenticators, gatewayapi.Authenticator{Name: "issuer-two", JWT: &copy})
			c.Servers[3].Authentication.AllOf = []string{"issuer-one", "issuer-two", "partner-key"}
		}},
		{name: "duplicate issuer on a shared permissive chain", want: "same issuer", edit: func(c *gatewayapi.Config) {
			copy := *c.Authenticators[0].JWT
			c.Authenticators = append(c.Authenticators, gatewayapi.Authenticator{Name: "issuer-two", JWT: &copy})
			c.Servers[1].Authentication.AnyOf = []string{"partner-key", "issuer-two"}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := loadConfigCase(t, "api-key-auth")
			test.edit(&c)
			if err := Validate(c); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate error = %v, want %q", err, test.want)
			}
		})
	}
}

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
		jwtAuthnFilterName, apiKeyFilterName, headerToMetadataFilterName, authenticationFilterName,
		attributeInitializationFilterName(1), attributeInitializationFilterName(2),
		authorizationFilterName, requiredHeaderFilterName, credentialCleanupFilterName,
		headerMutationFilterName, routerFilterName,
	}
	got := httpFilterNames(manager)
	start := slices.Index(got, jwtAuthnFilterName)
	if start < 0 {
		t.Fatal("JWT authentication filter is missing")
	}
	if !slices.Equal(got[start:], wantOrder) {
		t.Fatalf("HTTP authentication filter order = %v, want %v", got[start:], wantOrder)
	}
	keyFilter := apiKeyHTTPFilter(t, manager, apiKeyFilterName)
	discovery := keyFilter.GetConfigDiscovery()
	if !keyFilter.Disabled || discovery == nil || keyFilter.GetTypedConfig() != nil ||
		discovery.GetConfigSource().GetPathConfigSource().GetPath() != APIKeyECDSPath ||
		discovery.GetConfigSource().GetPathConfigSource().GetWatchedDirectory().GetPath() != APIKeyConfigDirectory ||
		!slices.Equal(discovery.GetTypeUrls(), []string{"envoy.extensions.common.matching.v3.ExtensionWithMatcher"}) {
		t.Fatalf("API-key ECDS filter = %#v", keyFilter)
	}
	metadataFilter := apiKeyHTTPFilter(t, manager, headerToMetadataFilterName)
	var metadata headertometadata.Config
	if err := metadataFilter.GetTypedConfig().UnmarshalTo(&metadata); err != nil {
		t.Fatal(err)
	}
	rules := metadata.GetRequestRules()
	if len(rules) != 3 || rules[0].Header != apiKeyClientHeader || rules[0].Remove ||
		rules[0].GetOnHeaderPresent().GetMetadataNamespace() != apiKeyMetadataNamespace ||
		rules[0].GetOnHeaderPresent().GetKey() != apiKeyMetadataKey ||
		rules[0].GetOnHeaderPresent().GetValue() != "verified" ||
		rules[0].GetOnHeaderPresent().GetType() != headertometadata.Config_STRING ||
		rules[0].GetOnHeaderPresent().GetEncode() != headertometadata.Config_NONE {
		t.Fatalf("API-key identity extraction = %#v", rules)
	}
	for index, attribute := range []string{"tenant_id", "writer_id"} {
		rule := rules[index+1]
		value := rule.GetOnHeaderPresent()
		if rule.Header != apiKeyClientHeader || rule.Remove != (index == 1) ||
			value.GetMetadataNamespace() != apiKeyMetadataNamespace ||
			value.GetKey() != apiKeyAttributeMetadataKey(attribute) ||
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
	bootstrap := decodeBootstrap(t, files.EnvoyBootstrap.Contents)
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

	if _, err := httpManager(c, []indexedVirtualHost{
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

func metadataMatcherPath(segments []*matcher.MetadataMatcher_PathSegment) []string {
	keys := make([]string, 0, len(segments))
	for _, segment := range segments {
		keys = append(keys, segment.GetKey())
	}
	return keys
}

func TestAPIKeySecretContainsOneReloadableResource(t *testing.T) {
	c := loadConfigCase(t, "api-key-auth")
	credentials := []gatewayapi.APIKeyCredential{
		{Key: "key-b", Attributes: map[string]string{"tenant_id": "client-b", "writer_id": "writer-b"}},
		{Key: "key-a", Attributes: map[string]string{"tenant_id": "client-a", "writer_id": "writer-a"}},
	}
	secret, err := APIKeySecret("gateway-test", c.Authenticators[1], credentials)
	if err != nil {
		t.Fatal(err)
	}
	if secret.Name != "gateway-api-keys" || secret.Namespace != "gateway-test" || len(secret.Data) != 1 {
		t.Fatalf("Secret identity or data = %#v", secret)
	}
	file, err := GenerateAPIKeyECDS(c.Authenticators[1], credentials)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(file, secret.Data[apiKeySecretFilename]) {
		t.Fatal("file-based and Secret API-key resources differ")
	}
	config := decodeAPIKeySecret(t, secret.Data[apiKeySecretFilename])
	if len(config.Credentials) != 2 || config.Credentials[0].Key != "key-a" || config.Credentials[1].Key != "key-b" {
		t.Fatalf("sorted credentials = %#v", config.Credentials)
	}
	if len(config.KeySources) != 1 || config.KeySources[0].Header != "x-partner-key" || config.Forwarding == nil ||
		config.Forwarding.Header != apiKeyClientHeader || !config.Forwarding.HideCredentials {
		t.Fatalf("API-key input and forwarding = %#v", config)
	}
	if got, want := config.Credentials[0].Client, "tenant_id=client-a;writer_id=writer-a"; got != want {
		t.Fatalf("readable credential identity = %q, want %q", got, want)
	}
	reversed, err := APIKeySecret("gateway-test", c.Authenticators[1], []gatewayapi.APIKeyCredential{credentials[1], credentials[0]})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(secret.Data[apiKeySecretFilename], reversed.Data[apiKeySecretFilename]) {
		t.Fatal("credential input order changed the ECDS resource")
	}
	empty, err := APIKeySecret("gateway-test", c.Authenticators[1], nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(empty.Data[apiKeySecretFilename], []byte("credentials: []")) || len(decodeAPIKeySecret(t, empty.Data[apiKeySecretFilename]).Credentials) != 0 {
		t.Fatalf("empty key list did not emit a deny-all resource: %s", empty.Data[apiKeySecretFilename])
	}
}

func TestAPIKeySecretRejectsInvalidCredentials(t *testing.T) {
	c := loadConfigCase(t, "api-key-auth")
	tests := []struct {
		name        string
		namespace   string
		auth        gatewayapi.Authenticator
		credentials []gatewayapi.APIKeyCredential
		want        string
	}{
		{name: "bad namespace", namespace: "Bad", auth: c.Authenticators[1], want: "namespace"},
		{name: "empty key", namespace: "gateway-test", auth: c.Authenticators[1], credentials: []gatewayapi.APIKeyCredential{{Key: ""}}, want: "credentials[0].key"},
		{name: "duplicate key", namespace: "gateway-test", auth: c.Authenticators[1], credentials: []gatewayapi.APIKeyCredential{{Key: "same"}, {Key: "same"}}, want: "credentials[1].key"},
		{name: "undeclared attribute", namespace: "gateway-test", auth: c.Authenticators[1], credentials: []gatewayapi.APIKeyCredential{{Key: "key", Attributes: map[string]string{"unknown": "value"}}}, want: "credentials[0].attributes"},
		{name: "unsafe attribute", namespace: "gateway-test", auth: c.Authenticators[1], credentials: []gatewayapi.APIKeyCredential{{Key: "key", Attributes: map[string]string{"tenant_id": "bad\r\nvalue"}}}, want: "credentials[0].attributes.tenant_id"},
		{name: "reserved separator", namespace: "gateway-test", auth: c.Authenticators[1], credentials: []gatewayapi.APIKeyCredential{{Key: "key", Attributes: map[string]string{"tenant_id": "client;other"}}}, want: "credentials[0].attributes.tenant_id"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := APIKeySecret(test.namespace, test.auth, test.credentials); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("APIKeySecret error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestFileBasedAPIKeyDoesNotNeedKubernetesSecret(t *testing.T) {
	input := `version: 1
authenticators:
  - name: local-key
    api_key: {}
apis:
  - name: ingest
    upstream:
      address: httpbin
      port: 8080
    routes:
      - methods: [POST]
        path:
          exact: /ingest
servers:
  - hostname: key.gateway.test
    authentication:
      any_of: [local-key]
    apis: [ingest]
`
	c, err := Load(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if c.Kubernetes != nil || c.Authenticators[0].APIKey == nil || c.Authenticators[0].APIKey.Secret != "" {
		t.Fatalf("file-based API-key config = %#v", c.Authenticators[0])
	}
	if _, err := Generate(c); err != nil {
		t.Fatalf("generate Envoy files: %v", err)
	}
	file, err := GenerateAPIKeyECDS(c.Authenticators[0], []gatewayapi.APIKeyCredential{{Key: "example-key"}})
	if err != nil {
		t.Fatalf("generate API-key ECDS file: %v", err)
	}
	if credentials := decodeAPIKeySecret(t, file).Credentials; len(credentials) != 1 || credentials[0].Client != "api-key" {
		t.Fatalf("API-key client without attributes = %#v", credentials)
	}
	if _, err := APIKeySecret("gateway-test", c.Authenticators[0], nil); err == nil || !strings.Contains(err.Error(), "authenticator.api_key.secret") {
		t.Fatalf("Secret without a configured name: %v", err)
	}
}

func TestAPIKeyDefaultsDoNotMutateInput(t *testing.T) {
	c := loadConfigCase(t, "api-key-auth")
	c.Authenticators[1].APIKey.Header = ""
	attributes := credentialAttributeNamesAuthenticator(c.Authenticators[1])
	if _, err := GenerateKubernetes(c); err != nil {
		t.Fatal(err)
	}
	if c.Authenticators[1].APIKey.Header != "" || !slices.Equal(credentialAttributeNamesAuthenticator(c.Authenticators[1]), attributes) {
		t.Fatalf("generation mutated the API-key authenticator: %#v", c.Authenticators[1].APIKey)
	}
}
