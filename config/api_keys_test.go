package config

import (
	"bytes"
	"encoding/json"
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
	"go.yaml.in/yaml/v3"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestAPIKeySecretContainsOneReloadableResource(t *testing.T) {
	c := loadConfigCase(t, "api-key-auth")
	credentials := []APIKeyCredential{
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
	reversed, err := APIKeySecret("gateway-test", c.Authenticators[1], []APIKeyCredential{credentials[1], credentials[0]})
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

func TestAPIKeyClientIncludesMissingAttributesInNameOrder(t *testing.T) {
	c := loadConfigCase(t, "api-key-auth")
	authenticator := c.Authenticators[1]
	file, err := GenerateAPIKeyECDS(authenticator, []APIKeyCredential{{
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
	authenticator.Attributes["requested_tenant"] = AttributeSource{Header: new("X-Tenant")}
	credential := []APIKeyCredential{{Key: "key-a", Attributes: map[string]string{"tenant_id": "client-a"}}}
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

	authenticator.Attributes = map[string]AttributeSource{"requested_tenant": {Header: new("X-Tenant")}}
	file, err = GenerateAPIKeyECDS(authenticator, []APIKeyCredential{{Key: "key-a"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := decodeAPIKeySecret(t, file).Credentials[0].Client; got != apiKeyClientNoAttributes {
		t.Fatalf("header-only credential identity = %q", got)
	}
}

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

func TestAPIKeySecretRejectsInvalidCredentials(t *testing.T) {
	c := loadConfigCase(t, "api-key-auth")
	tests := []struct {
		name        string
		namespace   string
		auth        Authenticator
		credentials []APIKeyCredential
		want        string
	}{
		{name: "bad namespace", namespace: "Bad", auth: c.Authenticators[1], want: "namespace"},
		{name: "empty key", namespace: "gateway-test", auth: c.Authenticators[1], credentials: []APIKeyCredential{{Key: ""}}, want: "credentials[0].key"},
		{name: "duplicate key", namespace: "gateway-test", auth: c.Authenticators[1], credentials: []APIKeyCredential{{Key: "same"}, {Key: "same"}}, want: "credentials[1].key"},
		{name: "undeclared attribute", namespace: "gateway-test", auth: c.Authenticators[1], credentials: []APIKeyCredential{{Key: "key", Attributes: map[string]string{"unknown": "value"}}}, want: "credentials[0].attributes"},
		{name: "unsafe attribute", namespace: "gateway-test", auth: c.Authenticators[1], credentials: []APIKeyCredential{{Key: "key", Attributes: map[string]string{"tenant_id": "bad\r\nvalue"}}}, want: "credentials[0].attributes.tenant_id"},
		{name: "reserved separator", namespace: "gateway-test", auth: c.Authenticators[1], credentials: []APIKeyCredential{{Key: "key", Attributes: map[string]string{"tenant_id": "client;other"}}}, want: "credentials[0].attributes.tenant_id"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := APIKeySecret(test.namespace, test.auth, test.credentials); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("APIKeySecret error = %v, want %q", err, test.want)
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
		!slices.Equal(c.Authenticators[0].credentialAttributeNames(), []string{"tenant_id"}) {
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
	file, err := GenerateAPIKeyECDS(c.Authenticators[0], []APIKeyCredential{{Key: "example-key"}})
	if err != nil {
		t.Fatalf("generate API-key ECDS file: %v", err)
	}
	if credentials := decodeAPIKeySecret(t, file).Credentials; len(credentials) != 1 || credentials[0].Client != apiKeyClientNoAttributes {
		t.Fatalf("API-key client without attributes = %#v", credentials)
	}
	if _, err := APIKeySecret("gateway-test", c.Authenticators[0], nil); err == nil || !strings.Contains(err.Error(), "authenticator.api_key.secret") {
		t.Fatalf("Secret without a configured name: %v", err)
	}
}

func TestValidateAPIKeyConfiguration(t *testing.T) {
	tests := []struct {
		name string
		want string
		edit func(*Config)
	}{
		{name: "missing Secret name", want: "authenticators[1].api_key.secret", edit: func(c *Config) { c.Authenticators[1].APIKey.Secret = "" }},
		{name: "invalid Secret name", want: "authenticators[1].api_key.secret", edit: func(c *Config) { c.Authenticators[1].APIKey.Secret = "Bad_Name" }},
		{name: "reserved header", want: "authenticators[1].api_key.header", edit: func(c *Config) { c.Authenticators[1].APIKey.Header = "Authorization" }},
		{name: "internal header", want: "authenticators[1].api_key.header", edit: func(c *Config) { c.Authenticators[1].APIKey.Header = "X-Auth-Gateway-Identity" }},
		{name: "underscore header", want: "authenticators[1].api_key.header", edit: func(c *Config) { c.Authenticators[1].APIKey.Header = "X_Partner_Key" }},
		{name: "invalid attribute", want: "authenticators[1].attributes", edit: func(c *Config) {
			source := c.Authenticators[1].Attributes["tenant_id"]
			delete(c.Authenticators[1].Attributes, "tenant_id")
			c.Authenticators[1].Attributes["Tenant.ID"] = source
		}},
		{name: "undeclared grant attribute", want: "authorization_policies[1].grants[0].attributes references", edit: func(c *Config) {
			c.AuthorizationPolicies[1].Grants[0].Attributes["undeclared"] = []string{"value"}
		}},
		{name: "credential header as route output", want: "apis[0].routes[0].processing.request_headers[0].name", edit: func(c *Config) {
			c.APIs[0].Routes[0].Processing.RequestHeaders[0].Name = "x-partner-key"
		}},
		{name: "second key authenticator", want: "only one API-key authenticator", edit: func(c *Config) {
			c.Authenticators = append(c.Authenticators, Authenticator{Name: "other-key", APIKey: &APIKeyAuthenticator{Secret: "other-keys"}})
		}},
		{name: "ambiguous authenticator type", want: "authenticators[0] must set exactly one", edit: func(c *Config) {
			c.Authenticators[0].APIKey = &APIKeyAuthenticator{Secret: "shared-keys"}
		}},
		{name: "two JWTs in all_of", want: "servers[3].authentication.all_of", edit: func(c *Config) {
			copy := *c.Authenticators[0].JWT
			copy.Issuer = "https://issuer-two.jwt.test"
			c.Authenticators = append(c.Authenticators, Authenticator{Name: "issuer-two", JWT: &copy})
			c.Servers[3].Authentication.AllOf = []string{"issuer-one", "issuer-two", "partner-key"}
		}},
		{name: "duplicate issuer on a shared permissive chain", want: "same issuer", edit: func(c *Config) {
			copy := *c.Authenticators[0].JWT
			c.Authenticators = append(c.Authenticators, Authenticator{Name: "issuer-two", JWT: &copy})
			c.Servers[1].Authentication.AnyOf = []string{"partner-key", "issuer-two"}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := loadConfigCase(t, "api-key-auth")
			test.edit(&c)
			if err := c.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestAPIKeyDefaultsDoNotMutateInput(t *testing.T) {
	c := loadConfigCase(t, "api-key-auth")
	c.Authenticators[1].APIKey.Header = ""
	attributes := c.Authenticators[1].credentialAttributeNames()
	if _, err := GenerateKubernetes(c); err != nil {
		t.Fatal(err)
	}
	if c.Authenticators[1].APIKey.Header != "" || !slices.Equal(c.Authenticators[1].credentialAttributeNames(), attributes) {
		t.Fatalf("generation mutated the API-key authenticator: %#v", c.Authenticators[1].APIKey)
	}
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
		attributeInitializationFilterName(1), attributeInitializationFilterName(2), attributeFilterName,
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
			value.GetRegexValueRewrite().GetPattern().GetRegex() != apiKeyClientPattern(c.Authenticators[1].credentialAttributeNames(), attribute) ||
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
	c.Servers = []Server{c.Servers[0], c.Servers[3]}
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
	c := loadAuthExample(t)
	c.Authenticators[2].Attributes["requested_tenant"] = AttributeSource{Header: new("x-TENANT")}
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

func metadataMatcherPath(segments []*matcher.MetadataMatcher_PathSegment) []string {
	keys := make([]string, 0, len(segments))
	for _, segment := range segments {
		keys = append(keys, segment.GetKey())
	}
	return keys
}
