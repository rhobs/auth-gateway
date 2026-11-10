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

	apikey "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/api_key_auth/v3"

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
	setTestAttribute(&authenticator, testTextAttribute("requested_tenant", "header", "X-Tenant"))
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

	authenticator.Attributes = []gatewayapi.AttributeSource{testTextAttribute("requested_tenant", "header", "X-Tenant")}
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
	var native apikey.ApiKeyAuth
	if err := extension.TypedConfig.UnmarshalTo(&native); err != nil {
		t.Fatal(err)
	}
	return &native
}

func TestPublicOnlyChainRemovesConfiguredCredentials(t *testing.T) {
	c := loadConfigCase(t, "api-key-auth")
	c.Servers = []gatewayapi.Server{c.Servers[0]}
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := decodeBootstrap(t, files.EnvoyBootstrap.Contents)
	manager := decodeHTTPManager(t, bootstrap.StaticResources.Listeners[0].FilterChains[0])
	if got, want := httpFilterNames(manager), []string{credentialConflictFilterName, requestControlsFilterName, credentialCleanupFilterName, routerFilterName}; !slices.Equal(got, want) {
		t.Fatalf("public-only HTTP filter order = %v, want %v", got, want)
	}
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
	c.Authenticators[0].Attributes = []gatewayapi.AttributeSource{*testAttribute(&gatewayapi.Authenticator{Attributes: sources}, "requested_tenant")}
	reversedValues := make(map[string]string)
	for index := 19; index >= 0; index-- {
		name := fmt.Sprintf("attribute%02d", index)
		setTestAttribute(&c.Authenticators[0], *testAttribute(&gatewayapi.Authenticator{Attributes: sources}, name))
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
		removeTestAttribute(&c.Authenticators[0], fmt.Sprintf("attribute%02d", index))
	}
	if count == 0 {
		c.APIs[0].Routes[0].Processing = nil
	} else {
		c.APIs[0].Routes[0].Processing.RequestHeaders = c.APIs[0].Routes[0].Processing.RequestHeaders[:count]
	}
	return c
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
  attributes:
    - name: tenant_id
      from_source: credential
      value: tenant_id
apis:
- name: ingest
  upstream:
    address: httpbin
    port: 8080
  routes:
  - methods:
    - POST
    path:
      exact: "/ingest"
servers:
- hostname: key.local.test
  apis:
  - name: ingest
    access:
    - name: writers
      authentication:
        api_key: {authenticator: local-key}
      authorization:
        grants:
        - authenticator: local-key
          attributes:
            - name: tenant_id
              expression: equals
              value: client-a
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
	file, err := GenerateAPIKeyECDS(c.Authenticators[0], []gatewayapi.APIKeyCredential{{Key: "example-key", Attributes: map[string]string{"tenant_id": "client-a"}}})
	if err != nil {
		t.Fatalf("generate API-key ECDS file: %v", err)
	}
	if credentials := decodeAPIKeySecret(t, file).Credentials; len(credentials) != 1 || credentials[0].Client != "tenant_id=client-a" {
		t.Fatalf("file-based API-key credential = %#v", credentials)
	}
	if _, err := APIKeySecret("gateway-test", c.Authenticators[0], nil); err == nil || !strings.Contains(err.Error(), "authenticator.api_key.secret") {
		t.Fatalf("Secret without a configured name: %v", err)
	}
}

func TestAPIKeyDefaultsDoNotMutateInput(t *testing.T) {
	c := loadConfigCase(t, "api-key-auth")
	c.Authenticators[1].APIKey.Header = ""
	c.Servers[2].APIs[0].Access[1].Match.Headers[0].Name = defaultAPIKeyHeader
	attributes := credentialAttributeNamesAuthenticator(c.Authenticators[1])
	if _, err := GenerateKubernetes(c); err != nil {
		t.Fatal(err)
	}
	if c.Authenticators[1].APIKey.Header != "" || !slices.Equal(credentialAttributeNamesAuthenticator(c.Authenticators[1]), attributes) {
		t.Fatalf("generation mutated the API-key authenticator: %#v", c.Authenticators[1].APIKey)
	}
}

func TestAPIKeyRouteForwardsVerifiedClientMetadata(t *testing.T) {
	c := loadConfigCase(t, "access-control")
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	manager := firstHTTPManager(t, files.EnvoyBootstrap.Contents)
	selected := namedRoute(manager.GetRouteConfig().GetVirtualHosts()[0].Routes, "api-0-write-route-0-method-0-access-1-match-0")
	var wrapper route.FilterConfig
	if err := selected.TypedPerFilterConfig[apiKeyFilterName].UnmarshalTo(&wrapper); err != nil {
		t.Fatal(err)
	}
	var config apikey.ApiKeyAuthPerRoute
	if err := wrapper.Config.UnmarshalTo(&config); err != nil {
		t.Fatal(err)
	}
	if config.GetForwarding().GetHeader() != "x-auth-gateway-api-key-client" || !config.GetForwarding().GetHideCredentials() {
		t.Fatalf("route must forward verified client metadata and hide the key: %v", &config)
	}
	if len(config.Credentials) != 0 || len(config.KeySources) != 0 {
		t.Fatal("route must use the reloadable ECDS credentials and configured source")
	}
}
