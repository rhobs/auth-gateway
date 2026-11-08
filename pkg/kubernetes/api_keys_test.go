package kubernetes

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	matching "github.com/envoyproxy/go-control-plane/envoy/extensions/common/matching/v3"
	apikey "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/api_key_auth/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	configuration "github.com/rhobs/auth-gateway/pkg/config"
	envoyimpl "github.com/rhobs/auth-gateway/pkg/envoy"
	"go.yaml.in/yaml/v3"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"
)

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
	file, err := envoyimpl.GenerateAPIKeyECDS(c.Authenticators[1], credentials)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(file, secret.Data[configuration.ApiKeySecretFilename]) {
		t.Fatal("file-based and Secret API-key resources differ")
	}
	config := decodeAPIKeySecret(t, secret.Data[configuration.ApiKeySecretFilename])
	if len(config.Credentials) != 2 || config.Credentials[0].Key != "key-a" || config.Credentials[1].Key != "key-b" {
		t.Fatalf("sorted credentials = %#v", config.Credentials)
	}
	if len(config.KeySources) != 1 || config.KeySources[0].Header != "x-partner-key" || config.Forwarding == nil ||
		config.Forwarding.Header != configuration.ApiKeyClientHeader || !config.Forwarding.HideCredentials {
		t.Fatalf("API-key input and forwarding = %#v", config)
	}
	if got, want := config.Credentials[0].Client, "tenant_id=client-a;writer_id=writer-a"; got != want {
		t.Fatalf("readable credential identity = %q, want %q", got, want)
	}
	reversed, err := APIKeySecret("gateway-test", c.Authenticators[1], []gatewayapi.APIKeyCredential{credentials[1], credentials[0]})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(secret.Data[configuration.ApiKeySecretFilename], reversed.Data[configuration.ApiKeySecretFilename]) {
		t.Fatal("credential input order changed the ECDS resource")
	}
	empty, err := APIKeySecret("gateway-test", c.Authenticators[1], nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(empty.Data[configuration.ApiKeySecretFilename], []byte("credentials: []")) || len(decodeAPIKeySecret(t, empty.Data[configuration.ApiKeySecretFilename]).Credentials) != 0 {
		t.Fatalf("empty key list did not emit a deny-all resource: %s", empty.Data[configuration.ApiKeySecretFilename])
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
	if extension.Name != "envoy.filters.http.api_key_auth" {
		t.Fatalf("ECDS resource name = %q", extension.Name)
	}
	var wrapped matching.ExtensionWithMatcher
	if err := extension.TypedConfig.UnmarshalTo(&wrapped); err != nil {
		t.Fatal(err)
	}
	if wrapped.ExtensionConfig == nil || wrapped.ExtensionConfig.Name != "envoy.filters.http.api_key_auth" {
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
	c, err := configuration.Load(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if c.Kubernetes != nil || c.Authenticators[0].APIKey == nil || c.Authenticators[0].APIKey.Secret != "" {
		t.Fatalf("file-based API-key config = %#v", c.Authenticators[0])
	}
	if _, err := envoyimpl.Generate(c); err != nil {
		t.Fatalf("generate Envoy files: %v", err)
	}
	file, err := envoyimpl.GenerateAPIKeyECDS(c.Authenticators[0], []gatewayapi.APIKeyCredential{{Key: "example-key"}})
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
	attributes := configuration.CredentialAttributeNamesAuthenticator(c.Authenticators[1])
	if _, err := Generate(c); err != nil {
		t.Fatal(err)
	}
	if c.Authenticators[1].APIKey.Header != "" || !slices.Equal(configuration.CredentialAttributeNamesAuthenticator(c.Authenticators[1]), attributes) {
		t.Fatalf("generation mutated the API-key authenticator: %#v", c.Authenticators[1].APIKey)
	}
}
