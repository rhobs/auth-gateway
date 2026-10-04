package config

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	matching "github.com/envoyproxy/go-control-plane/envoy/extensions/common/matching/v3"
	apikey "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/api_key_auth/v3"
	"go.yaml.in/yaml/v3"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
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
	config := decodeAPIKeySecret(t, secret.Data[apiKeySecretFilename])
	if len(config.Credentials) != 2 || config.Credentials[0].Key != "key-a" || config.Credentials[1].Key != "key-b" {
		t.Fatalf("sorted credentials = %#v", config.Credentials)
	}
	if len(config.KeySources) != 1 || config.KeySources[0].Header != "x-partner-key" || config.Forwarding == nil ||
		config.Forwarding.Header != apiKeyClientHeader || !config.Forwarding.HideCredentials {
		t.Fatalf("API-key input and forwarding = %#v", config)
	}
	client, err := base64.StdEncoding.DecodeString(config.Credentials[0].Client)
	if err != nil {
		t.Fatal(err)
	}
	var identity structpb.Value
	if err := proto.Unmarshal(client, &identity); err != nil {
		t.Fatal(err)
	}
	fields := identity.GetStructValue().Fields
	if fields["authenticator"].GetStringValue() != "partner-key" ||
		fields["attributes"].GetStructValue().Fields["tenant_id"].GetStringValue() != "client-a" ||
		fields["attributes"].GetStructValue().Fields["writer_id"].GetStringValue() != "writer-a" {
		t.Fatalf("decoded credential identity = %#v", fields)
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
      attributes: [tenant_id]
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
		len(key.Attributes) != 1 || key.Attributes[0] != "tenant_id" {
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
		edit func(*Config)
	}{
		{name: "missing Secret name", want: "authenticators[1].api_key.secret", edit: func(c *Config) { c.Authenticators[1].APIKey.Secret = "" }},
		{name: "invalid Secret name", want: "authenticators[1].api_key.secret", edit: func(c *Config) { c.Authenticators[1].APIKey.Secret = "Bad_Name" }},
		{name: "reserved header", want: "authenticators[1].api_key.header", edit: func(c *Config) { c.Authenticators[1].APIKey.Header = "Authorization" }},
		{name: "internal header", want: "authenticators[1].api_key.header", edit: func(c *Config) { c.Authenticators[1].APIKey.Header = "X-Auth-Gateway-Identity" }},
		{name: "underscore header", want: "authenticators[1].api_key.header", edit: func(c *Config) { c.Authenticators[1].APIKey.Header = "X_Partner_Key" }},
		{name: "duplicate attribute", want: "authenticators[1].api_key.attributes contains duplicate", edit: func(c *Config) {
			c.Authenticators[1].APIKey.Attributes = []string{"tenant_id", "tenant_id"}
		}},
		{name: "invalid attribute", want: "authenticators[1].api_key.attributes", edit: func(c *Config) {
			c.Authenticators[1].APIKey.Attributes[0] = "Tenant.ID"
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
	attributes := slices.Clone(c.Authenticators[1].APIKey.Attributes)
	if _, err := GenerateKubernetes(c); err != nil {
		t.Fatal(err)
	}
	if c.Authenticators[1].APIKey.Header != "" || !slices.Equal(c.Authenticators[1].APIKey.Attributes, attributes) {
		t.Fatalf("generation mutated the API-key authenticator: %#v", c.Authenticators[1].APIKey)
	}
}
