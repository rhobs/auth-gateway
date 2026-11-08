package config

import (
	"slices"
	"strings"
	"testing"

	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
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
		!slices.Equal(CredentialAttributeNamesAuthenticator(c.Authenticators[0]), []string{"tenant_id"}) {
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
