package config

import (
	"slices"
	"strings"
	"testing"
)

func TestAuthExampleContainsExpectedAuthenticationConfiguration(t *testing.T) {
	c := loadAuthExample(t)
	if len(c.Authenticators) != 3 || len(c.AuthorizationPolicies) != 3 || len(c.Processing) != 1 {
		t.Fatalf("auth example counts = %d authenticators, %d policies, %d processors", len(c.Authenticators), len(c.AuthorizationPolicies), len(c.Processing))
	}
	if c.Processing[0].Type != "attribute-mapper" {
		t.Fatalf("processing type = %q", c.Processing[0].Type)
	}
	if got, want := c.Authenticators[0].Attributes["tenant_id"].ClaimPath, []string{"x", "y", "z", "claim"}; !slices.Equal(got, want) {
		t.Fatalf("tenant claim path = %v, want %v", got, want)
	}
	if source := c.Authenticators[0].Attributes["requested_tenant"]; source.Header == nil || *source.Header != "X-Tenant" {
		t.Fatalf("JWT header attribute = %#v", source)
	}
	if got, want := c.AuthorizationPolicies[0].Grants[0].Attributes["tenant_id"], []string{"client-123", "client-456"}; !slices.Equal(got, want) {
		t.Fatalf("authorization values = %v, want original claim values %v", got, want)
	}
	if got, want := c.AuthorizationPolicies[2].Grants[0].Attributes["requested_tenant"], []string{"client-123"}; !slices.Equal(got, want) {
		t.Fatalf("header grant values = %v, want %v", got, want)
	}
	if key := c.Authenticators[2].APIKey; key == nil || key.Secret != "auth-gateway-api-keys" || key.Header != "X-Partner-Key" ||
		!slices.Equal(c.Authenticators[2].credentialAttributeNames(), []string{"tenant_id", "writer_id"}) {
		t.Fatalf("example API-key authenticator = %#v", key)
	}
	if source := c.Authenticators[2].Attributes["requested_tenant"]; source.Header == nil || *source.Header != "X-Tenant" {
		t.Fatalf("API-key header attribute = %#v", source)
	}
	headers := c.APIs[0].Routes[0].Processing.RequestHeaders
	if len(headers) != 2 || headers[0].Name != "X-Scope-OrgID" || headers[1].Name != "X-Writer-ID" {
		t.Fatalf("request header mappings = %#v", headers)
	}
}

func TestValidateAcceptsLiteralClaimKeysAndSingleJWTAllOf(t *testing.T) {
	config := loadAuthExample(t)
	config.Authenticators[0].Attributes["tenant_id"] = AttributeSource{
		ClaimPath: []string{"organization", "customer.id"},
	}
	config.Servers[0].Authentication = &Authentication{AllOf: []string{"internal-jwt"}}
	config.Servers[0].Authorization = &Authorization{AllOf: []string{"metrics-writers", "logs-writers"}}
	if err := config.Validate(); err != nil {
		t.Fatalf("Validate rejected a literal claim key and valid all_of combinations: %v", err)
	}
}

func TestLoadRejectsFutureMTLSAuthenticatorSchema(t *testing.T) {
	input := `version: 1
authenticators:
  - name: client-certificate
    mtls: {}
servers:
  - hostname: write.example.com
    apis: [write]
apis:
  - name: write
    upstream:
      address: backend.example.com
      port: 8080
    routes:
      - methods: [POST]
        path:
          exact: /write
`
	if _, err := Load(strings.NewReader(input)); err == nil || !strings.Contains(err.Error(), "field mtls not found") {
		t.Fatalf("Load error = %v, want strict rejection of the future mTLS field", err)
	}
}

func TestValidateAuthenticatorAttributeSources(t *testing.T) {
	tests := []struct {
		name string
		want string
		edit func(*Config)
	}{
		{name: "JWT missing source", want: "authenticators[0].attributes.tenant_id", edit: func(c *Config) {
			c.Authenticators[0].Attributes["tenant_id"] = AttributeSource{}
		}},
		{name: "JWT multiple sources", want: "authenticators[0].attributes.tenant_id", edit: func(c *Config) {
			c.Authenticators[0].Attributes["tenant_id"] = AttributeSource{ClaimPath: []string{"sub"}, Header: new("X-Tenant")}
		}},
		{name: "JWT credential source", want: "authenticators[0].attributes.tenant_id", edit: func(c *Config) {
			c.Authenticators[0].Attributes["tenant_id"] = AttributeSource{Credential: new(true)}
		}},
		{name: "empty header", want: "authenticators[0].attributes.requested_tenant.header", edit: func(c *Config) {
			c.Authenticators[0].Attributes["requested_tenant"] = AttributeSource{Header: new("")}
		}},
		{name: "invalid header", want: "authenticators[0].attributes.requested_tenant.header", edit: func(c *Config) {
			c.Authenticators[0].Attributes["requested_tenant"] = AttributeSource{Header: new("Bad Header")}
		}},
		{name: "reserved header", want: "authenticators[0].attributes.requested_tenant.header", edit: func(c *Config) {
			c.Authenticators[0].Attributes["requested_tenant"] = AttributeSource{Header: new("Authorization")}
		}},
		{name: "internal header", want: "authenticators[0].attributes.requested_tenant.header", edit: func(c *Config) {
			c.Authenticators[0].Attributes["requested_tenant"] = AttributeSource{Header: new("X-Auth-Gateway-Identity")}
		}},
		{name: "underscore header", want: "authenticators[0].attributes.requested_tenant.header", edit: func(c *Config) {
			c.Authenticators[0].Attributes["requested_tenant"] = AttributeSource{Header: new("X_Tenant")}
		}},
		{name: "key credential header", want: "authenticators[0].attributes.requested_tenant.header is reserved", edit: func(c *Config) {
			c.Authenticators[0].Attributes["requested_tenant"] = AttributeSource{Header: new("x-partner-key")}
		}},
		{name: "key missing source", want: "authenticators[2].attributes.tenant_id", edit: func(c *Config) {
			c.Authenticators[2].Attributes["tenant_id"] = AttributeSource{}
		}},
		{name: "key false credential", want: "authenticators[2].attributes.tenant_id.credential", edit: func(c *Config) {
			c.Authenticators[2].Attributes["tenant_id"] = AttributeSource{Credential: new(false)}
		}},
		{name: "key claim source", want: "authenticators[2].attributes.tenant_id", edit: func(c *Config) {
			c.Authenticators[2].Attributes["tenant_id"] = AttributeSource{ClaimPath: []string{"sub"}}
		}},
		{name: "key multiple sources", want: "authenticators[2].attributes.tenant_id", edit: func(c *Config) {
			c.Authenticators[2].Attributes["tenant_id"] = AttributeSource{Credential: new(true), Header: new("X-Tenant")}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := loadAuthExample(t)
			test.edit(&c)
			if err := c.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validation error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestValidateAcceptsHeaderOnlyGrant(t *testing.T) {
	c := loadAuthExample(t)
	c.AuthorizationPolicies[0].Grants[0].Attributes = map[string][]string{"requested_tenant": {"client-123"}}
	c.AuthorizationPolicies[2].Grants[0].Attributes = map[string][]string{"requested_tenant": {"client-123"}}
	if err := c.Validate(); err != nil {
		t.Fatalf("header-only grants were rejected: %v", err)
	}
}

func TestValidateRejectsInvalidAuthenticationAndAuthorization(t *testing.T) {
	tests := []struct {
		name string
		want string
		edit func(*Config)
	}{
		{name: "duplicate authenticator", want: "duplicate authenticator name", edit: func(c *Config) { c.Authenticators[1].Name = c.Authenticators[0].Name }},
		{name: "missing authenticator type", want: "authenticators[0] must set exactly one of jwt or api_key", edit: func(c *Config) { c.Authenticators[0].JWT = nil }},
		{name: "missing issuer", want: "authenticators[0].jwt.issuer", edit: func(c *Config) { c.Authenticators[0].JWT.Issuer = "" }},
		{name: "non-HTTPS JWKS", want: "authenticators[0].jwt.jwks.uri", edit: func(c *Config) { c.Authenticators[0].JWT.JWKS.URI = "http://sso.example.com/jwks" }},
		{name: "JWKS user information", want: "authenticators[0].jwt.jwks.uri", edit: func(c *Config) { c.Authenticators[0].JWT.JWKS.URI = "https://user@sso.example.com/jwks" }},
		{name: "duplicate audience", want: "authenticators[0].jwt.audiences", edit: func(c *Config) { c.Authenticators[0].JWT.Audiences = []string{"same", "same"} }},
		{name: "empty claim path", want: "authenticators[0].attributes.tenant_id.claim_path", edit: func(c *Config) {
			c.Authenticators[0].Attributes["tenant_id"] = AttributeSource{ClaimPath: []string{""}}
		}},
		{name: "empty mapping output", want: "processing[0].attributes.tenant_id.mappings", edit: func(c *Config) { c.Processing[0].Attributes["tenant_id"].Mappings["client-123"] = "" }},
		{name: "unsafe mapping output", want: "processing[0].attributes.tenant_id.mappings", edit: func(c *Config) {
			c.Processing[0].Attributes["tenant_id"].Mappings["client-123"] = "team-a\r\nInjected: yes"
		}},
		{name: "duplicate processor name", want: "duplicate processing name", edit: func(c *Config) { c.Processing = append(c.Processing, c.Processing[0]) }},
		{name: "unsupported processor type", want: "processing[0].type", edit: func(c *Config) { c.Processing[0].Type = "unknown" }},
		{name: "invalid processor attribute", want: "processing[0].attributes.bad.name", edit: func(c *Config) {
			c.Processing[0].Attributes["bad.name"] = AttributeMappings{Mappings: map[string]string{"from": "to"}}
		}},
		{name: "empty mapping source", want: "processing[0].attributes.tenant_id.mappings", edit: func(c *Config) { c.Processing[0].Attributes["tenant_id"].Mappings[""] = "team-a" }},
		{name: "duplicate policy", want: "duplicate authorization policy name", edit: func(c *Config) { c.AuthorizationPolicies[1].Name = c.AuthorizationPolicies[0].Name }},
		{name: "unknown authentication method", want: "servers[0].authentication.any_of", edit: func(c *Config) { c.Servers[0].Authentication.AnyOf = []string{"missing"} }},
		{name: "duplicate authentication method", want: "servers[0].authentication.any_of", edit: func(c *Config) { c.Servers[0].Authentication.AnyOf = []string{"internal-jwt", "internal-jwt"} }},
		{name: "both authentication combinations", want: "servers[0].authentication must set exactly one", edit: func(c *Config) { c.Servers[0].Authentication.AllOf = []string{"internal-jwt"} }},
		{name: "empty authentication combination", want: "servers[0].authentication.any_of", edit: func(c *Config) { c.Servers[0].Authentication.AnyOf = []string{} }},
		{name: "multiple JWT methods in all_of", want: "servers[0].authentication.all_of", edit: func(c *Config) {
			c.Servers[0].Authentication = &Authentication{AllOf: []string{"internal-jwt", "external-jwt"}}
		}},
		{name: "unknown authorization policy", want: "servers[0].authorization.any_of", edit: func(c *Config) { c.Servers[0].Authorization.AnyOf = []string{"missing"} }},
		{name: "authorization without authentication", want: "servers[0].authorization requires authentication", edit: func(c *Config) { c.Servers[0].Authentication = nil }},
		{name: "unknown grant authenticator", want: "authorization_policies[0].grants[0].authenticator", edit: func(c *Config) { c.AuthorizationPolicies[0].Grants[0].Authenticator = "missing" }},
		{name: "empty grant APIs", want: "authorization_policies[0].grants[0].apis", edit: func(c *Config) { c.AuthorizationPolicies[0].Grants[0].APIs = nil }},
		{name: "unknown grant API", want: "authorization_policies[0].grants[0].apis", edit: func(c *Config) { c.AuthorizationPolicies[0].Grants[0].APIs = []string{"missing"} }},
		{name: "empty grant attribute values", want: "authorization_policies[0].grants[0].attributes.tenant_id", edit: func(c *Config) { c.AuthorizationPolicies[0].Grants[0].Attributes["tenant_id"] = nil }},
		{name: "grant attribute absent from authenticator", want: "authorization_policies[0].grants[0].attributes references", edit: func(c *Config) { c.AuthorizationPolicies[0].Grants[0].Attributes["missing"] = []string{"value"} }},
		{name: "authorization policy combination empty", want: "servers[0].authorization.any_of", edit: func(c *Config) { c.Servers[0].Authorization.AnyOf = []string{} }},
		{name: "invalid header field name", want: "apis[0].routes[0].processing.request_headers[0].name", edit: func(c *Config) { c.APIs[0].Routes[0].Processing.RequestHeaders[0].Name = "Bad Header" }},
		{name: "reserved credential header", want: "apis[0].routes[0].processing.request_headers[0].name", edit: func(c *Config) { c.APIs[0].Routes[0].Processing.RequestHeaders[0].Name = "Authorization" }},
		{name: "duplicate header field name", want: "apis[0].routes[0].processing.request_headers[1].name", edit: func(c *Config) { c.APIs[0].Routes[0].Processing.RequestHeaders[1].Name = "x-scope-orgid" }},
		{name: "empty processing source", want: "apis[0].routes[0].processing.request_headers[0].from_attribute", edit: func(c *Config) { c.APIs[0].Routes[0].Processing.RequestHeaders[0].FromAttribute = "" }},
		{name: "processing on public server", want: "servers[0] processing on API", edit: func(c *Config) { c.Servers[0].Authentication = nil; c.Servers[0].Authorization = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := loadAuthExample(t)
			test.edit(&config)
			if err := config.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validation error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestAnyOfMayOmitUnusedHeaderAttributes(t *testing.T) {
	config := loadAuthExample(t)
	delete(config.Authenticators[1].Attributes, "writer_id")
	if err := config.Validate(); err != nil {
		t.Fatalf("Validate rejected an any_of authenticator that omits a route attribute: %v", err)
	}

	delete(config.Authenticators[0].Attributes, "writer_id")
	if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "does not provide processing attribute") {
		t.Fatalf("Validate error = %v, want missing bound attribute error", err)
	}
}

func TestDuplicateJWTIssuersAreRejectedPerServer(t *testing.T) {
	config := loadAuthExample(t)
	config.Authenticators[1].JWT.Issuer = config.Authenticators[0].JWT.Issuer
	config.Authenticators[1].JWT.Audiences = []string{"another-audience"}
	if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "same issuer") {
		t.Fatalf("Validate error = %v, want duplicate issuer binding error", err)
	}

	config = loadAuthExample(t)
	config.Authenticators[1].JWT.Issuer = config.Authenticators[0].JWT.Issuer
	config.Servers = config.Servers[:2]
	config.Servers[0].Authentication = &Authentication{AnyOf: []string{"internal-jwt"}}
	config.Servers[1].Authentication = &Authentication{AnyOf: []string{"external-jwt"}}
	if err := config.Validate(); err != nil {
		t.Fatalf("same issuer on separate servers was rejected: %v", err)
	}
}
