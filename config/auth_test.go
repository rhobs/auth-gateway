package config

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestAuthValidationFixtureContainsExpectedConfiguration(t *testing.T) {
	c := loadAuthValidationFixture(t)
	if len(c.Authenticators) != 3 || len(c.AuthorizationPolicies) != 3 {
		t.Fatalf("fixture counts = %d authenticators, %d policies", len(c.Authenticators), len(c.AuthorizationPolicies))
	}
	if got, want := c.Authenticators[0].Attributes["tenant_id"].ClaimPath, []string{"organization", "id"}; !slices.Equal(got, want) {
		t.Fatalf("tenant claim path = %v, want %v", got, want)
	}
	if source := c.Authenticators[0].Attributes["requested_tenant"]; source.Header == nil || *source.Header != "X-Tenant" {
		t.Fatalf("JWT header attribute = %#v", source)
	}
	if got, want := c.AuthorizationPolicies[0].Grants[0].Attributes["tenant_id"], []string{"client-123", "client-456"}; !slices.Equal(got, want) {
		t.Fatalf("authorization values = %v, want original claim values %v", got, want)
	}
	if key := c.Authenticators[2].APIKey; key == nil || key.Secret != "auth-gateway-api-keys" || key.Header != "X-Partner-Key" ||
		!slices.Equal(c.Authenticators[2].credentialAttributeNames(), []string{"tenant_id", "writer_id"}) {
		t.Fatalf("fixture API-key authenticator = %#v", key)
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
	config := loadAuthValidationFixture(t)
	config.Authenticators[0].Attributes["tenant_id"] = AttributeSource{
		ClaimPath: []string{"organization", "customer.id"},
	}
	config.Servers[0].Authentication = &Authentication{AllOf: []string{"internal-jwt"}}
	config.Servers[0].Authorization = &Authorization{AllOf: []string{"metrics-writers", "logs-writers"}}
	if err := config.Validate(); err != nil {
		t.Fatalf("Validate rejected a literal claim key and valid all_of combinations: %v", err)
	}
}

func TestLoadAcceptsMTLSAuthenticatorSchema(t *testing.T) {
	c := loadConfigCase(t, "mtls-auth")
	authenticator := c.Authenticators[1]
	if authenticator.MTLS == nil || authenticator.MTLS.TrustedCA == nil || authenticator.MTLS.TrustedCA.ConfigMap == nil ||
		authenticator.MTLS.TrustedCA.ConfigMap.Name != "gateway-client-ca" || authenticator.Attributes["tenant_id"].URISAN == nil ||
		authenticator.Attributes["dns_id"].DNSSAN == nil {
		t.Fatalf("loaded mTLS authenticator = %#v", authenticator)
	}
	if len(c.AuthorizationPolicies[3].Grants[0].Attributes) != 0 {
		t.Fatalf("CA-only grant has unexpected attribute constraints: %#v", c.AuthorizationPolicies[3].Grants[0])
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
			c := loadAuthValidationFixture(t)
			test.edit(&c)
			if err := c.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validation error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestValidateAcceptsHeaderOnlyGrant(t *testing.T) {
	c := loadAuthValidationFixture(t)
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
		{name: "missing authenticator type", want: "authenticators[0] must set exactly one of jwt, api_key, or mtls", edit: func(c *Config) { c.Authenticators[0].JWT = nil }},
		{name: "missing issuer", want: "authenticators[0].jwt.issuer", edit: func(c *Config) { c.Authenticators[0].JWT.Issuer = "" }},
		{name: "non-HTTPS JWKS", want: "authenticators[0].jwt.jwks.uri", edit: func(c *Config) { c.Authenticators[0].JWT.JWKS.URI = "http://sso.example.com/jwks" }},
		{name: "unsupported JWKS DNS lookup family", want: "authenticators[0].jwt.jwks.dns_lookup_family", edit: func(c *Config) { c.Authenticators[0].JWT.JWKS.DNSLookupFamily = "V5_ONLY" }},
		{name: "JWKS user information", want: "authenticators[0].jwt.jwks.uri", edit: func(c *Config) { c.Authenticators[0].JWT.JWKS.URI = "https://user@sso.example.com/jwks" }},
		{name: "duplicate audience", want: "authenticators[0].jwt.audiences", edit: func(c *Config) { c.Authenticators[0].JWT.Audiences = []string{"same", "same"} }},
		{name: "empty claim path", want: "authenticators[0].attributes.tenant_id.claim_path", edit: func(c *Config) {
			c.Authenticators[0].Attributes["tenant_id"] = AttributeSource{ClaimPath: []string{""}}
		}},
		{name: "duplicate policy", want: "duplicate authorization policy name", edit: func(c *Config) { c.AuthorizationPolicies[1].Name = c.AuthorizationPolicies[0].Name }},
		{name: "unknown authentication method", want: "servers[0].authentication.any_of", edit: func(c *Config) { c.Servers[0].Authentication.AnyOf = []string{"missing"} }},
		{name: "duplicate authentication method", want: "servers[0].authentication.any_of", edit: func(c *Config) { c.Servers[0].Authentication.AnyOf = []string{"internal-jwt", "internal-jwt"} }},
		{name: "no authentication combination", want: "servers[0].authentication must set exactly one", edit: func(c *Config) { c.Servers[0].Authentication = &Authentication{} }},
		{name: "both authentication combinations", want: "servers[0].authentication must set exactly one", edit: func(c *Config) { c.Servers[0].Authentication.AllOf = []string{"internal-jwt"} }},
		{name: "empty authentication combination", want: "servers[0].authentication.any_of", edit: func(c *Config) { c.Servers[0].Authentication.AnyOf = []string{} }},
		{name: "multiple JWT methods in all_of", want: "servers[0].authentication.all_of", edit: func(c *Config) {
			c.Servers[0].Authentication = &Authentication{AllOf: []string{"internal-jwt", "external-jwt"}}
		}},
		{name: "unknown authorization policy", want: "servers[0].authorization.any_of", edit: func(c *Config) { c.Servers[0].Authorization.AnyOf = []string{"missing"} }},
		{name: "no authorization combination", want: "servers[0].authorization must set exactly one", edit: func(c *Config) { c.Servers[0].Authorization = &Authorization{} }},
		{name: "both authorization combinations", want: "servers[0].authorization must set exactly one", edit: func(c *Config) { c.Servers[0].Authorization.AllOf = []string{"metrics-writers"} }},
		{name: "duplicate any_of authorization policy", want: "servers[0].authorization.any_of", edit: func(c *Config) { c.Servers[0].Authorization.AnyOf = []string{"metrics-writers", "metrics-writers"} }},
		{name: "duplicate all_of authorization policy", want: "servers[0].authorization.all_of", edit: func(c *Config) {
			c.Servers[0].Authorization = &Authorization{AllOf: []string{"metrics-writers", "metrics-writers"}}
		}},
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
			config := loadAuthValidationFixture(t)
			test.edit(&config)
			if err := config.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validation error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestAnyOfMayOmitUnusedHeaderAttributes(t *testing.T) {
	config := loadAuthValidationFixture(t)
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
	config := loadAuthValidationFixture(t)
	config.Authenticators[1].JWT.Issuer = config.Authenticators[0].JWT.Issuer
	config.Authenticators[1].JWT.Audiences = []string{"another-audience"}
	if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "same issuer") {
		t.Fatalf("Validate error = %v, want duplicate issuer binding error", err)
	}

	config = loadAuthValidationFixture(t)
	config.Authenticators[1].JWT.Issuer = config.Authenticators[0].JWT.Issuer
	config.Servers = config.Servers[:2]
	config.Servers[0].Authentication = &Authentication{AnyOf: []string{"internal-jwt"}}
	config.Servers[1].Authentication = &Authentication{AnyOf: []string{"external-jwt"}}
	if err := config.Validate(); err != nil {
		t.Fatalf("same issuer on separate servers was rejected: %v", err)
	}
}

func TestJWKSValidationIncludesUnusedProviders(t *testing.T) {
	tests := []struct {
		name  string
		edit  func(*Config)
		field string
	}{
		{"zero", func(c *Config) { c.Authenticators[0].JWT.JWKS.CacheDuration = duration(0) }, ".cache_duration"},
		{"negative Go duration", func(c *Config) { c.Authenticators[0].JWT.JWKS.CacheDuration = duration(-time.Second) }, ".cache_duration"},
		{"connect exceeds fetch", func(c *Config) { c.Authenticators[0].JWT.JWKS.ConnectTimeout = duration(6 * time.Second) }, ".connect_timeout"},
		{"empty CA", func(c *Config) { c.Authenticators[0].JWT.JWKS.TrustedCA = &TrustedCA{} }, ".trusted_ca"},
		{"both sources", func(c *Config) {
			c.Authenticators[0].JWT.JWKS.TrustedCA = &TrustedCA{Filename: "/ca.pem", ConfigMap: &CAConfigMap{Name: "ca", Key: "ca.pem"}}
		}, ".trusted_ca"},
		{"ConfigMap without Kubernetes", func(c *Config) {
			c.Kubernetes = nil
			c.Authenticators[0].JWT.JWKS.TrustedCA = &TrustedCA{ConfigMap: &CAConfigMap{Name: "ca", Key: "ca.pem"}}
		}, ".trusted_ca.config_map"},
		{"bad ConfigMap name", func(c *Config) {
			c.Authenticators[0].JWT.JWKS.TrustedCA = &TrustedCA{ConfigMap: &CAConfigMap{Name: "bad/name", Key: "ca.pem"}}
		}, ".trusted_ca.config_map.name"},
		{"bad key", func(c *Config) {
			c.Authenticators[0].JWT.JWKS.TrustedCA = &TrustedCA{ConfigMap: &CAConfigMap{Name: "ca", Key: "../ca.pem"}}
		}, ".trusted_ca.config_map.key"},
		{"relative file", func(c *Config) {
			c.Kubernetes = nil
			c.Authenticators[0].JWT.JWKS.TrustedCA = &TrustedCA{Filename: "ca.pem"}
		}, ".trusted_ca.filename"},
		{"relative file in Kubernetes", func(c *Config) {
			c.Authenticators[0].JWT.JWKS.TrustedCA = &TrustedCA{Filename: "ca.pem"}
		}, ".trusted_ca.filename"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := loadConfigCase(t, "jwt-auth")
			c.Servers[0].Authentication = nil
			c.Servers[0].Authorization = nil
			tt.edit(&c)
			if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "authenticators[0].jwt.jwks"+tt.field) {
				t.Fatalf("validation = %v", err)
			}
		})
	}
	c := loadConfigCase(t, "jwt-auth")
	c.Kubernetes = nil
	c.Authenticators[0].JWT.JWKS.TrustedCA = &TrustedCA{Filename: "/etc/company/ca.crt"}
	if _, err := Generate(c); err != nil {
		t.Fatal(err)
	}
	c = loadConfigCase(t, "server-tls")
	c.Servers[1].TLSConfig.Certificate = caDirectory + "/roots/tls.crt"
	c.Servers[1].TLSConfig.PrivateKey = caDirectory + "/roots/tls.key"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), caDirectory) {
		t.Fatalf("reserved CA mount tree: %v", err)
	}
}

func TestValidateMTLSRequiresExplicitClientCA(t *testing.T) {
	tests := []struct {
		name string
		want string
		edit func(*Config)
	}{
		{name: "missing CA", want: "authenticators[1].mtls.trusted_ca", edit: func(c *Config) {
			c.Authenticators[1].MTLS.TrustedCA = nil
		}},
		{name: "empty CA", want: "authenticators[1].mtls.trusted_ca", edit: func(c *Config) {
			c.Authenticators[1].MTLS.TrustedCA = &TrustedCA{}
		}},
		{name: "both CA sources", want: "authenticators[1].mtls.trusted_ca", edit: func(c *Config) {
			c.Authenticators[1].MTLS.TrustedCA.Filename = "/etc/client-ca.crt"
		}},
		{name: "relative CA file", want: "authenticators[1].mtls.trusted_ca.filename", edit: func(c *Config) {
			c.Authenticators[1].MTLS.TrustedCA = &TrustedCA{Filename: "client-ca.crt"}
		}},
		{name: "ConfigMap without Kubernetes", want: "authenticators[1].mtls.trusted_ca.config_map", edit: func(c *Config) {
			c.Kubernetes = nil
		}},
		{name: "invalid ConfigMap key", want: "authenticators[1].mtls.trusted_ca.config_map.key", edit: func(c *Config) {
			c.Authenticators[1].MTLS.TrustedCA.ConfigMap.Key = "../ca.crt"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := loadConfigCase(t, "mtls-auth")
			test.edit(&c)
			if err := c.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validation error = %v, want %q", err, test.want)
			}
		})
	}
	c := loadConfigCase(t, "mtls-auth")
	c.Kubernetes = nil
	c.Authenticators[1].MTLS.TrustedCA = &TrustedCA{Filename: "/etc/client-ca.crt"}
	if err := c.Validate(); err != nil {
		t.Fatalf("file-based mTLS CA was rejected: %v", err)
	}
}

func TestValidateMTLSRequiresHTTPSAndOneAuthenticatorPerServer(t *testing.T) {
	c := loadConfigCase(t, "mtls-auth")
	c.Servers[0].TLSConfig = nil
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "servers[0].authentication requires tls_config") {
		t.Fatalf("HTTP mTLS binding error = %v", err)
	}

	c = loadConfigCase(t, "mtls-auth")
	second := c.Authenticators[1].clone()
	second.Name = "second-client-cert"
	c.Authenticators = append(c.Authenticators, second)
	c.Servers[0].Authentication.AnyOf = []string{"client-cert", second.Name}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "servers[0].authentication cannot contain more than one mTLS") {
		t.Fatalf("duplicate mTLS binding error = %v", err)
	}
}

func TestValidateMTLSAttributeSources(t *testing.T) {
	tests := []struct {
		name string
		want string
		edit func(*Config)
	}{
		{name: "missing source", want: "authenticators[1].attributes.tenant_id", edit: func(c *Config) {
			c.Authenticators[1].Attributes["tenant_id"] = AttributeSource{}
		}},
		{name: "false URI SAN", want: "authenticators[1].attributes.tenant_id.uri_san", edit: func(c *Config) {
			c.Authenticators[1].Attributes["tenant_id"] = AttributeSource{URISAN: new(false)}
		}},
		{name: "false DNS SAN", want: "authenticators[1].attributes.dns_id.dns_san", edit: func(c *Config) {
			c.Authenticators[1].Attributes["dns_id"] = AttributeSource{DNSSAN: new(false)}
		}},
		{name: "multiple sources", want: "authenticators[1].attributes.tenant_id", edit: func(c *Config) {
			c.Authenticators[1].Attributes["tenant_id"] = AttributeSource{URISAN: new(true), DNSSAN: new(true)}
		}},
		{name: "JWT source", want: "authenticators[1].attributes.tenant_id", edit: func(c *Config) {
			c.Authenticators[1].Attributes["tenant_id"] = AttributeSource{ClaimPath: []string{"sub"}}
		}},
		{name: "API key source", want: "authenticators[1].attributes.tenant_id", edit: func(c *Config) {
			c.Authenticators[1].Attributes["tenant_id"] = AttributeSource{Credential: new(true)}
		}},
		{name: "URI SAN on JWT", want: "authenticators[0].attributes.tenant_id", edit: func(c *Config) {
			c.Authenticators[0].Attributes["tenant_id"] = AttributeSource{URISAN: new(true)}
		}},
		{name: "DNS SAN on API key", want: "authenticators[2].attributes.tenant_id", edit: func(c *Config) {
			c.Authenticators[2].Attributes["tenant_id"] = AttributeSource{DNSSAN: new(true)}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := loadConfigCase(t, "mtls-auth")
			test.edit(&c)
			if err := c.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validation error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestValidateMTLSGrantMayUseOnlyHeaders(t *testing.T) {
	c := loadConfigCase(t, "mtls-auth")
	c.AuthorizationPolicies[1].Grants[0].Attributes = map[string][]string{"requested_tenant": {"client-a"}}
	if err := c.Validate(); err != nil {
		t.Fatalf("header-only mTLS grant was rejected: %v", err)
	}
}
