package config

import (
	"os"
	"strings"
	"testing"
)

func loadAuthExample(t testing.TB) Config {
	t.Helper()
	config, err := Load(strings.NewReader(readFile(t, "../config.auth.example.yaml")))
	if err != nil {
		t.Fatalf("load auth example: %v", err)
	}
	return config
}

func readFile(t testing.TB, name string) string {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %q: %v", name, err)
	}
	return string(data)
}

func TestLoadAuthExample(t *testing.T) {
	config := loadAuthExample(t)
	if len(config.Authenticators) != 2 || len(config.AuthorizationPolicies) != 2 {
		t.Fatalf("auth config counts = %d authenticators, %d policies", len(config.Authenticators), len(config.AuthorizationPolicies))
	}
	if len(config.Processing) != 1 || config.Processing[0].Type != "attribute-mapper" {
		t.Fatalf("processing config = %#v", config.Processing)
	}
	if got := config.Authenticators[0].JWT.Attributes["tenant_id"].ClaimPath; len(got) != 4 {
		t.Fatalf("nested claim path = %#v", got)
	}
	if got := config.AuthorizationPolicies[0].Grants[0].Attributes["tenant_id"]; len(got) != 2 || got[0] != "client-123" {
		t.Fatalf("authorization must use original IDs, got %#v", got)
	}
	if got := config.APIs[0].Routes[0].Processing.RequestHeaders; len(got) != 2 {
		t.Fatalf("request header mappings = %#v", got)
	}
}

func TestValidateAcceptsLiteralClaimKeysAndSingleJWTAllOf(t *testing.T) {
	config := loadAuthExample(t)
	config.Authenticators[0].JWT.Attributes["tenant_id"] = JWTAttribute{
		ClaimPath: []string{"organization", "customer.id"},
	}
	config.Servers[0].Authentication = &Authentication{AllOf: []string{"internal-jwt"}}
	config.Servers[0].Authorization = &Authorization{AllOf: []string{"metrics-writers", "logs-writers"}}
	if err := config.Validate(); err != nil {
		t.Fatalf("Validate rejected a literal claim key and valid all_of combinations: %v", err)
	}
}

func TestLoadRejectsFutureMTLSAuthenticatorSchema(t *testing.T) {
	input := strings.Replace(readFile(t, "../config.auth.example.yaml"), "    jwt:\n", "    mtls:\n", 1)
	if _, err := Load(strings.NewReader(input)); err == nil || !strings.Contains(err.Error(), "field mtls not found") {
		t.Fatalf("Load error = %v, want strict rejection of the future mTLS field", err)
	}
}

func TestValidateRejectsInvalidAuthenticationAndAuthorization(t *testing.T) {
	tests := map[string]func(*Config){
		"duplicate authenticator": func(c *Config) {
			c.Authenticators[1].Name = c.Authenticators[0].Name
		},
		"missing JWT type": func(c *Config) {
			c.Authenticators[0].JWT = nil
		},
		"missing issuer": func(c *Config) {
			c.Authenticators[0].JWT.Issuer = ""
		},
		"non-HTTPS JWKS": func(c *Config) {
			c.Authenticators[0].JWT.JWKSURI = "http://sso.example.com/jwks"
		},
		"JWKS user information": func(c *Config) {
			c.Authenticators[0].JWT.JWKSURI = "https://user@sso.example.com/jwks"
		},
		"missing audiences": func(c *Config) {
			c.Authenticators[0].JWT.Audiences = nil
		},
		"duplicate audience": func(c *Config) {
			c.Authenticators[0].JWT.Audiences = []string{"same", "same"}
		},
		"empty claim path": func(c *Config) {
			c.Authenticators[0].JWT.Attributes["tenant_id"] = JWTAttribute{ClaimPath: []string{""}}
		},
		"empty mapping output": func(c *Config) {
			c.Processing[0].Attributes["tenant_id"].Mappings["client-123"] = ""
		},
		"unsafe mapping output": func(c *Config) {
			c.Processing[0].Attributes["tenant_id"].Mappings["client-123"] = "team-a\r\nInjected: yes"
		},
		"duplicate processor name": func(c *Config) {
			c.Processing = append(c.Processing, c.Processing[0])
		},
		"unsupported processor type": func(c *Config) {
			c.Processing[0].Type = "unknown"
		},
		"invalid processor attribute": func(c *Config) {
			c.Processing[0].Attributes["bad.name"] = AttributeMappings{Mappings: map[string]string{"from": "to"}}
		},
		"empty mapping source": func(c *Config) {
			c.Processing[0].Attributes["tenant_id"].Mappings[""] = "team-a"
		},
		"duplicate policy": func(c *Config) {
			c.AuthorizationPolicies[1].Name = c.AuthorizationPolicies[0].Name
		},
		"unknown authentication method": func(c *Config) {
			c.Servers[0].Authentication.AnyOf = []string{"missing"}
		},
		"duplicate authentication method": func(c *Config) {
			c.Servers[0].Authentication.AnyOf = []string{"internal-jwt", "internal-jwt"}
		},
		"both authentication combinations": func(c *Config) {
			c.Servers[0].Authentication.AllOf = []string{"internal-jwt"}
		},
		"empty authentication combination": func(c *Config) {
			c.Servers[0].Authentication.AnyOf = []string{}
		},
		"multiple JWT methods in all_of": func(c *Config) {
			c.Servers[0].Authentication = &Authentication{AllOf: []string{"internal-jwt", "external-jwt"}}
		},
		"unknown authorization policy": func(c *Config) {
			c.Servers[0].Authorization.AnyOf = []string{"missing"}
		},
		"authorization without authentication": func(c *Config) {
			c.Servers[0].Authentication = nil
		},
		"unknown grant authenticator": func(c *Config) {
			c.AuthorizationPolicies[0].Grants[0].Authenticator = "missing"
		},
		"empty grant APIs": func(c *Config) {
			c.AuthorizationPolicies[0].Grants[0].APIs = nil
		},
		"unknown grant API": func(c *Config) {
			c.AuthorizationPolicies[0].Grants[0].APIs = []string{"missing"}
		},
		"empty grant attribute values": func(c *Config) {
			c.AuthorizationPolicies[0].Grants[0].Attributes["tenant_id"] = nil
		},
		"grant attribute absent from authenticator": func(c *Config) {
			c.AuthorizationPolicies[0].Grants[0].Attributes["missing"] = []string{"value"}
		},
		"authorization policy combination empty": func(c *Config) {
			c.Servers[0].Authorization.AnyOf = []string{}
		},
		"public server with authorization": func(c *Config) {
			c.Servers[0].Authentication = nil
		},
		"invalid header field name": func(c *Config) {
			c.APIs[0].Routes[0].Processing.RequestHeaders[0].Name = "Bad Header"
		},
		"reserved credential header": func(c *Config) {
			c.APIs[0].Routes[0].Processing.RequestHeaders[0].Name = "Authorization"
		},
		"duplicate header field name": func(c *Config) {
			c.APIs[0].Routes[0].Processing.RequestHeaders[1].Name = "x-scope-orgid"
		},
		"empty processing source": func(c *Config) {
			c.APIs[0].Routes[0].Processing.RequestHeaders[0].FromAttribute = ""
		},
		"processing on public server": func(c *Config) {
			c.Servers[0].Authentication = nil
			c.Servers[0].Authorization = nil
		},
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			config := loadAuthExample(t)
			change(&config)
			if err := config.Validate(); err == nil {
				t.Fatal("Validate accepted invalid authentication configuration")
			}
		})
	}
}

func TestAnyOfMayOmitUnusedHeaderAttributes(t *testing.T) {
	config := loadAuthExample(t)
	delete(config.Authenticators[1].JWT.Attributes, "writer_id")
	if err := config.Validate(); err != nil {
		t.Fatalf("Validate rejected an any_of authenticator that omits a route attribute: %v", err)
	}

	delete(config.Authenticators[0].JWT.Attributes, "writer_id")
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
	config.Servers[0].Authentication = &Authentication{AnyOf: []string{"internal-jwt"}}
	config.Servers[1].Authentication = &Authentication{AnyOf: []string{"external-jwt"}}
	if err := config.Validate(); err != nil {
		t.Fatalf("same issuer on separate servers was rejected: %v", err)
	}
}

func TestAuthenticationDefaultsDoNotMutateInput(t *testing.T) {
	config := loadAuthExample(t)
	defaulted := config.withDefaults()
	defaulted.Authenticators[0].JWT.Audiences[0] = "changed"
	defaulted.Authenticators[0].JWT.Attributes["tenant_id"].ClaimPath[0] = "changed"
	defaulted.Processing[0].Attributes["tenant_id"].Mappings["client-123"] = "changed"
	defaulted.AuthorizationPolicies[0].Grants[0].APIs[0] = "changed"
	defaulted.AuthorizationPolicies[0].Grants[0].Attributes["tenant_id"][0] = "changed"
	defaulted.Servers[0].Authentication.AnyOf[0] = "changed"
	defaulted.Servers[0].Authorization.AnyOf[0] = "changed"
	defaulted.APIs[0].Routes[0].Processing.RequestHeaders[0].Name = "changed"

	if config.Authenticators[0].JWT.Audiences[0] == "changed" ||
		config.Authenticators[0].JWT.Attributes["tenant_id"].ClaimPath[0] == "changed" ||
		config.Processing[0].Attributes["tenant_id"].Mappings["client-123"] == "changed" ||
		config.AuthorizationPolicies[0].Grants[0].APIs[0] == "changed" ||
		config.AuthorizationPolicies[0].Grants[0].Attributes["tenant_id"][0] == "changed" ||
		config.Servers[0].Authentication.AnyOf[0] == "changed" ||
		config.Servers[0].Authorization.AnyOf[0] == "changed" ||
		config.APIs[0].Routes[0].Processing.RequestHeaders[0].Name == "changed" {
		t.Fatal("withDefaults retained aliases to authentication configuration")
	}
}

func TestGenerateIncludesAuthenticationAuthorizationAndProcessing(t *testing.T) {
	config := loadAuthExample(t)
	files, err := Generate(config)
	if err != nil {
		t.Fatalf("Generate rejected the JWT example: %v", err)
	}
	manager := firstHTTPManager(t, files["envoy.yaml"])
	want := []string{
		"envoy.filters.http.jwt_authn", authorizationFilterName, attributeFilterName,
		requiredHeaderFilterName, "envoy.filters.http.header_mutation", "envoy.filters.http.router",
	}
	if got := httpFilterNames(manager); !equalStringSlices(got, want) {
		t.Fatalf("JWT example filter order = %v, want %v", got, want)
	}
	resources, err := GenerateKubernetes(config)
	if err != nil {
		t.Fatalf("GenerateKubernetes rejected the JWT example: %v", err)
	}
	if resources.ConfigMap.Data["envoy.yaml"] == "" {
		t.Fatal("generated JWT example has no Envoy configuration")
	}
}

func equalStringSlices(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
