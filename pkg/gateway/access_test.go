package gateway

import (
	"bytes"
	"strings"
	"testing"

	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	yaml "go.yaml.in/yaml/v3"
)

func TestAccessValidation(t *testing.T) {
	for _, test := range []struct {
		name string
		want string
		edit func(*gatewayapi.Config)
	}{
		{"missing access", "apis[0].access", func(c *gatewayapi.Config) { c.Servers[0].APIs[0].Access = nil }},
		{"public and access", ".public cannot", func(c *gatewayapi.Config) { c.Servers[0].APIs[0].Public = true }},
		{"missing label", "exactly one of tenant or name", func(c *gatewayapi.Config) { c.Servers[0].APIs[0].Access[0].Name = "" }},
		{"both labels", "exactly one of tenant or name", func(c *gatewayapi.Config) { c.Servers[0].APIs[0].Access[0].Tenant = "tenant-a" }},
		{"missing authentication", ".authentication must select", func(c *gatewayapi.Config) { c.Servers[0].APIs[0].Access[0].Authentication = nil }},
		{"both credential types", "exactly one of jwt or api_key", func(c *gatewayapi.Config) {
			c.Servers[0].APIs[0].Access[0].Authentication.APIKey = &gatewayapi.AuthenticatorReference{Authenticator: "writer-key"}
		}},
		{"empty providers", "jwt.providers must not be empty", func(c *gatewayapi.Config) { c.Servers[0].APIs[0].Access[0].Authentication.JWT.Providers = nil }},
		{"unknown provider", "unknown name", func(c *gatewayapi.Config) {
			c.Servers[0].APIs[0].Access[0].Authentication.JWT.Providers = []string{"unknown"}
		}},
		{"wrong provider type", "wrong type", func(c *gatewayapi.Config) {
			c.Servers[0].APIs[0].Access[0].Authentication.JWT.Providers = []string{"writer-key"}
		}},
		{"duplicate provider", "duplicates name", func(c *gatewayapi.Config) {
			c.Servers[0].APIs[0].Access[0].Authentication.JWT.Providers = []string{"issuer-one", "issuer-one"}
		}},
		{"duplicate issuer in entry", "same issuer", func(c *gatewayapi.Config) { c.Authenticators[1].JWT.Issuer = c.Authenticators[0].JWT.Issuer }},
		{"missing grants", "authorization.grants must not be empty", func(c *gatewayapi.Config) { c.Servers[0].APIs[0].Access[0].Authorization.Grants = nil }},
		{"unselected grant provider", "is not enabled", func(c *gatewayapi.Config) {
			c.Servers[0].APIs[0].Access[0].Authorization.Grants[0].Authenticator = "issuer-two"
		}},
		{"undeclared attribute", "is not declared", func(c *gatewayapi.Config) { removeTestAttribute(&c.Authenticators[0], "role") }},
		{"header identity condition", "not a header source", func(c *gatewayapi.Config) {
			setTestAttribute(&c.Authenticators[0], testTextAttribute("role", "header", "X-Role"))
		}},
		{"null condition", "must contain values", func(c *gatewayapi.Config) {
			c.Servers[0].APIs[0].Access[0].Authorization.Grants[0].Attributes["role"] = nil
		}},
		{"empty allowlist", "must contain values", func(c *gatewayapi.Config) {
			c.Servers[0].APIs[0].Access[0].Authorization.Grants[0].Attributes["role"].Values = nil
		}},
		{"duplicate allowed values", "distinct nonempty values", func(c *gatewayapi.Config) {
			c.Servers[0].APIs[0].Access[0].Authorization.Grants[0].Attributes["role"].Values = []string{"writer", "writer"}
		}},
		{"unknown comparison source", "undeclared attribute", func(c *gatewayapi.Config) {
			c.Servers[0].APIs[0].Access[0].Authorization.Grants[0].Attributes["tenant_id"].EqualsAttribute = "unknown"
		}},
		{"unmatched comparison header", "must be selected in match.headers", func(c *gatewayapi.Config) {
			setTestAttribute(&c.Authenticators[0], testTextAttribute("requested_tenant", "header", "X-Other-Tenant"))
		}},
		{"both condition forms", "cannot combine", func(c *gatewayapi.Config) {
			c.Servers[0].APIs[0].Access[0].Authorization.Grants[0].Attributes["tenant_id"].Values = []string{"tenant-a"}
		}},
		{"duplicate header casing", "duplicates header", func(c *gatewayapi.Config) {
			c.Servers[0].APIs[0].Access[0].Match.Headers["x-tenant"] = gatewayapi.HeaderMatch{Exact: new("tenant-a")}
		}},
		{"credential selector", "unsafe header", func(c *gatewayapi.Config) {
			c.Servers[0].APIs[0].Access[0].Match.Headers["X-Writer-Key"] = gatewayapi.HeaderMatch{Exact: new("secret")}
		}},
		{"empty header values", ".in must not be empty", func(c *gatewayapi.Config) {
			c.Servers[0].APIs[0].Access[0].Match.Headers["X-Tenant"] = gatewayapi.HeaderMatch{In: []string{}}
		}},
		{"both header forms", "exactly one of exact or in", func(c *gatewayapi.Config) {
			c.Servers[0].APIs[0].Access[0].Match.Headers["X-Tenant"] = gatewayapi.HeaderMatch{Exact: new("tenant-a"), In: []string{"tenant-b"}}
		}},
		{"comma in selector", "without commas", func(c *gatewayapi.Config) {
			c.Servers[0].APIs[0].Access[0].Match.Headers["X-Tenant"] = gatewayapi.HeaderMatch{In: []string{"tenant-a,tenant-b"}}
		}},
		{"overlapping entries", ".match overlaps", func(c *gatewayapi.Config) {
			c.Servers[0].APIs[0].Access[1].Match.Headers["X-Tenant"] = gatewayapi.HeaderMatch{Exact: new("tenant-a")}
		}},
		{"unselected CA verifier", "must reference an mTLS", func(c *gatewayapi.Config) { c.Servers[1].TLSConfig.MTLS.Authenticator = "issuer-one" }},
		{"missing client CA", "mtls.trusted_ca", func(c *gatewayapi.Config) { c.Authenticators[3].MTLS.TrustedCA = nil }},
		{"JWT on mTLS server", "forbidden on a dedicated mTLS server", func(c *gatewayapi.Config) {
			c.Servers[1].APIs[0].Access[0].Authentication = &gatewayapi.Authentication{JWT: &gatewayapi.JWTAuthentication{Providers: []string{"issuer-one"}}}
		}},
		{"key on mTLS server", "forbidden on a dedicated mTLS server", func(c *gatewayapi.Config) {
			c.Servers[1].APIs[0].Access[0].Authentication = &gatewayapi.Authentication{APIKey: &gatewayapi.AuthenticatorReference{Authenticator: "writer-key"}}
		}},
		{"another API with auth on mTLS server", "forbidden on a dedicated mTLS server", func(c *gatewayapi.Config) {
			c.Servers[1].APIs = append(c.Servers[1].APIs, c.Servers[0].APIs[1])
		}},
		{"another grant on mTLS server", "is not enabled", func(c *gatewayapi.Config) {
			c.Servers[1].APIs[0].Access[0].Authorization.Grants[0].Authenticator = "writer-key"
		}},
		{"public on mTLS server", ".public cannot", func(c *gatewayapi.Config) {
			c.Servers[1].APIs = append(c.Servers[1].APIs, gatewayapi.APIBinding{Name: "health", Public: true})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := loadConfigCase(t, "access-control")
			test.edit(&c)
			if err := Validate(c); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate() = %v, want %q", err, test.want)
			}
		})
	}
}

func TestDisjointEnvironmentCannotChangeTenantAuthentication(t *testing.T) {
	c := loadConfigCase(t, "access-control")
	c.Servers[0].APIs[0].Access[1].Match.Headers = map[string]gatewayapi.HeaderMatch{
		"X-Tenant": {Exact: new("tenant-a")}, "X-Mode": {Exact: new("different")},
	}
	if err := Validate(c); err == nil || !strings.Contains(err.Error(), "overlaps tenant values") {
		t.Fatalf("Validate() = %v, want overlapping tenant selections", err)
	}
}

func TestAccessDefaultsDoNotAliasSourcesOrConditions(t *testing.T) {
	c := loadConfigCase(t, "access-control")
	before, err := yaml.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	cloned := withDefaultsConfig(c)
	access := &cloned.Servers[0].APIs[0].Access[0]
	access.Match.Headers["X-Tenant"].In[0] = "changed"
	*access.Match.Headers["X-Mode"].Exact = "changed"
	access.Authentication.JWT.Providers[0] = "changed"
	access.Authorization.Grants[0].Attributes["tenant_id"].EqualsAttribute = "changed"
	access.Authorization.Grants[0].Attributes["role"].Values[0] = "changed"
	cloned.Servers[1].TLSConfig.MTLS.Authenticator = "changed"
	after, err := yaml.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("defaulting aliases the caller's access configuration")
	}
}

func TestLoadRejectsLegacyAccessSchema(t *testing.T) {
	for _, input := range []string{
		"version: 1\nauthorization_policies: []\n",
		"version: 1\nservers:\n- hostname: example.test\n  authentication: {any_of: [issuer]}\n",
		"version: 1\nservers:\n- hostname: example.test\n  apis: [write]\n",
	} {
		if _, err := Load(strings.NewReader(input)); err == nil {
			t.Fatalf("legacy access schema accepted: %s", input)
		}
	}
}
