package gateway

import (
	"bytes"
	"strings"
	"testing"

	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
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
		{"missing expression", ".expression", func(c *gatewayapi.Config) {
			c.Servers[0].APIs[0].Access[0].Authorization.Grants[0].Attributes[1].Expression = ""
		}},
		{"empty list", "nonempty list", func(c *gatewayapi.Config) {
			condition := &c.Servers[0].APIs[0].Access[0].Authorization.Grants[0].Attributes[1]
			condition.Expression = "in"
			condition.Value = gatewayapi.MatchValue{IsList: true}
		}},
		{"duplicate allowed values", "distinct nonempty strings", func(c *gatewayapi.Config) {
			condition := &c.Servers[0].APIs[0].Access[0].Authorization.Grants[0].Attributes[1]
			condition.Expression = "in"
			condition.Value = gatewayapi.MatchValue{IsList: true, Items: []string{"writer", "writer"}}
		}},
		{"unknown comparison source", "undeclared attribute", func(c *gatewayapi.Config) {
			c.Servers[0].APIs[0].Access[0].Authorization.Grants[0].Attributes[0].Value.Text = "unknown"
		}},
		{"unmatched comparison header", "must be selected in match.headers", func(c *gatewayapi.Config) {
			setTestAttribute(&c.Authenticators[0], testTextAttribute("requested_tenant", "header", "X-Other-Tenant"))
		}},
		{"wrong value type", "nonempty string", func(c *gatewayapi.Config) {
			c.Servers[0].APIs[0].Access[0].Authorization.Grants[0].Attributes[0].Value = gatewayapi.MatchValue{IsList: true, Items: []string{"tenant-a"}}
		}},
		{"attribute in with scalar value", "nonempty list", func(c *gatewayapi.Config) {
			c.Servers[0].APIs[0].Access[0].Authorization.Grants[0].Attributes[1].Expression = "in"
		}},
		{"has with list value", "nonempty string", func(c *gatewayapi.Config) {
			condition := &c.Servers[0].APIs[0].Access[0].Authorization.Grants[0].Attributes[1]
			condition.Expression = gatewayapi.ExpressionHas
			condition.Value = gatewayapi.MatchValue{IsList: true, Items: []string{"writer"}}
		}},
		{"has-one-of with scalar value", "nonempty list", func(c *gatewayapi.Config) {
			c.Servers[0].APIs[0].Access[0].Authorization.Grants[0].Attributes[1].Expression = gatewayapi.ExpressionHasOneOf
		}},
		{"has-one-of with duplicate values", "distinct nonempty strings", func(c *gatewayapi.Config) {
			condition := &c.Servers[0].APIs[0].Access[0].Authorization.Grants[0].Attributes[1]
			condition.Expression = gatewayapi.ExpressionHasOneOf
			condition.Value = gatewayapi.MatchValue{IsList: true, Items: []string{"writer", "writer"}}
		}},
		{"has on API-key attribute", "requires a JWT claim source", func(c *gatewayapi.Config) {
			c.Servers[0].APIs[0].Access[1].Authorization.Grants[0].Attributes[1].Expression = gatewayapi.ExpressionHas
		}},
		{"has-one-of on certificate attribute", "requires a JWT claim source", func(c *gatewayapi.Config) {
			condition := &c.Servers[1].APIs[0].Access[0].Authorization.Grants[0].Attributes[0]
			condition.Expression = gatewayapi.ExpressionHasOneOf
			condition.Value = gatewayapi.MatchValue{IsList: true, Items: []string{"writer", "reader"}}
		}},
		{"duplicate attribute", "duplicates attribute", func(c *gatewayapi.Config) {
			grant := &c.Servers[0].APIs[0].Access[0].Authorization.Grants[0]
			grant.Attributes = append(grant.Attributes, grant.Attributes[1])
		}},
		{"unknown attribute expression", ".expression", func(c *gatewayapi.Config) {
			c.Servers[0].APIs[0].Access[0].Authorization.Grants[0].Attributes[1].Expression = "contains"
		}},
		{"duplicate header casing", "duplicates header", func(c *gatewayapi.Config) {
			c.Servers[0].APIs[0].Access[0].Match.Headers = append(c.Servers[0].APIs[0].Access[0].Match.Headers, gatewayapi.MatchExpression{Name: "x-tenant", Expression: "equals", Value: gatewayapi.MatchValue{Text: "tenant-a"}})
		}},
		{"credential selector", "unsafe header", func(c *gatewayapi.Config) {
			c.Servers[0].APIs[0].Access[0].Match.Headers = append(c.Servers[0].APIs[0].Access[0].Match.Headers, gatewayapi.MatchExpression{Name: "X-Writer-Key", Expression: "equals", Value: gatewayapi.MatchValue{Text: "secret"}})
		}},
		{"Authorization value selector", "unsafe header", func(c *gatewayapi.Config) {
			c.Servers[0].APIs[0].Access[0].Match.Headers = append(c.Servers[0].APIs[0].Access[0].Match.Headers, gatewayapi.MatchExpression{Name: "Authorization", Expression: "equals", Value: gatewayapi.MatchValue{Text: "Bearer token"}})
		}},
		{"Authorization on key entry", "requires JWT authentication", func(c *gatewayapi.Config) {
			c.Servers[0].APIs[0].Access[1].Match.Headers = append(c.Servers[0].APIs[0].Access[1].Match.Headers, gatewayapi.MatchExpression{Name: "Authorization", Expression: "present"})
		}},
		{"key header on JWT entry", "requires API-key authentication", func(c *gatewayapi.Config) {
			c.Servers[0].APIs[0].Access[0].Match.Headers = append(c.Servers[0].APIs[0].Access[0].Match.Headers, gatewayapi.MatchExpression{Name: "X-Writer-Key", Expression: "present"})
		}},
		{"present with value", "value must be omitted", func(c *gatewayapi.Config) {
			c.Servers[0].APIs[0].Access[0].Match.Headers[1].Expression = "present"
		}},
		{"present attribute with value", "value must be omitted for present", func(c *gatewayapi.Config) {
			condition := &c.Servers[0].APIs[0].Access[0].Authorization.Grants[0].Attributes[1]
			condition.Expression = "present"
			condition.Value = gatewayapi.MatchValue{Text: "writer"}
		}},
		{"present attribute with list value", "value must be omitted for present", func(c *gatewayapi.Config) {
			condition := &c.Servers[0].APIs[0].Access[0].Authorization.Grants[0].Attributes[1]
			condition.Expression = "present"
			condition.Value = gatewayapi.MatchValue{IsList: true, Items: []string{"writer"}}
		}},
		{"present header attribute", "not a header source", func(c *gatewayapi.Config) {
			condition := &c.Servers[0].APIs[0].Access[0].Authorization.Grants[0].Attributes[1]
			condition.Expression = "present"
			condition.Value = gatewayapi.MatchValue{}
			setTestAttribute(&c.Authenticators[0], testTextAttribute("role", "header", "X-Role"))
		}},
		{"empty header values", "nonempty list", func(c *gatewayapi.Config) {
			c.Servers[0].APIs[0].Access[0].Match.Headers[0].Value = gatewayapi.MatchValue{IsList: true}
		}},
		{"header equality with list", "nonempty string", func(c *gatewayapi.Config) {
			c.Servers[0].APIs[0].Access[0].Match.Headers[0] = gatewayapi.MatchExpression{Name: "X-Tenant", Expression: "equals", Value: gatewayapi.MatchValue{IsList: true, Items: []string{"tenant-a"}}}
		}},
		{"header in with scalar value", "nonempty list", func(c *gatewayapi.Config) {
			c.Servers[0].APIs[0].Access[0].Match.Headers[0].Value = gatewayapi.MatchValue{Text: "tenant-a"}
		}},
		{"attribute comparison on header", "only valid for attributes", func(c *gatewayapi.Config) {
			c.Servers[0].APIs[0].Access[0].Match.Headers[0].Expression = "equals-attribute"
		}},
		{"has on header", "only valid for attributes", func(c *gatewayapi.Config) {
			c.Servers[0].APIs[0].Access[0].Match.Headers[0].Expression = gatewayapi.ExpressionHas
		}},
		{"has-one-of on header", "only valid for attributes", func(c *gatewayapi.Config) {
			c.Servers[0].APIs[0].Access[0].Match.Headers[0].Expression = gatewayapi.ExpressionHasOneOf
		}},
		{"comma in selector", "must not contain commas", func(c *gatewayapi.Config) {
			c.Servers[0].APIs[0].Access[0].Match.Headers[0].Value.Items = []string{"tenant-a,tenant-b"}
		}},
		{"overlapping entries", ".match overlaps", func(c *gatewayapi.Config) {
			c.Servers[0].APIs[0].Access[1].Match.Headers[0] = gatewayapi.MatchExpression{Name: "X-Tenant", Expression: "equals", Value: gatewayapi.MatchValue{Text: "tenant-a"}}
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

func TestPresentGrantValidation(t *testing.T) {
	for _, test := range []struct {
		name   string
		server int
		access int
	}{
		{name: "JWT", server: 0, access: 0},
		{name: "API key", server: 0, access: 1},
		{name: "mTLS", server: 1, access: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := loadConfigCase(t, "access-control")
			grant := &c.Servers[test.server].APIs[0].Access[test.access].Authorization.Grants[0]
			grant.Attributes = []gatewayapi.MatchExpression{{Name: "tenant_id", Expression: gatewayapi.ExpressionPresent}}
			if err := Validate(c); err != nil {
				t.Fatalf("valid present grant was rejected: %v", err)
			}
		})
	}
}

func TestJWTListGrantValidation(t *testing.T) {
	for _, test := range []struct {
		name       string
		expression string
		value      gatewayapi.MatchValue
	}{
		{name: "has", expression: gatewayapi.ExpressionHas, value: gatewayapi.MatchValue{Text: "writer"}},
		{name: "has-one-of", expression: gatewayapi.ExpressionHasOneOf, value: gatewayapi.MatchValue{IsList: true, Items: []string{"reader", "writer"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := loadConfigCase(t, "access-control")
			condition := &c.Servers[0].APIs[0].Access[0].Authorization.Grants[0].Attributes[1]
			condition.Expression = test.expression
			condition.Value = test.value
			if err := Validate(c); err != nil {
				t.Fatalf("valid JWT list grant was rejected: %v", err)
			}
		})
	}
}

func TestDisjointEnvironmentCannotChangeTenantAuthentication(t *testing.T) {
	c := loadConfigCase(t, "access-control")
	c.Servers[0].APIs[0].Access[1].Match.Headers = []gatewayapi.MatchExpression{
		{Name: "X-Tenant", Expression: "equals", Value: gatewayapi.MatchValue{Text: "tenant-a"}},
		{Name: "X-Mode", Expression: "equals", Value: gatewayapi.MatchValue{Text: "different"}},
	}
	if err := Validate(c); err == nil || !strings.Contains(err.Error(), "overlaps tenant values") {
		t.Fatalf("Validate() = %v, want overlapping tenant selections", err)
	}
}

func sharedCredentialAccessConfig(t *testing.T) gatewayapi.Config {
	t.Helper()
	c := loadConfigCase(t, "access-control")
	jwt := &c.Servers[0].APIs[0].Access[0]
	jwt.Match.Headers = append(jwt.Match.Headers, gatewayapi.MatchExpression{Name: "Authorization", Expression: gatewayapi.ExpressionPresent})
	key := &c.Servers[0].APIs[0].Access[1]
	key.Match.Headers[0] = gatewayapi.MatchExpression{Name: "X-Tenant", Expression: gatewayapi.ExpressionEquals, Value: gatewayapi.MatchValue{Text: "tenant-a"}}
	key.Match.Headers = append(key.Match.Headers, gatewayapi.MatchExpression{Name: "X-Writer-Key", Expression: gatewayapi.ExpressionPresent})
	return c
}

func TestSharedCredentialAccessRequiresBothSelectors(t *testing.T) {
	c := sharedCredentialAccessConfig(t)
	if err := Validate(c); err != nil {
		t.Fatalf("same tenant with separate credential selectors: %v", err)
	}
	for _, test := range []struct {
		name string
		edit func(*gatewayapi.Config)
	}{
		{"JWT selector missing", func(c *gatewayapi.Config) {
			access := &c.Servers[0].APIs[0].Access[0]
			access.Match.Headers = access.Match.Headers[:len(access.Match.Headers)-1]
		}},
		{"key selector missing", func(c *gatewayapi.Config) {
			access := &c.Servers[0].APIs[0].Access[1]
			access.Match.Headers = access.Match.Headers[:len(access.Match.Headers)-1]
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := sharedCredentialAccessConfig(t)
			test.edit(&changed)
			if err := Validate(changed); err == nil || !strings.Contains(err.Error(), ".match overlaps") {
				t.Fatalf("Validate() = %v, want overlapping access error", err)
			}
		})
	}
}

func TestSharedCredentialAccessUsesDefaultKeyHeader(t *testing.T) {
	c := sharedCredentialAccessConfig(t)
	c.Authenticators[2].APIKey.Header = ""
	c.Servers[0].APIs[0].Access[1].Match.Headers[2].Name = "x-api-key"
	if err := Validate(c); err != nil {
		t.Fatalf("default API-key header presence selector: %v", err)
	}
}

func TestPresentHeaderOverlapsValueSelector(t *testing.T) {
	c := loadConfigCase(t, "access-control")
	c.Servers[0].APIs[0].Access[0].Match.Headers[0] = gatewayapi.MatchExpression{Name: "X-Tenant", Expression: gatewayapi.ExpressionPresent}
	if err := Validate(c); err == nil || !strings.Contains(err.Error(), ".match overlaps") {
		t.Fatalf("Validate() = %v, want overlapping access error", err)
	}
}

func TestSharedCredentialAccessRoutesMatchHeaderPresence(t *testing.T) {
	c := sharedCredentialAccessConfig(t)
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	manager := firstHTTPManager(t, files.EnvoyBootstrap.Contents)
	host := manager.GetRouteConfig().GetVirtualHosts()[0]
	for _, test := range []struct {
		name, header string
	}{
		{"api-0-write-route-0-method-0-access-0-match-0", "authorization"},
		{"api-0-write-route-0-method-0-access-1-match-0", "x-writer-key"},
	} {
		generated := namedRoute(host.Routes, test.name)
		if generated == nil {
			t.Fatalf("route %q is missing", test.name)
		}
		var found bool
		for _, header := range generated.GetMatch().GetHeaders() {
			if header.GetName() == test.header {
				found = true
				if _, ok := header.GetHeaderMatchSpecifier().(*route.HeaderMatcher_PresentMatch); !ok || !header.GetPresentMatch() {
					t.Fatalf("route %q has no presence matcher for %q: %v", test.name, test.header, header)
				}
			}
		}
		if !found {
			t.Fatalf("route %q does not match %q", test.name, test.header)
		}
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
	access.Match.Headers[0].Value.Items[0] = "changed"
	access.Match.Headers[1].Value.Text = "changed"
	access.Authentication.JWT.Providers[0] = "changed"
	access.Authorization.Grants[0].Attributes[0].Value.Text = "changed"
	access.Authorization.Grants[0].Attributes[1].Value.Text = "changed"
	cloned.Servers[1].TLSConfig.MTLS.Authenticator = "changed"
	after, err := yaml.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("defaulting aliases the caller's access configuration")
	}
}
