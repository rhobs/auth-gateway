package config

import (
	"bytes"
	"reflect"
	"slices"
	"strings"
	"testing"

	jwt "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/jwt_authn/v3"
	"go.yaml.in/yaml/v3"
)

func TestReferenceErrorsFollowConfiguredOrder(t *testing.T) {
	for _, test := range []struct {
		name  string
		field string
		edit  func(*Config)
	}{
		{
			name: "API binding", field: "servers[2].apis",
			edit: func(c *Config) { c.Servers[2].APIs = []string{"z-missing", "a-missing"} },
		},
		{
			name: "authenticator binding", field: "servers[2].authentication.any_of",
			edit: func(c *Config) { c.Servers[2].Authentication.AnyOf = []string{"z-missing", "a-missing"} },
		},
		{
			name: "policy binding", field: "servers[2].authorization.any_of",
			edit: func(c *Config) { c.Servers[2].Authorization.AnyOf = []string{"z-missing", "a-missing"} },
		},
		{
			name: "grant API", field: "authorization_policies[0].grants[0].apis",
			edit: func(c *Config) { c.AuthorizationPolicies[0].Grants[0].APIs = []string{"z-missing", "a-missing"} },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := loadConfigCase(t, "api-key-auth")
			test.edit(&c)
			for _, operation := range []struct {
				name string
				run  func(Config) error
			}{
				{name: "validate", run: Config.Validate},
				{name: "Envoy", run: func(c Config) error { _, err := Generate(c); return err }},
				{name: "Kubernetes", run: func(c Config) error { _, err := GenerateKubernetes(c); return err }},
				{name: "collector", run: func(c Config) error { _, err := GenerateOTelCollectorConfig(c); return err }},
			} {
				t.Run(operation.name, func(t *testing.T) {
					err := operation.run(c)
					if err == nil || !strings.Contains(err.Error(), test.field) || !strings.Contains(err.Error(), `"z-missing"`) {
						t.Fatalf("error = %v, want %s to report the first configured reference", err, test.field)
					}
				})
			}
		})
	}
}

func TestResolvedReferencesDoNotAliasInput(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*Config)
	}{
		{name: "API route", edit: func(c *Config) { c.APIs[0].Routes[0].Path.Exact = "/changed" }},
		{name: "authenticator", edit: func(c *Config) { c.Authenticators[0].JWT.Issuer = "https://changed.jwt.test" }},
		{name: "attribute source", edit: func(c *Config) {
			c.Authenticators[0].Attributes["tenant_id"] = AttributeSource{ClaimPath: []string{"changed"}}
		}},
		{name: "grant allowlist", edit: func(c *Config) { c.AuthorizationPolicies[0].Grants[0].Attributes["tenant_id"][0] = "changed" }},
		{name: "server", edit: func(c *Config) { c.Servers[2].Hostname = "changed.gateway.test" }},
		{name: "API binding", edit: func(c *Config) { c.Servers[2].APIs[0] = "public" }},
		{name: "authenticator binding", edit: func(c *Config) { slices.Reverse(c.Servers[2].Authentication.AnyOf) }},
		{name: "policy binding", edit: func(c *Config) { slices.Reverse(c.Servers[2].Authorization.AnyOf) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := loadConfigCase(t, "api-key-auth")
			effective := resolveTestConfig(t, c)
			before, err := generate(effective)
			if err != nil {
				t.Fatal(err)
			}
			test.edit(&c)
			after, err := generate(effective)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, after) {
				t.Fatal("changing the caller's configuration changed resolved output")
			}
		})
	}
}

func TestGenerationCanReuseResolvedConfiguration(t *testing.T) {
	for _, fixture := range []string{"jwt-auth-with-attributes", "api-key-auth", "mtls-auth"} {
		t.Run(fixture, func(t *testing.T) {
			c := resolveTestConfig(t, loadConfigCase(t, fixture))
			before, err := yaml.Marshal(c.Config)
			if err != nil {
				t.Fatal(err)
			}
			first, err := generate(c)
			if err != nil {
				t.Fatal(err)
			}
			second, err := generate(c)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(first, second) {
				t.Fatal("reusing resolved configuration changed generated output")
			}
			after, err := yaml.Marshal(c.Config)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("generation changed the resolved configuration")
			}
		})
	}
}

func TestResolvedJWTRequirementsFollowSelectionOrder(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-multiple-issuers")
	c.Servers[0].Authentication.AnyOf = []string{"issuer-two", "issuer-one"}
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	manager := firstHTTPManager(t, files.EnvoyBootstrap.Contents)
	var authentication jwt.JwtAuthentication
	for _, filter := range manager.HttpFilters {
		if filter.Name == "envoy.filters.http.jwt_authn" {
			if err := filter.GetTypedConfig().UnmarshalTo(&authentication); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	requirements := authentication.RequirementMap["server-0"].GetRequiresAny().GetRequirements()
	if len(requirements) != 2 || requirements[0].GetProviderName() != "issuer-two" || requirements[1].GetProviderName() != "issuer-one" {
		t.Fatalf("JWT requirements = %v, want issuer-two followed by issuer-one", requirements)
	}
}

func resolveTestConfig(t testing.TB, c Config) effectiveConfig {
	t.Helper()
	effective, err := resolveConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	return effective
}
