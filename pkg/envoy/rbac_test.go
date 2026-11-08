package envoy

import (
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	rbac "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	configuration "github.com/rhobs/auth-gateway/pkg/config"
)

func TestJWKSValidationIncludesUnusedProviders(t *testing.T) {
	tests := []struct {
		name  string
		edit  func(*gatewayapi.Config)
		field string
	}{
		{"zero", func(c *gatewayapi.Config) { c.Authenticators[0].JWT.JWKS.CacheDuration = duration(0) }, ".cache_duration"},
		{"negative Go duration", func(c *gatewayapi.Config) { c.Authenticators[0].JWT.JWKS.CacheDuration = duration(-time.Second) }, ".cache_duration"},
		{"connect exceeds fetch", func(c *gatewayapi.Config) { c.Authenticators[0].JWT.JWKS.ConnectTimeout = duration(6 * time.Second) }, ".connect_timeout"},
		{"empty CA", func(c *gatewayapi.Config) { c.Authenticators[0].JWT.JWKS.TrustedCA = &gatewayapi.TrustedCA{} }, ".trusted_ca"},
		{"both sources", func(c *gatewayapi.Config) {
			c.Authenticators[0].JWT.JWKS.TrustedCA = &gatewayapi.TrustedCA{Filename: "/ca.pem", ConfigMap: &gatewayapi.CAConfigMap{Name: "ca", Key: "ca.pem"}}
		}, ".trusted_ca"},
		{"ConfigMap without Kubernetes", func(c *gatewayapi.Config) {
			c.Kubernetes = nil
			c.Authenticators[0].JWT.JWKS.TrustedCA = &gatewayapi.TrustedCA{ConfigMap: &gatewayapi.CAConfigMap{Name: "ca", Key: "ca.pem"}}
		}, ".trusted_ca.config_map"},
		{"bad ConfigMap name", func(c *gatewayapi.Config) {
			c.Authenticators[0].JWT.JWKS.TrustedCA = &gatewayapi.TrustedCA{ConfigMap: &gatewayapi.CAConfigMap{Name: "bad/name", Key: "ca.pem"}}
		}, ".trusted_ca.config_map.name"},
		{"bad key", func(c *gatewayapi.Config) {
			c.Authenticators[0].JWT.JWKS.TrustedCA = &gatewayapi.TrustedCA{ConfigMap: &gatewayapi.CAConfigMap{Name: "ca", Key: "../ca.pem"}}
		}, ".trusted_ca.config_map.key"},
		{"relative file", func(c *gatewayapi.Config) {
			c.Kubernetes = nil
			c.Authenticators[0].JWT.JWKS.TrustedCA = &gatewayapi.TrustedCA{Filename: "ca.pem"}
		}, ".trusted_ca.filename"},
		{"relative file in Kubernetes", func(c *gatewayapi.Config) {
			c.Authenticators[0].JWT.JWKS.TrustedCA = &gatewayapi.TrustedCA{Filename: "ca.pem"}
		}, ".trusted_ca.filename"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := loadConfigCase(t, "jwt-auth")
			c.Servers[0].Authentication = nil
			c.Servers[0].Authorization = nil
			tt.edit(&c)
			if err := configuration.Validate(c); err == nil || !strings.Contains(err.Error(), "authenticators[0].jwt.jwks"+tt.field) {
				t.Fatalf("validation = %v", err)
			}
		})
	}
	c := loadConfigCase(t, "jwt-auth")
	c.Kubernetes = nil
	c.Authenticators[0].JWT.JWKS.TrustedCA = &gatewayapi.TrustedCA{Filename: "/etc/company/ca.crt"}
	if _, err := Generate(c); err != nil {
		t.Fatal(err)
	}
	c = loadConfigCase(t, "server-tls")
	c.Servers[1].TLSConfig.Certificate = configuration.CaDirectory + "/roots/tls.crt"
	c.Servers[1].TLSConfig.PrivateKey = configuration.CaDirectory + "/roots/tls.key"
	if err := configuration.Validate(c); err == nil || !strings.Contains(err.Error(), configuration.CaDirectory) {
		t.Fatalf("reserved CA mount tree: %v", err)
	}
}

func TestRequiredHeaderRBACRulesRejectsEmptyMappings(t *testing.T) {
	_, err := requiredHeaderRBACRules(nil)
	if err == nil || !strings.Contains(err.Error(), "at least one request header mapping") {
		t.Fatalf("required header rules error = %v, want empty mapping error", err)
	}
}

func TestJWTHeaderOnlyGrantRequiresNamedVerifiedIssuer(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-multiple-issuers")
	c.Authenticators[0].Attributes["requested_tenant"] = gatewayapi.AttributeSource{Header: new("X-Tenant")}
	c.AuthorizationPolicies[0].Grants[0].Attributes = map[string][]string{"requested_tenant": {"customer-a"}}
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	manager := firstHTTPManager(t, files.EnvoyBootstrap.Contents)
	names := httpFilterNames(manager)
	if slices.Index(names, "envoy.filters.http.header_to_metadata") < 0 ||
		slices.Index(names, "envoy.filters.http.set_filter_state") >= 0 {
		t.Fatalf("header-only grant needs capture but no working attributes: %v", names)
	}
	grant := toGrantPrincipal(resolveTestConfig(t, c), c.AuthorizationPolicies[0].Grants[0]).GetAndIds().GetIds()
	if len(grant) != 2 {
		t.Fatalf("header-only JWT grant principals = %#v", grant)
	}
	header := grant[0].GetSourcedMetadata().GetMetadataMatcher()
	issuer := grant[1].GetSourcedMetadata().GetMetadataMatcher()
	if header.GetFilter() != "auth_gateway.request_headers" ||
		!slices.Equal(metadataMatcherPath(header.GetPath()), []string{"x-tenant"}) ||
		header.GetValue().GetStringMatch().GetExact() != "customer-a" ||
		issuer.GetFilter() != "envoy.filters.http.jwt_authn" ||
		!slices.Equal(metadataMatcherPath(issuer.GetPath()), []string{"issuer-one", "iss"}) ||
		issuer.GetValue().GetStringMatch().GetExact() != "https://issuer-one.jwt.test" {
		t.Fatalf("header-only JWT grant does not bind the named issuer: %#v", grant)
	}
}

func TestJWTAuthorizationReadsOriginalClaimsFromNamedProvider(t *testing.T) {
	c := resolveTestConfig(t, loadConfigCase(t, "jwt-auth-multiple-issuers"))
	rules := toServerRBACRules(c, c.ResolvedServers[0])
	policy := rules.Policies["api-metrics"]
	if policy == nil || len(policy.Principals) != 1 {
		t.Fatalf("API authorization policy = %#v", policy)
	}
	grants := policy.Principals[0].GetOrIds().Ids
	if len(grants) != 2 {
		t.Fatalf("provider grant count = %d, want one for each issuer", len(grants))
	}
	gotValues := make(map[string]string, len(grants))
	for _, grant := range grants {
		claim := grant.GetSourcedMetadata()
		if claim == nil || claim.MetadataSource != rbac.MetadataSource_DYNAMIC || claim.GetMetadataMatcher().GetFilter() != "envoy.filters.http.jwt_authn" {
			t.Fatalf("grant does not use verified JWT metadata: %#v", grant)
		}
		var path []string
		for _, segment := range claim.GetMetadataMatcher().GetPath() {
			path = append(path, segment.GetKey())
		}
		if len(path) != 3 || path[1] != "organization" || path[2] != "id" {
			t.Fatalf("grant claim path = %v, want provider.organization.id", path)
		}
		valueMatcher := claim.GetMetadataMatcher().GetValue()
		branches := valueMatcher.GetOrMatch().GetValueMatchers()
		if len(branches) != 2 || branches[0].GetStringMatch() == nil || branches[1].GetListMatch() == nil {
			t.Fatalf("claim matcher = %#v, want scalar and list branches", valueMatcher)
		}
		listValueMatcher := branches[1].GetListMatch().GetOneOf()
		if listValueMatcher == nil || listValueMatcher.GetStringMatch() == nil {
			t.Fatalf("list matcher = %#v, want an exact string member matcher", branches[1].GetListMatch())
		}
		value := branches[0].GetStringMatch().GetExact()
		if listValueMatcher.GetStringMatch().GetExact() != value {
			t.Fatalf("scalar and list match values = %q and %q", value, listValueMatcher.GetStringMatch().GetExact())
		}
		gotValues[path[0]] = value
	}
	if !reflect.DeepEqual(gotValues, map[string]string{"issuer-one": "customer-a", "issuer-two": "customer-b"}) {
		t.Fatalf("raw provider grants = %v", gotValues)
	}

	config, err := toJWTFilterConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	any := config.RequirementMap[serverJWTRequirementName(0)].GetRequiresAny().Requirements
	if len(any) != 2 || any[0].GetProviderName() != "issuer-one" || any[1].GetProviderName() != "issuer-two" {
		t.Fatalf("alternative issuer requirement = %#v", any)
	}
}

func TestJWTAuthorizationMatchesAnyAllowedListClaimValue(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth")
	c.Authenticators[0].Attributes["my_list"] = gatewayapi.AttributeSource{ClaimPath: []string{"x", "my_list"}}
	grant := c.AuthorizationPolicies[0].Grants[0]
	grant.Attributes = map[string][]string{"my_list": {"y", "z"}}

	principal := toGrantPrincipal(resolveTestConfig(t, c), grant)
	claim := principal.GetSourcedMetadata()
	if claim == nil {
		t.Fatalf("grant principal = %#v, want a JWT metadata matcher", principal)
	}
	var gotPath []string
	for _, segment := range claim.GetMetadataMatcher().GetPath() {
		gotPath = append(gotPath, segment.GetKey())
	}
	if !slices.Equal(gotPath, []string{"internal-jwt", "x", "my_list"}) {
		t.Fatalf("claim path = %v, want internal-jwt.x.my_list", gotPath)
	}

	valueMatcher := claim.GetMetadataMatcher().GetValue()
	branches := valueMatcher.GetOrMatch().GetValueMatchers()
	if len(branches) != 2 || branches[0].GetOrMatch() == nil || branches[1].GetListMatch() == nil {
		t.Fatalf("claim matcher = %#v, want scalar allowlist and list-member branches", valueMatcher)
	}
	scalarValues := branches[0].GetOrMatch().GetValueMatchers()
	listMatcher := branches[1].GetListMatch().GetOneOf()
	if listMatcher == nil || listMatcher.GetOrMatch() == nil {
		t.Fatalf("list matcher = %#v, want an allowlist matcher for list members", branches[1].GetListMatch())
	}
	listValues := listMatcher.GetOrMatch().GetValueMatchers()
	if len(scalarValues) != 2 || len(listValues) != 2 {
		t.Fatalf("scalar/list allowlist lengths = %d/%d, want 2/2", len(scalarValues), len(listValues))
	}
	for i, want := range []string{"y", "z"} {
		if scalarValues[i].GetStringMatch() == nil || scalarValues[i].GetStringMatch().GetExact() != want {
			t.Fatalf("scalar allowlist value %d = %#v, want %q", i, scalarValues[i], want)
		}
		if listValues[i].GetStringMatch() == nil || listValues[i].GetStringMatch().GetExact() != want {
			t.Fatalf("list-member allowlist value %d = %#v, want %q", i, listValues[i], want)
		}
	}
}

func TestJWTAuthorizationPolicyCombinationsAreAPIScoped(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-with-attributes")
	effective := resolveTestConfig(t, c)
	rules := toServerRBACRules(effective, effective.ResolvedServers[0])
	if rules.Policies["api-metrics-write"] == nil || rules.Policies["api-logs"] == nil {
		t.Fatalf("any_of policies did not generate both granted API rules: %#v", rules.Policies)
	}
	metricsGrants := rules.Policies["api-metrics-write"].Principals[0].GetOrIds().Ids
	if len(metricsGrants) != 2 {
		t.Fatalf("metrics API grant principals = %d, want one grant from each issuer", len(metricsGrants))
	}

	c.Servers[0].Authorization = &gatewayapi.Authorization{AllOf: []string{"metrics-writers", "logs-writers"}}
	effective = resolveTestConfig(t, c)
	rules = toServerRBACRules(effective, effective.ResolvedServers[0])
	if rules.Policies["api-metrics-write"] != nil || rules.Policies["api-logs"] != nil {
		t.Fatalf("all_of policies for disjoint APIs granted access: %#v", rules.Policies)
	}
	if rules.Policies["local-responses"] == nil {
		t.Fatal("all_of denied APIs but removed local 404/405 responses")
	}
}
