package config

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	rbac "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
)

func TestRequiredHeaderRBACRulesRejectsEmptyMappings(t *testing.T) {
	_, err := requiredHeaderRBACRules(nil)
	if err == nil || !strings.Contains(err.Error(), "at least one request header mapping") {
		t.Fatalf("required header rules error = %v, want empty mapping error", err)
	}
}

func TestJWTHeaderOnlyGrantRequiresNamedVerifiedIssuer(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-multiple-issuers")
	c.Authenticators[0].Attributes["requested_tenant"] = AttributeSource{Header: new("X-Tenant")}
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
	grant := resolveTestConfig(t, c).toGrantPrincipal(c.AuthorizationPolicies[0].Grants[0]).GetAndIds().GetIds()
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
	rules := c.toServerRBACRules(c.servers[0])
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

	config, err := c.toJWTFilterConfig()
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
	c.Authenticators[0].Attributes["my_list"] = AttributeSource{ClaimPath: []string{"x", "my_list"}}
	grant := c.AuthorizationPolicies[0].Grants[0]
	grant.Attributes = map[string][]string{"my_list": {"y", "z"}}

	principal := resolveTestConfig(t, c).toGrantPrincipal(grant)
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
	rules := effective.toServerRBACRules(effective.servers[0])
	if rules.Policies["api-metrics-write"] == nil || rules.Policies["api-logs"] == nil {
		t.Fatalf("any_of policies did not generate both granted API rules: %#v", rules.Policies)
	}
	metricsGrants := rules.Policies["api-metrics-write"].Principals[0].GetOrIds().Ids
	if len(metricsGrants) != 2 {
		t.Fatalf("metrics API grant principals = %d, want one grant from each issuer", len(metricsGrants))
	}

	c.Servers[0].Authorization = &Authorization{AllOf: []string{"metrics-writers", "logs-writers"}}
	effective = resolveTestConfig(t, c)
	rules = effective.toServerRBACRules(effective.servers[0])
	if rules.Policies["api-metrics-write"] != nil || rules.Policies["api-logs"] != nil {
		t.Fatalf("all_of policies for disjoint APIs granted access: %#v", rules.Policies)
	}
	if rules.Policies["local-responses"] == nil {
		t.Fatal("all_of denied APIs but removed local 404/405 responses")
	}
}
