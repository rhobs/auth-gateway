package config

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	xdsmatcher "github.com/cncf/xds/go/xds/type/matcher/v3"
	composite "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/composite/v3"
	fault "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/fault/v3"
	networkinput "github.com/envoyproxy/go-control-plane/envoy/extensions/matching/common_inputs/network/v3"
)

func faultSelectorConfig(t testing.TB) Config {
	t.Helper()
	return loadTestConfig(t, readFixture(t, "fault-selectors.yaml"), "fault selectors")
}

func TestLoadFaultMatchSelectors(t *testing.T) {
	c := faultSelectorConfig(t)
	want := &FaultMatchConfig{
		Headers:    map[string]string{"X-Inject-Fault": "true"},
		Attributes: map[string][]string{"tenant_id": {"tenant-a", "tenant-c"}, "writer_id": {"writer-a"}},
	}
	assertConfigDiff(t, "fault selectors", want, c.APIs[0].FaultInjection.Match)
}

func TestFaultMatchDefaultsCloneInput(t *testing.T) {
	c := faultSelectorConfig(t)
	defaulted := c.withDefaults()
	defaulted.APIs[0].FaultInjection.Match.Headers["X-Inject-Fault"] = "changed"
	defaulted.APIs[0].FaultInjection.Match.Attributes["tenant_id"][0] = "changed"
	defaulted.APIs[0].FaultInjection.Match.Attributes["writer_id"] = []string{"changed"}
	want := &FaultMatchConfig{
		Headers:    map[string]string{"X-Inject-Fault": "true"},
		Attributes: map[string][]string{"tenant_id": {"tenant-a", "tenant-c"}, "writer_id": {"writer-a"}},
	}
	assertConfigDiff(t, "original fault selectors", want, c.APIs[0].FaultInjection.Match)
}

func TestFaultMatchValidation(t *testing.T) {
	for _, test := range []struct {
		name  string
		field string
		edit  func(*FaultMatchConfig)
	}{
		{name: "empty match", field: "match must contain", edit: func(c *FaultMatchConfig) { *c = FaultMatchConfig{} }},
		{name: "invalid header", field: "match.headers", edit: func(c *FaultMatchConfig) { c.Headers[":path"] = "/" }},
		{name: "credential header", field: "match.headers", edit: func(c *FaultMatchConfig) { c.Headers["Authorization"] = "test" }},
		{name: "internal header", field: "match.headers", edit: func(c *FaultMatchConfig) { c.Headers["X-Auth-Gateway-Tenant"] = "test" }},
		{name: "removed header", field: "match.headers", edit: func(c *FaultMatchConfig) { c.Headers["X-Envoy-Max-Retries"] = "1" }},
		{name: "duplicate header case", field: "match.headers", edit: func(c *FaultMatchConfig) { c.Headers["x-inject-fault"] = "true" }},
		{name: "empty header value", field: "match.headers.X-Inject-Fault", edit: func(c *FaultMatchConfig) { c.Headers["X-Inject-Fault"] = "" }},
		{name: "header control character", field: "match.headers.X-Inject-Fault", edit: func(c *FaultMatchConfig) { c.Headers["X-Inject-Fault"] = "yes\n" }},
		{name: "invalid attribute name", field: "match.attributes", edit: func(c *FaultMatchConfig) { c.Attributes["Tenant"] = []string{"a"} }},
		{name: "empty values", field: "match.attributes.tenant_id", edit: func(c *FaultMatchConfig) { c.Attributes["tenant_id"] = nil }},
		{name: "empty attribute value", field: "match.attributes.tenant_id", edit: func(c *FaultMatchConfig) { c.Attributes["tenant_id"] = []string{""} }},
		{name: "attribute control character", field: "match.attributes.tenant_id", edit: func(c *FaultMatchConfig) { c.Attributes["tenant_id"] = []string{"a\x7f"} }},
		{name: "duplicate attribute values", field: "match.attributes.tenant_id", edit: func(c *FaultMatchConfig) { c.Attributes["tenant_id"] = []string{"a", "a"} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := faultSelectorConfig(t)
			test.edit(c.APIs[0].FaultInjection.Match)
			want := "apis[0].fault_injection." + test.field
			if err := c.Validate(); err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("validation error = %v, want %q", err, want)
			}
		})
	}
}

func TestFaultMatchReferences(t *testing.T) {
	for _, test := range []struct {
		name string
		want string
		edit func(*Config)
	}{
		{name: "API key trigger", want: "apis[0].fault_injection.match.headers.X-Partner-Key is reserved", edit: func(c *Config) {
			c.APIs[0].FaultInjection.Match.Headers["X-Partner-Key"] = "key-a"
		}},
		{name: "overwritten trigger", want: "apis[0].fault_injection.match.headers.X-Inject-Fault is overwritten", edit: func(c *Config) {
			c.APIs[0].Routes[0].Processing = &RouteProcessing{RequestHeaders: []RequestHeaderMapping{{Name: "x-inject-fault", FromAttribute: "tenant_id"}}}
		}},
		{name: "unknown attribute", want: "servers[0] authentication does not provide fault_injection.match.attributes.unknown", edit: func(c *Config) {
			c.APIs[0].FaultInjection.Match.Attributes["unknown"] = []string{"a"}
		}},
		{name: "unbound provider", want: "servers[0] authentication does not provide fault_injection.match.attributes.writer_id", edit: func(c *Config) {
			c.Servers[0].Authentication = &Authentication{AnyOf: []string{"partner-key"}}
			delete(c.Authenticators[1].Attributes, "writer_id")
		}},
		{name: "public binding", want: "servers[0] authentication does not provide fault_injection.match.attributes.tenant_id", edit: func(c *Config) {
			c.Servers[0].Authentication = nil
			c.Servers[0].Authorization = nil
		}},
		{name: "request header tenant", want: "fault_injection.match.attributes.tenant_id requires an identity attribute", edit: func(c *Config) {
			c.Authenticators[0].Attributes["tenant_id"] = AttributeSource{Header: new("X-Tenant-ID")}
		}},
		{name: "invalid disabled match", want: "fault_injection.match.attributes.unknown", edit: func(c *Config) {
			c.APIs[0].FaultInjection.Enabled = false
			c.APIs[0].FaultInjection.Match.Attributes["unknown"] = []string{"a"}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := faultSelectorConfig(t)
			test.edit(&c)
			if err := c.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validation error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestGeneratedFaultMatchUsesAuthenticatedFilterState(t *testing.T) {
	c := faultSelectorConfig(t)
	c.APIs[0].Metrics = nil
	c.APIs[0].AdmissionControl = &AdmissionControlConfig{Enabled: true}
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	manager := firstGeneratedHTTPManager(t, files.EnvoyBootstrap.Contents)
	names := httpFilterNames(manager)
	faultIndex := slices.Index(names, faultCompositeFilterName)
	for _, name := range []string{jwtAuthnFilterName, apiKeyFilterName, attributeInitializationFilterName(0), authorizationFilterName} {
		if index := slices.Index(names, name); index < 0 || index >= faultIndex {
			t.Fatalf("filter %q must precede fault injection: %v", name, names)
		}
	}
	if index := slices.Index(names, admissionCompositeFilterName); index <= faultIndex {
		t.Fatalf("admission control must follow fault injection: %v", names)
	}
	var config composite.Composite
	if err := manager.GetHttpFilters()[faultIndex].GetTypedConfig().UnmarshalTo(&config); err != nil {
		t.Fatal(err)
	}
	var policy fault.HTTPFault
	if err := config.GetNamedFilterChains()["injected"].GetTypedConfig()[0].GetTypedConfig().UnmarshalTo(&policy); err != nil {
		t.Fatal(err)
	}
	if len(policy.Headers) != 1 || policy.Headers[0].Name != "x-inject-fault" || policy.Headers[0].GetStringMatch().GetExact() != "true" ||
		policy.GetAbort().GetHttpStatus() != http.StatusServiceUnavailable || policy.GetAbort().GetHeaderAbort() != nil {
		t.Fatalf("native fault policy = %v, want exact trigger and configured status", &policy)
	}
	generatedRoute := namedRoute(manager.GetRouteConfig().GetVirtualHosts()[0].GetRoutes(), "api-0-injected-route-0-method-0")
	var selector composite.CompositePerRoute
	if err := generatedRoute.GetTypedPerFilterConfig()[faultCompositeFilterName].UnmarshalTo(&selector); err != nil {
		t.Fatal(err)
	}
	if selector.GetMatcher().GetOnNoMatch() != nil {
		t.Fatal("unmatched attributes must not select a fault")
	}
	fields := selector.GetMatcher().GetMatcherList().GetMatchers()
	if len(fields) != 1 {
		t.Fatalf("fault selector fields = %v, want one conjunction", fields)
	}
	predicates := fields[0].GetPredicate().GetAndMatcher().GetPredicate()
	if len(predicates) != 2 {
		t.Fatalf("attribute predicates = %v, want tenant and writer", predicates)
	}
	tenants := predicates[0].GetOrMatcher().GetPredicate()
	if len(tenants) != 2 {
		t.Fatalf("tenant predicates = %v, want two alternatives", tenants)
	}
	assertFaultAttributePredicate(t, tenants[0], "auth_gateway.attributes.tenant_id", "tenant-a")
	assertFaultAttributePredicate(t, tenants[1], "auth_gateway.attributes.tenant_id", "tenant-c")
	assertFaultAttributePredicate(t, predicates[1], "auth_gateway.attributes.writer_id", "writer-a")
}

func TestFaultMatchInitializesAttributesWithoutMetrics(t *testing.T) {
	for _, test := range []struct {
		name   string
		filter string
	}{
		{name: "issuer-one", filter: "envoy.filters.http.set_filter_state"},
		{name: "partner-key", filter: "auth_gateway.attributes.server-0"},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := faultSelectorConfig(t)
			c.APIs[0].Metrics = nil
			c.Servers[0].Authentication = &Authentication{AnyOf: []string{test.name}}
			files, err := Generate(c)
			if err != nil {
				t.Fatal(err)
			}
			manager := firstGeneratedHTTPManager(t, files.EnvoyBootstrap.Contents)
			if !hasHTTPFilter(manager, test.filter) {
				t.Fatalf("HTTP filters = %v, want attribute initialization for fault selectors", httpFilterNames(manager))
			}
		})
	}
}

func assertFaultAttributePredicate(t *testing.T, predicate *xdsmatcher.Matcher_MatcherList_Predicate, key, value string) {
	t.Helper()
	single := predicate.GetSinglePredicate()
	var input networkinput.FilterStateInput
	if err := single.GetInput().GetTypedConfig().UnmarshalTo(&input); err != nil {
		t.Fatal(err)
	}
	if input.GetKey() != key || single.GetValueMatch().GetExact() != value {
		t.Fatalf("attribute predicate = %v, want %q equal to %q", single, key, value)
	}
}
