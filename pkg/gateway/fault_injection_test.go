package gateway

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	xdsmatcher "github.com/cncf/xds/go/xds/type/matcher/v3"
	composite "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/composite/v3"
	fault "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/fault/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	networkinput "github.com/envoyproxy/go-control-plane/envoy/extensions/matching/common_inputs/network/v3"
	envoytype "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
)

func TestLoadFaultInjection(t *testing.T) {
	c := loadConfigCase(t, "fault-injection")
	want := &gatewayapi.FaultInjectionConfig{Enabled: true, Abort: &gatewayapi.FaultAbortConfig{
		HTTPStatus: http.StatusServiceUnavailable,
		Percentage: 25,
	}}
	assertConfigDiff(t, "fault injection", want, c.APIs[0].FaultInjection)
	if c.APIs[1].FaultInjection != nil {
		t.Fatal("unconfigured API gained fault injection")
	}
}

func TestFaultInjectionValidation(t *testing.T) {
	for _, test := range []struct {
		name  string
		field string
		edit  func(*gatewayapi.FaultInjectionConfig)
	}{
		{name: "missing abort", field: "abort", edit: func(c *gatewayapi.FaultInjectionConfig) { c.Abort = nil }},
		{name: "status below 400", field: "abort.http_status", edit: func(c *gatewayapi.FaultInjectionConfig) { c.Abort.HTTPStatus = 399 }},
		{name: "status above 599", field: "abort.http_status", edit: func(c *gatewayapi.FaultInjectionConfig) { c.Abort.HTTPStatus = 600 }},
		{name: "zero percentage", field: "abort.percentage", edit: func(c *gatewayapi.FaultInjectionConfig) { c.Abort.Percentage = 0 }},
		{name: "percentage above 100", field: "abort.percentage", edit: func(c *gatewayapi.FaultInjectionConfig) { c.Abort.Percentage = 101 }},
		{name: "invalid disabled policy", field: "abort.percentage", edit: func(c *gatewayapi.FaultInjectionConfig) {
			c.Enabled = false
			c.Abort.Percentage = 0
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := loadConfigCase(t, "fault-injection")
			test.edit(c.APIs[0].FaultInjection)
			if err := Validate(c); err == nil || !strings.Contains(err.Error(), "apis[0].fault_injection."+test.field) {
				t.Fatalf("validation error = %v, want field apis[0].fault_injection.%s", err, test.field)
			}
		})
	}
}

func TestFaultInjectionDefaultsCloneInput(t *testing.T) {
	c := loadConfigCase(t, "fault-injection")
	defaulted := withDefaultsConfig(c)
	defaulted.APIs[0].FaultInjection.Abort.Percentage = 50
	if c.APIs[0].FaultInjection.Abort.Percentage != 25 {
		t.Fatal("defaulting aliased the caller's fault policy")
	}
}

func faultSelectorConfig(t testing.TB) gatewayapi.Config {
	t.Helper()
	return loadTestConfig(t, readFixture(t, "fault-selectors.yaml"), "fault selectors")
}

func TestLoadFaultMatchSelectors(t *testing.T) {
	c := faultSelectorConfig(t)
	want := &gatewayapi.FaultMatchConfig{
		Headers:    map[string]string{"X-Inject-Fault": "true"},
		Attributes: map[string][]string{"tenant_id": {"tenant-a", "tenant-c"}, "writer_id": {"writer-a"}},
	}
	assertConfigDiff(t, "fault selectors", want, c.APIs[0].FaultInjection.Match)
}

func TestFaultMatchDefaultsCloneInput(t *testing.T) {
	c := faultSelectorConfig(t)
	defaulted := withDefaultsConfig(c)
	defaulted.APIs[0].FaultInjection.Match.Headers["X-Inject-Fault"] = "changed"
	defaulted.APIs[0].FaultInjection.Match.Attributes["tenant_id"][0] = "changed"
	defaulted.APIs[0].FaultInjection.Match.Attributes["writer_id"] = []string{"changed"}
	want := &gatewayapi.FaultMatchConfig{
		Headers:    map[string]string{"X-Inject-Fault": "true"},
		Attributes: map[string][]string{"tenant_id": {"tenant-a", "tenant-c"}, "writer_id": {"writer-a"}},
	}
	assertConfigDiff(t, "original fault selectors", want, c.APIs[0].FaultInjection.Match)
}

func TestFaultMatchValidation(t *testing.T) {
	for _, test := range []struct {
		name  string
		field string
		edit  func(*gatewayapi.FaultMatchConfig)
	}{
		{name: "empty match", field: "match must contain", edit: func(c *gatewayapi.FaultMatchConfig) { *c = gatewayapi.FaultMatchConfig{} }},
		{name: "invalid header", field: "match.headers", edit: func(c *gatewayapi.FaultMatchConfig) { c.Headers[":path"] = "/" }},
		{name: "credential header", field: "match.headers", edit: func(c *gatewayapi.FaultMatchConfig) { c.Headers["Authorization"] = "test" }},
		{name: "internal header", field: "match.headers", edit: func(c *gatewayapi.FaultMatchConfig) { c.Headers["X-Auth-Gateway-Tenant"] = "test" }},
		{name: "removed header", field: "match.headers", edit: func(c *gatewayapi.FaultMatchConfig) { c.Headers["X-Envoy-Max-Retries"] = "1" }},
		{name: "duplicate header case", field: "match.headers", edit: func(c *gatewayapi.FaultMatchConfig) { c.Headers["x-inject-fault"] = "true" }},
		{name: "empty header value", field: "match.headers.X-Inject-Fault", edit: func(c *gatewayapi.FaultMatchConfig) { c.Headers["X-Inject-Fault"] = "" }},
		{name: "header control character", field: "match.headers.X-Inject-Fault", edit: func(c *gatewayapi.FaultMatchConfig) { c.Headers["X-Inject-Fault"] = "yes\n" }},
		{name: "invalid attribute name", field: "match.attributes", edit: func(c *gatewayapi.FaultMatchConfig) { c.Attributes["Tenant"] = []string{"a"} }},
		{name: "empty values", field: "match.attributes.tenant_id", edit: func(c *gatewayapi.FaultMatchConfig) { c.Attributes["tenant_id"] = nil }},
		{name: "empty attribute value", field: "match.attributes.tenant_id", edit: func(c *gatewayapi.FaultMatchConfig) { c.Attributes["tenant_id"] = []string{""} }},
		{name: "attribute control character", field: "match.attributes.tenant_id", edit: func(c *gatewayapi.FaultMatchConfig) { c.Attributes["tenant_id"] = []string{"a\x7f"} }},
		{name: "duplicate attribute values", field: "match.attributes.tenant_id", edit: func(c *gatewayapi.FaultMatchConfig) { c.Attributes["tenant_id"] = []string{"a", "a"} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := faultSelectorConfig(t)
			test.edit(c.APIs[0].FaultInjection.Match)
			want := "apis[0].fault_injection." + test.field
			if err := Validate(c); err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("validation error = %v, want %q", err, want)
			}
		})
	}
}

func TestFaultMatchReferences(t *testing.T) {
	for _, test := range []struct {
		name string
		want string
		edit func(*gatewayapi.Config)
	}{
		{name: "API key trigger", want: "apis[0].fault_injection.match.headers.X-Partner-Key is reserved", edit: func(c *gatewayapi.Config) {
			c.APIs[0].FaultInjection.Match.Headers["X-Partner-Key"] = "key-a"
		}},
		{name: "overwritten trigger", want: "apis[0].fault_injection.match.headers.X-Inject-Fault is overwritten", edit: func(c *gatewayapi.Config) {
			c.APIs[0].Routes[0].Processing = &gatewayapi.RouteProcessing{RequestHeaders: []gatewayapi.RequestHeaderMapping{{Name: "x-inject-fault", FromAttribute: "tenant_id"}}}
		}},
		{name: "unknown attribute", want: "servers[0] authentication does not provide fault_injection.match.attributes.unknown", edit: func(c *gatewayapi.Config) {
			c.APIs[0].FaultInjection.Match.Attributes["unknown"] = []string{"a"}
		}},
		{name: "unbound provider", want: "servers[0] authentication does not provide fault_injection.match.attributes.writer_id", edit: func(c *gatewayapi.Config) {
			c.Servers[0].Authentication = &gatewayapi.Authentication{AnyOf: []string{"partner-key"}}
			delete(c.Authenticators[1].Attributes, "writer_id")
		}},
		{name: "public binding", want: "servers[0] authentication does not provide fault_injection.match.attributes.tenant_id", edit: func(c *gatewayapi.Config) {
			c.Servers[0].Authentication = nil
			c.Servers[0].Authorization = nil
		}},
		{name: "request header tenant", want: "fault_injection.match.attributes.tenant_id requires an identity attribute", edit: func(c *gatewayapi.Config) {
			c.Authenticators[0].Attributes["tenant_id"] = gatewayapi.AttributeSource{Header: new("X-Tenant-ID")}
		}},
		{name: "invalid disabled match", want: "fault_injection.match.attributes.unknown", edit: func(c *gatewayapi.Config) {
			c.APIs[0].FaultInjection.Enabled = false
			c.APIs[0].FaultInjection.Match.Attributes["unknown"] = []string{"a"}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := faultSelectorConfig(t)
			test.edit(&c)
			if err := Validate(c); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validation error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestFaultInjectionDefaultsOff(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*gatewayapi.Config)
	}{
		{name: "omitted", edit: func(c *gatewayapi.Config) { c.APIs[0].FaultInjection = nil }},
		{name: "disabled", edit: func(c *gatewayapi.Config) { c.APIs[0].FaultInjection.Enabled = false }},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := loadConfigCase(t, "fault-injection")
			test.edit(&c)
			files, err := Generate(c)
			if err != nil {
				t.Fatal(err)
			}
			manager := firstGeneratedHTTPManager(t, files.EnvoyBootstrap.Contents)
			if hasHTTPFilter(manager, faultCompositeFilterName) {
				t.Fatal("fault filter was generated while disabled")
			}
			for _, generatedRoute := range manager.GetRouteConfig().GetVirtualHosts()[0].GetRoutes() {
				if generatedRoute.GetTypedPerFilterConfig()[faultCompositeFilterName] != nil {
					t.Fatalf("route %q gained disabled fault config", generatedRoute.Name)
				}
			}
		})
	}
}

func TestGeneratedFaultInjectionIsScopedToAPI(t *testing.T) {
	c := loadConfigCase(t, "fault-injection")
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	manager := firstGeneratedHTTPManager(t, files.EnvoyBootstrap.Contents)
	filters := manager.GetHttpFilters()
	if len(filters) < 2 || filters[len(filters)-2].Name != faultCompositeFilterName {
		t.Fatalf("HTTP filters = %v, want fault injection before router", httpFilterNames(manager))
	}
	if filters[len(filters)-1].Name != routerFilterName {
		t.Fatalf("last HTTP filter = %q, want router", filters[len(filters)-1].Name)
	}
	var global composite.Composite
	if err := filters[len(filters)-2].GetTypedConfig().UnmarshalTo(&global); err != nil {
		t.Fatal(err)
	}
	if global.GetMatcher() != nil || len(global.GetNamedFilterChains()) != 1 {
		t.Fatalf("global fault policy = %v, want one API chain and no default selector", &global)
	}
	chain := global.GetNamedFilterChains()["injected"].GetTypedConfig()
	if len(chain) != 1 || chain[0].Name != faultFilterName {
		t.Fatalf("fault chain = %v, want one native fault filter", chain)
	}
	var policy fault.HTTPFault
	if err := chain[0].GetTypedConfig().UnmarshalTo(&policy); err != nil {
		t.Fatal(err)
	}
	if policy.GetAbort().GetHttpStatus() != http.StatusServiceUnavailable ||
		policy.GetAbort().GetPercentage().GetNumerator() != 25 ||
		policy.GetAbort().GetPercentage().GetDenominator() != envoytype.FractionalPercent_HUNDRED ||
		!policy.GetDisableDownstreamClusterStats() {
		t.Fatalf("fault policy = %v", &policy)
	}

	routes := manager.GetRouteConfig().GetVirtualHosts()[0].GetRoutes()
	for _, name := range []string{"api-0-injected-route-0-method-0", "api-0-injected-route-0-method-1"} {
		generatedRoute := namedRoute(routes, name)
		if generatedRoute == nil {
			t.Fatalf("route %q is missing", name)
		}
		perRouteConfig := generatedRoute.GetTypedPerFilterConfig()[faultCompositeFilterName]
		if perRouteConfig == nil {
			t.Fatalf("route %q has no fault policy", name)
		}
		var perRoute composite.CompositePerRoute
		if err := perRouteConfig.UnmarshalTo(&perRoute); err != nil {
			t.Fatal(err)
		}
		var action composite.ExecuteFilterAction
		if err := perRoute.GetMatcher().GetOnNoMatch().GetAction().GetTypedConfig().UnmarshalTo(&action); err != nil {
			t.Fatal(err)
		}
		if action.GetFilterChainName() != "injected" {
			t.Fatalf("route %q selects fault chain %q, want injected", name, action.GetFilterChainName())
		}
	}
	for _, generatedRoute := range routes {
		if strings.HasPrefix(generatedRoute.Name, "api-0-injected-") {
			continue
		}
		if generatedRoute.GetTypedPerFilterConfig()[faultCompositeFilterName] != nil {
			t.Fatalf("unconfigured or fallback route %q has fault injection", generatedRoute.Name)
		}
	}
}

func TestFaultInjectionOnlyUsesManagersWithTargetAPI(t *testing.T) {
	c := loadConfigCase(t, "server-tls")
	c.APIs[0].FaultInjection = &gatewayapi.FaultInjectionConfig{Enabled: true, Abort: &gatewayapi.FaultAbortConfig{
		HTTPStatus: http.StatusServiceUnavailable,
		Percentage: 10,
	}}
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := decodeBootstrap(t, files.EnvoyBootstrap.Contents)
	var configured, unconfigured int
	for _, chain := range bootstrap.GetStaticResources().GetListeners()[0].GetFilterChains() {
		manager := decodeHTTPManager(t, chain)
		host := manager.GetRouteConfig().GetVirtualHosts()[0]
		if host.Name == "query.example.com" {
			unconfigured++
			if hasHTTPFilter(manager, faultCompositeFilterName) {
				t.Fatal("fault filter was added to the unrelated HTTPS manager")
			}
			continue
		}
		configured++
		if !hasHTTPFilter(manager, faultCompositeFilterName) {
			t.Fatalf("manager for %q has no fault filter", host.Name)
		}
	}
	if configured != 2 || unconfigured != 1 {
		t.Fatalf("configured/unconfigured managers = %d/%d, want 2/1", configured, unconfigured)
	}
}

func TestFaultInjectionPreservesRouteHeaderProcessing(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-with-headers")
	c.APIs[0].FaultInjection = &gatewayapi.FaultInjectionConfig{Enabled: true, Abort: &gatewayapi.FaultAbortConfig{
		HTTPStatus: http.StatusServiceUnavailable,
		Percentage: 10,
	}}
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	manager := firstHTTPManager(t, files.EnvoyBootstrap.Contents)
	names := httpFilterNames(manager)
	faultIndex := slices.Index(names, faultCompositeFilterName)
	for _, name := range []string{jwtAuthnFilterName, attributeFilterName, authorizationFilterName, requiredHeaderFilterName, headerMutationFilterName} {
		if index := slices.Index(names, name); index < 0 || index >= faultIndex {
			t.Fatalf("filter %q must precede fault injection: %v", name, names)
		}
	}
	route := namedRoute(manager.GetRouteConfig().GetVirtualHosts()[0].GetRoutes(), "api-0-metrics-route-0-method-0")
	if route == nil {
		t.Fatal("processed route is missing")
	}
	for _, name := range []string{faultCompositeFilterName, headerMutationFilterName, requiredHeaderFilterName} {
		if route.GetTypedPerFilterConfig()[name] == nil {
			t.Fatalf("processed route lost %q configuration", name)
		}
	}
}

func firstGeneratedHTTPManager(t *testing.T, data []byte) *hcm.HttpConnectionManager {
	t.Helper()
	bootstrap := decodeBootstrap(t, data)
	return decodeHTTPManager(t, bootstrap.GetStaticResources().GetListeners()[0].GetFilterChains()[0])
}

func TestGeneratedFaultMatchUsesAuthenticatedFilterState(t *testing.T) {
	c := faultSelectorConfig(t)
	c.APIs[0].Metrics = nil
	c.APIs[0].AdmissionControl = &gatewayapi.AdmissionControlConfig{Enabled: true}
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
			c.Servers[0].Authentication = &gatewayapi.Authentication{AnyOf: []string{test.name}}
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
