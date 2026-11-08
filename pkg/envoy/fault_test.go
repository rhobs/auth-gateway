package envoy

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
	configuration "github.com/rhobs/auth-gateway/pkg/config"
)

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
	for _, name := range []string{configuration.JwtAuthnFilterName, attributeFilterName, authorizationFilterName, requiredHeaderFilterName, headerMutationFilterName} {
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

func faultSelectorConfig(t testing.TB) gatewayapi.Config {
	t.Helper()
	return loadTestConfig(t, readFixture(t, "fault-selectors.yaml"), "fault selectors")
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
	for _, name := range []string{configuration.JwtAuthnFilterName, apiKeyFilterName, attributeInitializationFilterName(0), authorizationFilterName} {
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
