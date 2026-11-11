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
	want := &gatewayapi.FaultInjectionConfig{Enabled: true, Abort: &gatewayapi.FaultAbortConfig{HTTPStatus: http.StatusServiceUnavailable, Percentage: 25}}
	assertConfigDiff(t, "fault injection", want, c.Servers[0].APIs[0].FaultInjection)
	if c.Servers[0].APIs[1].FaultInjection != nil {
		t.Fatal("unconfigured binding gained fault injection")
	}
}

func TestFaultInjectionValidation(t *testing.T) {
	for _, test := range []struct {
		name, field string
		edit        func(*gatewayapi.FaultInjectionConfig)
	}{
		{"missing abort", "abort", func(c *gatewayapi.FaultInjectionConfig) { c.Abort = nil }},
		{"status below 400", "abort.http_status", func(c *gatewayapi.FaultInjectionConfig) { c.Abort.HTTPStatus = 399 }},
		{"status above 599", "abort.http_status", func(c *gatewayapi.FaultInjectionConfig) { c.Abort.HTTPStatus = 600 }},
		{"zero percentage", "abort.percentage", func(c *gatewayapi.FaultInjectionConfig) { c.Abort.Percentage = 0 }},
		{"percentage above 100", "abort.percentage", func(c *gatewayapi.FaultInjectionConfig) { c.Abort.Percentage = 101 }},
		{"invalid disabled policy", "abort.percentage", func(c *gatewayapi.FaultInjectionConfig) { c.Enabled = false; c.Abort.Percentage = 0 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := loadConfigCase(t, "fault-injection")
			test.edit(c.Servers[0].APIs[0].FaultInjection)
			want := "servers[0].apis[0].fault_injection." + test.field
			if err := Validate(c); err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("validation error = %v, want %q", err, want)
			}
		})
	}
}

func TestFaultInjectionDefaultsCloneInput(t *testing.T) {
	c := loadConfigCase(t, "fault-injection")
	defaulted := withDefaultsConfig(c)
	defaulted.Servers[0].APIs[0].FaultInjection.Abort.Percentage = 50
	if c.Servers[0].APIs[0].FaultInjection.Abort.Percentage != 25 {
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
		Headers: []gatewayapi.MatchExpression{{Name: "X-Inject-Fault", Expression: gatewayapi.ExpressionEquals, Value: gatewayapi.MatchValue{Text: "true"}}},
		Attributes: []gatewayapi.MatchExpression{
			{Name: "tenant_id", Expression: gatewayapi.ExpressionIn, Value: gatewayapi.MatchValue{Items: []string{"tenant-a", "tenant-c"}, IsList: true}},
			{Name: "writer_id", Expression: gatewayapi.ExpressionEquals, Value: gatewayapi.MatchValue{Text: "writer-a"}},
		},
	}
	assertConfigDiff(t, "fault selectors", want, c.Servers[0].APIs[0].FaultInjection.Match)
}

func TestFaultMatchDefaultsCloneInput(t *testing.T) {
	c := faultSelectorConfig(t)
	defaulted := withDefaultsConfig(c)
	match := defaulted.Servers[0].APIs[0].FaultInjection.Match
	match.Headers[0].Value.Text = "changed"
	match.Attributes[0].Value.Items[0] = "changed"
	match.Attributes[1].Value.Text = "changed"
	original := c.Servers[0].APIs[0].FaultInjection.Match
	if original.Headers[0].Value.Text != "true" || original.Attributes[0].Value.Items[0] != "tenant-a" || original.Attributes[1].Value.Text != "writer-a" {
		t.Fatal("defaulting aliased the caller's fault selectors")
	}
}

func TestFaultMatchValidation(t *testing.T) {
	for _, test := range []struct {
		name, field string
		edit        func(*gatewayapi.FaultMatchConfig)
	}{
		{"empty match", "match must contain", func(c *gatewayapi.FaultMatchConfig) { *c = gatewayapi.FaultMatchConfig{} }},
		{"invalid header", "match.headers[0]", func(c *gatewayapi.FaultMatchConfig) { c.Headers[0].Name = ":path" }},
		{"credential header", "match.headers[0]", func(c *gatewayapi.FaultMatchConfig) { c.Headers[0].Name = "Authorization" }},
		{"internal header", "match.headers[0]", func(c *gatewayapi.FaultMatchConfig) { c.Headers[0].Name = "X-Auth-Gateway-Tenant" }},
		{"duplicate header case", "match.headers[1]", func(c *gatewayapi.FaultMatchConfig) {
			c.Headers = append(c.Headers, gatewayapi.MatchExpression{Name: "x-inject-fault", Expression: gatewayapi.ExpressionPresent})
		}},
		{"empty header value", "match.headers[0].value", func(c *gatewayapi.FaultMatchConfig) { c.Headers[0].Value.Text = "" }},
		{"invalid header expression", "match.headers[0].expression", func(c *gatewayapi.FaultMatchConfig) { c.Headers[0].Expression = gatewayapi.ExpressionHas }},
		{"present with value", "match.headers[0].value", func(c *gatewayapi.FaultMatchConfig) { c.Headers[0].Expression = gatewayapi.ExpressionPresent }},
		{"invalid attribute name", "match.attributes[0]", func(c *gatewayapi.FaultMatchConfig) { c.Attributes[0].Name = "Tenant" }},
		{"duplicate attribute", "match.attributes[2]", func(c *gatewayapi.FaultMatchConfig) { c.Attributes = append(c.Attributes, c.Attributes[0]) }},
		{"empty values", "match.attributes[0].value", func(c *gatewayapi.FaultMatchConfig) { c.Attributes[0].Value.Items = nil }},
		{"duplicate values", "match.attributes[0].value", func(c *gatewayapi.FaultMatchConfig) { c.Attributes[0].Value.Items[1] = "tenant-a" }},
		{"invalid attribute expression", "match.attributes[0].expression", func(c *gatewayapi.FaultMatchConfig) { c.Attributes[0].Expression = gatewayapi.ExpressionHasOneOf }},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := faultSelectorConfig(t)
			test.edit(c.Servers[0].APIs[0].FaultInjection.Match)
			want := "servers[0].apis[0].fault_injection." + test.field
			if err := Validate(c); err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("validation error = %v, want %q", err, want)
			}
		})
	}
}

func TestFaultMatchReferences(t *testing.T) {
	for _, test := range []struct {
		name, want string
		edit       func(*gatewayapi.Config)
	}{
		{"API key trigger", "match.headers[0] is reserved", func(c *gatewayapi.Config) {
			c.Servers[0].APIs[0].FaultInjection.Match.Headers[0].Name = "X-Partner-Key"
		}},
		{"overwritten trigger", "match.headers[0] is overwritten", func(c *gatewayapi.Config) {
			c.APIs[0].Routes[0].Processing = &gatewayapi.RouteProcessing{RequestHeaders: []gatewayapi.RequestHeaderMapping{{Name: "x-inject-fault", FromAttribute: "tenant_id"}}}
		}},
		{"unknown attribute", "fault_injection.match.attributes.unknown", func(c *gatewayapi.Config) { c.Servers[0].APIs[0].FaultInjection.Match.Attributes[0].Name = "unknown" }},
		{"unbound provider", "fault_injection.match.attributes.writer_id", func(c *gatewayapi.Config) { removeTestAttribute(&c.Authenticators[1], "writer_id") }},
		{"public binding", "fault_injection.match.attributes.tenant_id", func(c *gatewayapi.Config) { c.Servers[0].APIs[0].Public = true; c.Servers[0].APIs[0].Access = nil }},
		{"request header source", "fault_injection.match.attributes.requested_tenant requires an identity attribute", func(c *gatewayapi.Config) {
			c.Servers[0].APIs[0].FaultInjection.Match.Attributes[0].Name = "requested_tenant"
		}},
		{"invalid disabled match", "fault_injection.match.attributes.unknown", func(c *gatewayapi.Config) {
			c.Servers[0].APIs[0].FaultInjection.Enabled = false
			c.Servers[0].APIs[0].FaultInjection.Match.Attributes[0].Name = "unknown"
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
		{name: "omitted", edit: func(c *gatewayapi.Config) { c.Servers[0].APIs[0].FaultInjection = nil }},
		{name: "disabled", edit: func(c *gatewayapi.Config) { c.Servers[0].APIs[0].FaultInjection.Enabled = false }},
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
	chain := global.GetNamedFilterChains()["server-0-api-0"].GetTypedConfig()
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
		if action.GetFilterChainName() != "server-0-api-0" {
			t.Fatalf("route %q selects fault chain %q, want server-0-api-0", name, action.GetFilterChainName())
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
	c.Servers[0].APIs[0].FaultInjection = &gatewayapi.FaultInjectionConfig{Enabled: true, Abort: &gatewayapi.FaultAbortConfig{
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
		if host.Name != "auth.example.com" {
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
	if configured != 1 || unconfigured != 2 {
		t.Fatalf("configured/unconfigured managers = %d/%d, want 1/2", configured, unconfigured)
	}
}

func TestFaultInjectionUsesDistinctPoliciesForSameAPIOnDifferentServers(t *testing.T) {
	c := faultSelectorConfig(t)
	other := cloneAPIBinding(c.Servers[0].APIs[0])
	other.FaultInjection.Abort.HTTPStatus = http.StatusTooManyRequests
	c.Servers = append(c.Servers, gatewayapi.Server{Hostname: "fault-other.example.com", APIs: []gatewayapi.APIBinding{other}})
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	manager := firstGeneratedHTTPManager(t, files.EnvoyBootstrap.Contents)
	index := slices.Index(httpFilterNames(manager), faultCompositeFilterName)
	var global composite.Composite
	if err := manager.GetHttpFilters()[index].GetTypedConfig().UnmarshalTo(&global); err != nil {
		t.Fatal(err)
	}
	if len(global.GetNamedFilterChains()) != 2 {
		t.Fatalf("fault chains = %d, want one for each server binding", len(global.GetNamedFilterChains()))
	}
	for _, test := range []struct {
		chain  string
		status uint32
	}{
		{"server-0-api-0", http.StatusServiceUnavailable},
		{"server-1-api-0", http.StatusTooManyRequests},
	} {
		chain := global.GetNamedFilterChains()[test.chain]
		if chain == nil {
			t.Fatalf("fault chain %q is missing", test.chain)
		}
		var policy fault.HTTPFault
		if err := chain.GetTypedConfig()[0].GetTypedConfig().UnmarshalTo(&policy); err != nil {
			t.Fatal(err)
		}
		if policy.GetAbort().GetHttpStatus() != test.status {
			t.Fatalf("fault chain %q returns %d, want %d", test.chain, policy.GetAbort().GetHttpStatus(), test.status)
		}
	}
}

func TestFaultInjectionPreservesRouteHeaderProcessing(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-with-headers")
	c.Servers[0].APIs[0].FaultInjection = &gatewayapi.FaultInjectionConfig{Enabled: true, Abort: &gatewayapi.FaultAbortConfig{
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
	route := namedRoute(manager.GetRouteConfig().GetVirtualHosts()[0].GetRoutes(), "api-0-metrics-route-0-method-0-access-0-match-0")
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
	for _, name := range []string{jwtAuthnFilterName, apiKeyFilterName, attributeFilterName, authorizationFilterName} {
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
	if err := config.GetNamedFilterChains()["server-0-api-0"].GetTypedConfig()[0].GetTypedConfig().UnmarshalTo(&policy); err != nil {
		t.Fatal(err)
	}
	if len(policy.Headers) != 1 || policy.Headers[0].Name != "x-inject-fault" || policy.Headers[0].GetStringMatch().GetExact() != "true" ||
		policy.GetAbort().GetHttpStatus() != http.StatusServiceUnavailable || policy.GetAbort().GetHeaderAbort() != nil {
		t.Fatalf("native fault policy = %v, want exact trigger and configured status", &policy)
	}
	generatedRoute := namedRoute(manager.GetRouteConfig().GetVirtualHosts()[0].GetRoutes(), "api-0-injected-route-0-method-0-access-0-match-0")
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

func TestGeneratedFaultMatchSupportsInAndPresent(t *testing.T) {
	c := faultSelectorConfig(t)
	match := c.Servers[0].APIs[0].FaultInjection.Match
	match.Headers = []gatewayapi.MatchExpression{
		{Name: "X-Inject-Fault", Expression: gatewayapi.ExpressionIn, Value: gatewayapi.MatchValue{Items: []string{"true", "a.b"}, IsList: true}},
		{Name: "X-Fault-Test", Expression: gatewayapi.ExpressionPresent},
	}
	match.Attributes = []gatewayapi.MatchExpression{{Name: "writer_id", Expression: gatewayapi.ExpressionPresent}}
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	manager := firstGeneratedHTTPManager(t, files.EnvoyBootstrap.Contents)
	var global composite.Composite
	filter := manager.GetHttpFilters()[slices.Index(httpFilterNames(manager), faultCompositeFilterName)]
	if err := filter.GetTypedConfig().UnmarshalTo(&global); err != nil {
		t.Fatal(err)
	}
	var policy fault.HTTPFault
	if err := global.GetNamedFilterChains()["server-0-api-0"].GetTypedConfig()[0].GetTypedConfig().UnmarshalTo(&policy); err != nil {
		t.Fatal(err)
	}
	if len(policy.Headers) != 2 || policy.Headers[0].Name != "x-fault-test" || !policy.Headers[0].GetPresentMatch() ||
		policy.Headers[1].Name != "x-inject-fault" || policy.Headers[1].GetStringMatch().GetSafeRegex().GetRegex() != `^(?:true|a\.b)$` {
		t.Fatalf("fault header conditions = %v", policy.Headers)
	}
	route := namedRoute(manager.GetRouteConfig().GetVirtualHosts()[0].GetRoutes(), "api-0-injected-route-0-method-0-access-0-match-0")
	var selector composite.CompositePerRoute
	if err := route.GetTypedPerFilterConfig()[faultCompositeFilterName].UnmarshalTo(&selector); err != nil {
		t.Fatal(err)
	}
	predicate := selector.GetMatcher().GetMatcherList().GetMatchers()[0].GetPredicate().GetSinglePredicate()
	if predicate.GetValueMatch().GetSafeRegex().GetRegex() != ".+" {
		t.Fatalf("attribute presence matcher = %v, want nonempty value", predicate.GetValueMatch())
	}
}

func TestFaultMatchInitializesAttributesWithoutMetrics(t *testing.T) {
	for _, test := range []struct {
		name   string
		filter string
	}{
		{name: "issuer-one", filter: "envoy.filters.http.set_filter_state"},
		{name: "partner-key", filter: "envoy.filters.http.set_filter_state"},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := faultSelectorConfig(t)
			c.APIs[0].Metrics = nil
			index := 0
			if test.name == "partner-key" {
				index = 1
			}
			c.Servers[0].APIs[0].Access = []gatewayapi.Access{c.Servers[0].APIs[0].Access[index]}
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
