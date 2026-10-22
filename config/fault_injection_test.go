package config

import (
	"net/http"
	"reflect"
	"strings"
	"testing"

	fault "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/fault/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoytype "github.com/envoyproxy/go-control-plane/envoy/type/v3"
)

func TestLoadFaultInjection(t *testing.T) {
	c := loadConfigCase(t, "fault-injection")
	want := &FaultInjectionConfig{Enabled: true, Abort: &FaultAbortConfig{
		HTTPStatus: http.StatusServiceUnavailable,
		Percentage: 25,
	}}
	assertConfigDiff(t, "fault injection", want, c.APIs[0].FaultInjection)
	if c.APIs[1].FaultInjection != nil {
		t.Fatal("unconfigured API gained fault injection")
	}
}

func TestFaultInjectionDefaultsOff(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*Config)
	}{
		{name: "omitted", edit: func(c *Config) { c.APIs[0].FaultInjection = nil }},
		{name: "disabled", edit: func(c *Config) { c.APIs[0].FaultInjection.Enabled = false }},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := loadConfigCase(t, "fault-injection")
			test.edit(&c)
			files, err := Generate(c)
			if err != nil {
				t.Fatal(err)
			}
			manager := firstGeneratedHTTPManager(t, files.EnvoyBootstrap.Contents)
			if hasHTTPFilter(manager, faultFilterName) {
				t.Fatal("fault filter was generated while disabled")
			}
			for _, generatedRoute := range manager.GetRouteConfig().GetVirtualHosts()[0].GetRoutes() {
				if generatedRoute.GetTypedPerFilterConfig()[faultFilterName] != nil {
					t.Fatalf("route %q gained disabled fault config", generatedRoute.Name)
				}
			}
		})
	}
}

func TestFaultInjectionValidation(t *testing.T) {
	for _, test := range []struct {
		name  string
		field string
		edit  func(*FaultInjectionConfig)
	}{
		{name: "missing abort", field: "abort", edit: func(c *FaultInjectionConfig) { c.Abort = nil }},
		{name: "status below 400", field: "abort.http_status", edit: func(c *FaultInjectionConfig) { c.Abort.HTTPStatus = 399 }},
		{name: "status above 599", field: "abort.http_status", edit: func(c *FaultInjectionConfig) { c.Abort.HTTPStatus = 600 }},
		{name: "zero percentage", field: "abort.percentage", edit: func(c *FaultInjectionConfig) { c.Abort.Percentage = 0 }},
		{name: "percentage above 100", field: "abort.percentage", edit: func(c *FaultInjectionConfig) { c.Abort.Percentage = 101 }},
		{name: "invalid disabled policy", field: "abort.percentage", edit: func(c *FaultInjectionConfig) {
			c.Enabled = false
			c.Abort.Percentage = 0
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := loadConfigCase(t, "fault-injection")
			test.edit(c.APIs[0].FaultInjection)
			if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "apis[0].fault_injection."+test.field) {
				t.Fatalf("validation error = %v, want field apis[0].fault_injection.%s", err, test.field)
			}
		})
	}
}

func TestFaultInjectionDefaultsCloneInput(t *testing.T) {
	c := loadConfigCase(t, "fault-injection")
	defaulted := c.withDefaults()
	defaulted.APIs[0].FaultInjection.Abort.Percentage = 50
	if c.APIs[0].FaultInjection.Abort.Percentage != 25 {
		t.Fatal("defaulting aliased the caller's fault policy")
	}
}

func TestGeneratedFaultInjectionIsFirstAndScopedToAPI(t *testing.T) {
	c := loadConfigCase(t, "fault-injection")
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	manager := firstGeneratedHTTPManager(t, files.EnvoyBootstrap.Contents)
	filters := manager.GetHttpFilters()
	if len(filters) == 0 || filters[0].Name != faultFilterName {
		t.Fatalf("first HTTP filter = %v, want %s", httpFilterNames(manager), faultFilterName)
	}
	if filters[len(filters)-1].Name != routerFilterName {
		t.Fatalf("last HTTP filter = %q, want router", filters[len(filters)-1].Name)
	}
	var global fault.HTTPFault
	if err := filters[0].GetTypedConfig().UnmarshalTo(&global); err != nil {
		t.Fatal(err)
	}
	if global.GetAbort().GetHttpStatus() != http.StatusServiceUnavailable ||
		global.GetAbort().GetPercentage().GetNumerator() != 0 ||
		!global.GetDisableDownstreamClusterStats() {
		t.Fatalf("global fault policy = %v, want a zero-percent fallback", &global)
	}

	routes := manager.GetRouteConfig().GetVirtualHosts()[0].GetRoutes()
	for _, name := range []string{"api-0-injected-route-0-method-0", "api-0-injected-route-0-method-1"} {
		generatedRoute := namedRoute(routes, name)
		if generatedRoute == nil {
			t.Fatalf("route %q is missing", name)
		}
		perRouteConfig := generatedRoute.GetTypedPerFilterConfig()[faultFilterName]
		if perRouteConfig == nil {
			t.Fatalf("route %q has no fault policy", name)
		}
		var perRoute fault.HTTPFault
		if err := perRouteConfig.UnmarshalTo(&perRoute); err != nil {
			t.Fatal(err)
		}
		if perRoute.GetAbort().GetHttpStatus() != http.StatusServiceUnavailable ||
			perRoute.GetAbort().GetPercentage().GetNumerator() != 25 ||
			perRoute.GetAbort().GetPercentage().GetDenominator() != envoytype.FractionalPercent_HUNDRED ||
			!perRoute.GetDisableDownstreamClusterStats() {
			t.Fatalf("route %q fault policy = %v", name, &perRoute)
		}
	}
	for _, generatedRoute := range routes {
		if strings.HasPrefix(generatedRoute.Name, "api-0-injected-") {
			continue
		}
		if generatedRoute.GetTypedPerFilterConfig()[faultFilterName] != nil {
			t.Fatalf("unconfigured or fallback route %q has fault injection", generatedRoute.Name)
		}
	}
}

func TestFaultInjectionOnlyUsesManagersWithTargetAPI(t *testing.T) {
	c := loadConfigCase(t, "server-tls")
	c.APIs[0].FaultInjection = &FaultInjectionConfig{Enabled: true, Abort: &FaultAbortConfig{
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
			if hasHTTPFilter(manager, faultFilterName) {
				t.Fatal("fault filter was added to the unrelated HTTPS manager")
			}
			continue
		}
		configured++
		if manager.GetHttpFilters()[0].Name != faultFilterName {
			t.Fatalf("manager for %q does not start with fault filter", host.Name)
		}
	}
	if configured != 2 || unconfigured != 1 {
		t.Fatalf("configured/unconfigured managers = %d/%d, want 2/1", configured, unconfigured)
	}
}

func TestFaultInjectionPreservesRouteHeaderProcessing(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-with-headers")
	c.APIs[0].FaultInjection = &FaultInjectionConfig{Enabled: true, Abort: &FaultAbortConfig{
		HTTPStatus: http.StatusServiceUnavailable,
		Percentage: 10,
	}}
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	manager := firstHTTPManager(t, files.EnvoyBootstrap.Contents)
	if manager.GetHttpFilters()[0].Name != faultFilterName {
		t.Fatal("fault filter must precede authentication")
	}
	route := namedRoute(manager.GetRouteConfig().GetVirtualHosts()[0].GetRoutes(), "api-0-metrics-route-0-method-0")
	if route == nil {
		t.Fatal("processed route is missing")
	}
	for _, name := range []string{faultFilterName, headerMutationFilterName, requiredHeaderFilterName} {
		if route.GetTypedPerFilterConfig()[name] == nil {
			t.Fatalf("processed route lost %q configuration", name)
		}
	}
}

func TestFaultInjectionToggleChangesOnlyBootstrapConfigMap(t *testing.T) {
	c := loadConfigCase(t, "fault-injection")
	before, err := GenerateKubernetes(c)
	if err != nil {
		t.Fatal(err)
	}
	c.APIs[0].FaultInjection.Enabled = false
	after, err := GenerateKubernetes(c)
	if err != nil {
		t.Fatal(err)
	}
	if before.ConfigMap.Data[envoyConfigFilename] == after.ConfigMap.Data[envoyConfigFilename] {
		t.Fatal("fault toggle did not change the Envoy bootstrap")
	}
	if !reflect.DeepEqual(before.Deployment.Spec.Template, after.Deployment.Spec.Template) {
		t.Fatal("fault toggle changed the Deployment template")
	}
	if len(before.Deployment.Spec.Template.Annotations) != 0 || len(after.Deployment.Spec.Template.Annotations) != 0 {
		t.Fatal("fault toggle added a Deployment checksum annotation")
	}
}

func firstGeneratedHTTPManager(t *testing.T, data []byte) *hcm.HttpConnectionManager {
	t.Helper()
	bootstrap := decodeBootstrap(t, data)
	return decodeHTTPManager(t, bootstrap.GetStaticResources().GetListeners()[0].GetFilterChains()[0])
}
