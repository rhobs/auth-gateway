package config

import (
	"maps"
	"math"
	"slices"
	"strings"
	"testing"
	"time"

	admissioncontrol "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/admission_control/v3"
	composite "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/composite/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"github.com/google/go-cmp/cmp"
)

func TestLoadAPIAdmissionControl(t *testing.T) {
	c := loadConfigCase(t, "admission-control")
	want := &AdmissionControlConfig{
		Enabled: true, SamplingWindow: duration(45 * time.Second), SrThreshold: new(91.5),
		RPSThreshold: new(uint32(25)), MaxRejectionProbability: new(65.0),
	}
	assertConfigDiff(t, "API admission control", want, c.APIs[0].AdmissionControl)
	assertConfigDiff(t, "default tuning", &AdmissionControlConfig{Enabled: true}, c.APIs[1].AdmissionControl)
	if c.APIs[2].AdmissionControl != nil {
		t.Fatal("unconfigured API gained admission control")
	}
	if c.APIs[3].AdmissionControl.Enabled {
		t.Fatal("omitted enabled field opted an API into admission control")
	}
}

func TestLoadEmptyAdmissionControlDefaultsOff(t *testing.T) {
	input := `version: 1
servers:
  - hostname: admission.test
    apis: [plain]
apis:
  - name: plain
    admission_control: {}
    upstream: {address: httpbin, port: 8080}
    routes:
      - methods: [GET]
        path: {exact: /plain}
`
	c, err := Load(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	assertConfigDiff(t, "empty admission block", &AdmissionControlConfig{}, c.APIs[0].AdmissionControl)
}

func TestAdmissionControlRejectsInvalidSettings(t *testing.T) {
	for _, test := range []struct {
		name  string
		field string
		edit  func(*AdmissionControlConfig)
	}{
		{name: "zero window", field: "sampling_window", edit: func(c *AdmissionControlConfig) { c.SamplingWindow = duration(0) }},
		{name: "negative window", field: "sampling_window", edit: func(c *AdmissionControlConfig) { c.SamplingWindow = duration(-time.Second) }},
		{name: "negative success rate", field: "sr_threshold", edit: func(c *AdmissionControlConfig) { c.SrThreshold = new(-1.0) }},
		{name: "success rate above 100", field: "sr_threshold", edit: func(c *AdmissionControlConfig) { c.SrThreshold = new(100.1) }},
		{name: "NaN success rate", field: "sr_threshold", edit: func(c *AdmissionControlConfig) { c.SrThreshold = new(math.NaN()) }},
		{name: "infinite success rate", field: "sr_threshold", edit: func(c *AdmissionControlConfig) { c.SrThreshold = new(math.Inf(1)) }},
		{name: "negative rejection probability", field: "max_rejection_probability", edit: func(c *AdmissionControlConfig) { c.MaxRejectionProbability = new(-1.0) }},
		{name: "rejection probability above 100", field: "max_rejection_probability", edit: func(c *AdmissionControlConfig) { c.MaxRejectionProbability = new(100.1) }},
		{name: "NaN rejection probability", field: "max_rejection_probability", edit: func(c *AdmissionControlConfig) { c.MaxRejectionProbability = new(math.NaN()) }},
		{name: "infinite rejection probability", field: "max_rejection_probability", edit: func(c *AdmissionControlConfig) { c.MaxRejectionProbability = new(math.Inf(-1)) }},
		{name: "invalid disabled policy", field: "sampling_window", edit: func(c *AdmissionControlConfig) {
			c.Enabled = false
			c.SamplingWindow = duration(0)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := loadConfigCase(t, "admission-control")
			test.edit(c.APIs[0].AdmissionControl)
			field := "apis[0].admission_control." + test.field
			if err := c.Validate(); err == nil || !strings.Contains(err.Error(), field) {
				t.Fatalf("validation error = %v, want field %s", err, field)
			}
		})
	}
}

func TestAdmissionControlDefaultsCloneInput(t *testing.T) {
	c := loadConfigCase(t, "admission-control")
	defaulted := c.withDefaults()
	policy := defaulted.APIs[0].AdmissionControl
	policy.Enabled = false
	*policy.SamplingWindow = Duration(time.Minute)
	*policy.SrThreshold = 90
	*policy.RPSThreshold = 10
	*policy.MaxRejectionProbability = 80
	want := &AdmissionControlConfig{
		Enabled: true, SamplingWindow: duration(45 * time.Second), SrThreshold: new(91.5),
		RPSThreshold: new(uint32(25)), MaxRejectionProbability: new(65.0),
	}
	assertConfigDiff(t, "original admission policy", want, c.APIs[0].AdmissionControl)
}

func TestAdmissionControlNamedChains(t *testing.T) {
	c := loadConfigCase(t, "admission-control")
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	manager := firstGeneratedHTTPManager(t, files.EnvoyBootstrap.Contents)
	var count int
	for _, filter := range manager.GetHttpFilters() {
		if filter.Name == "envoy.filters.http.composite" {
			count++
		}
		if filter.Name == "envoy.filters.http.admission_control" {
			t.Fatal("HTTP manager has an unscoped admission filter")
		}
	}
	if count != 1 {
		t.Fatalf("Composite filters = %d, want 1", count)
	}
	config := generatedAdmissionComposite(t, manager)
	if got := slices.Sorted(maps.Keys(config.GetNamedFilterChains())); !slices.Equal(got, []string{"admission-other", "admission-protected"}) {
		t.Fatalf("named chains = %v, want one per enabled API", got)
	}
	if config.GetMatcher() != nil {
		t.Fatal("HTTP manager has a default admission selector")
	}
	filters := config.GetNamedFilterChains()["admission-protected"].GetTypedConfig()
	if len(filters) != 1 || filters[0].Name != "envoy.filters.http.admission_control" {
		t.Fatalf("named chain filters = %v, want one native admission filter", filters)
	}
	var policy admissioncontrol.AdmissionControl
	if err := filters[0].GetTypedConfig().UnmarshalTo(&policy); err != nil {
		t.Fatal(err)
	}
	if !policy.GetEnabled().GetDefaultValue().GetValue() || policy.GetSamplingWindow().AsDuration() != 45*time.Second ||
		policy.GetSrThreshold().GetDefaultValue().GetValue() != 91.5 || policy.GetRpsThreshold().GetDefaultValue() != 25 ||
		policy.GetMaxRejectionProbability().GetDefaultValue().GetValue() != 65 {
		t.Fatalf("admission settings = %v, want the protected API's policy", &policy)
	}
}

func TestAdmissionControlOmittedTuningUsesEnvoyDefaults(t *testing.T) {
	c := loadConfigCase(t, "admission-control")
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	config := generatedAdmissionComposite(t, firstGeneratedHTTPManager(t, files.EnvoyBootstrap.Contents))
	filters := config.GetNamedFilterChains()["admission-other"].GetTypedConfig()
	if len(filters) != 1 {
		t.Fatalf("default chain filters = %v, want one admission filter", filters)
	}
	var policy admissioncontrol.AdmissionControl
	if err := filters[0].GetTypedConfig().UnmarshalTo(&policy); err != nil {
		t.Fatal(err)
	}
	if !policy.GetEnabled().GetDefaultValue().GetValue() || policy.GetSuccessCriteria() == nil {
		t.Fatalf("default admission policy = %v, want enabled with default success criteria", &policy)
	}
	if policy.SamplingWindow != nil || policy.SrThreshold != nil || policy.RpsThreshold != nil || policy.MaxRejectionProbability != nil {
		t.Fatalf("default admission policy overrides Envoy tuning: %v", &policy)
	}
}

func TestAdmissionControlRouteSelectors(t *testing.T) {
	c := loadConfigCase(t, "admission-control")
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := decodeBootstrap(t, files.EnvoyBootstrap.Contents)
	var selected, unselected int
	for _, chain := range bootstrap.GetStaticResources().GetListeners()[0].GetFilterChains() {
		manager := decodeHTTPManager(t, chain)
		config := generatedAdmissionComposite(t, manager)
		for _, host := range manager.GetRouteConfig().GetVirtualHosts() {
			for _, generatedRoute := range host.GetRoutes() {
				if generatedRoute.GetTypedPerFilterConfig()["envoy.filters.http.admission_control"] != nil {
					t.Fatalf("route %q has native admission configuration", generatedRoute.Name)
				}
				cluster := generatedRoute.GetRoute().GetCluster()
				want := map[string]string{"api-protected": "admission-protected", "api-other": "admission-other"}[cluster]
				packed := generatedRoute.GetTypedPerFilterConfig()["envoy.filters.http.composite"]
				if want == "" {
					unselected++
					if packed != nil {
						t.Fatalf("disabled or fallback route %q has an admission selector", generatedRoute.Name)
					}
					continue
				}
				selected++
				if packed == nil {
					t.Fatalf("route %q has no admission selector", generatedRoute.Name)
				}
				var selector composite.CompositePerRoute
				if err := packed.UnmarshalTo(&selector); err != nil {
					t.Fatalf("route %q selector must be a direct CompositePerRoute: %v", generatedRoute.Name, err)
				}
				if selector.GetMatcher().GetMatcherType() != nil {
					t.Fatalf("route %q selector repeats request matching", generatedRoute.Name)
				}
				var action composite.ExecuteFilterAction
				if err := selector.GetMatcher().GetOnNoMatch().GetAction().GetTypedConfig().UnmarshalTo(&action); err != nil {
					t.Fatalf("route %q action: %v", generatedRoute.Name, err)
				}
				if action.GetFilterChainName() != want || config.GetNamedFilterChains()[want] == nil {
					t.Fatalf("route %q selects %q, want emitted chain %q", generatedRoute.Name, action.GetFilterChainName(), want)
				}
				if action.GetTypedConfig() != nil || action.GetFilterChain() != nil || action.GetDynamicConfig() != nil {
					t.Fatalf("route %q embeds a filter configuration", generatedRoute.Name)
				}
			}
		}
	}
	if selected != 8 || unselected != 18 {
		t.Fatalf("selected/unselected routes = %d/%d, want 8/18", selected, unselected)
	}
}

func TestAdmissionControlChainsFollowManagerBindings(t *testing.T) {
	c := loadConfigCase(t, "admission-control")
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := decodeBootstrap(t, files.EnvoyBootstrap.Contents)
	chains := bootstrap.GetStaticResources().GetListeners()[0].GetFilterChains()
	if len(chains) != 3 {
		t.Fatalf("HTTP managers = %d, want 3", len(chains))
	}
	want := [][]string{{"admission-other", "admission-protected"}, {"admission-other"}, nil}
	for index, chain := range chains {
		manager := decodeHTTPManager(t, chain)
		config := generatedAdmissionComposite(t, manager)
		if got := slices.Sorted(maps.Keys(config.GetNamedFilterChains())); !slices.Equal(got, want[index]) {
			t.Fatalf("manager %d chains = %v, want %v", index, got, want[index])
		}
		if index == 2 && config != nil {
			t.Fatal("manager with only disabled APIs has a Composite filter")
		}
	}
}

func TestAdmissionControlFilterIsOmittedWhenDisabled(t *testing.T) {
	for _, test := range []struct {
		name string
		omit bool
	}{{name: "disabled"}, {name: "omitted", omit: true}} {
		t.Run(test.name, func(t *testing.T) {
			c := loadConfigCase(t, "admission-control")
			for index := range c.APIs {
				if test.omit {
					c.APIs[index].AdmissionControl = nil
				} else if c.APIs[index].AdmissionControl != nil {
					c.APIs[index].AdmissionControl.Enabled = false
				}
			}
			files, err := Generate(c)
			if err != nil {
				t.Fatal(err)
			}
			bootstrap := decodeBootstrap(t, files.EnvoyBootstrap.Contents)
			for _, chain := range bootstrap.GetStaticResources().GetListeners()[0].GetFilterChains() {
				manager := decodeHTTPManager(t, chain)
				if generatedAdmissionComposite(t, manager) != nil {
					t.Fatal("disabled admission control generated a Composite filter")
				}
				for _, host := range manager.GetRouteConfig().GetVirtualHosts() {
					for _, generatedRoute := range host.GetRoutes() {
						if generatedRoute.GetTypedPerFilterConfig()["envoy.filters.http.composite"] != nil {
							t.Fatalf("disabled admission control generated a selector on %q", generatedRoute.Name)
						}
					}
				}
			}
		})
	}
}

func TestAdmissionControlPreservesRouteProcessing(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-with-headers")
	c.APIs[0].AdmissionControl = &AdmissionControlConfig{Enabled: true}
	c.APIs[0].FaultInjection = &FaultInjectionConfig{Enabled: true, Abort: &FaultAbortConfig{HTTPStatus: 503, Percentage: 10}}
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	manager := firstGeneratedHTTPManager(t, files.EnvoyBootstrap.Contents)
	route := namedRoute(manager.GetRouteConfig().GetVirtualHosts()[0].GetRoutes(), "api-0-metrics-route-0-method-0")
	if route == nil {
		t.Fatal("processed route is missing")
	}
	for _, name := range []string{"envoy.filters.http.composite", "envoy.filters.http.fault", "envoy.filters.http.header_mutation", "auth_gateway.required_headers"} {
		if route.GetTypedPerFilterConfig()[name] == nil {
			t.Fatalf("processed route lost %q configuration", name)
		}
	}
}

func TestAdmissionControlUpdateRequiresBootstrapRollout(t *testing.T) {
	c := loadConfigCase(t, "admission-control")
	before, err := GenerateKubernetes(c)
	if err != nil {
		t.Fatal(err)
	}
	c.APIs[0].AdmissionControl.SrThreshold = new(90.0)
	after, err := GenerateKubernetes(c)
	if err != nil {
		t.Fatal(err)
	}
	if before.ConfigMap.Data["envoy.yaml"] == after.ConfigMap.Data["envoy.yaml"] {
		t.Fatal("admission update did not change the bootstrap ConfigMap")
	}
	if diff := cmp.Diff(before.Deployment.Spec.Template, after.Deployment.Spec.Template); diff != "" {
		t.Fatalf("admission update changed the Deployment template (-before +after):\n%s", diff)
	}
	if len(after.Deployment.Spec.Template.Annotations) != 0 {
		t.Fatal("admission update added a checksum annotation")
	}
}

func generatedAdmissionComposite(t *testing.T, manager *hcm.HttpConnectionManager) *composite.Composite {
	t.Helper()
	filter := generatedHTTPFilter(manager, "envoy.filters.http.composite")
	if filter == nil {
		return nil
	}
	if filter.GetDisabled() {
		t.Fatal("Composite filter is disabled at the HTTP manager")
	}
	var config composite.Composite
	if err := filter.GetTypedConfig().UnmarshalTo(&config); err != nil {
		t.Fatal(err)
	}
	return &config
}
