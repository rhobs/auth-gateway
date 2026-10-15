package config

import (
	"strings"
	"testing"
	"time"

	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	admissioncontrol "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/admission_control/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
)

func TestGlobalAdmissionControlIsConfiguredAtHTTPManagerScope(t *testing.T) {
	config := loadConfigCase(t, "admission-control")
	files, err := Generate(config)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := decodeBootstrap(t, files.EnvoyBootstrap.Contents)
	var manager *hcm.HttpConnectionManager
	for _, chain := range bootstrap.GetStaticResources().GetListeners()[0].GetFilterChains() {
		candidate := decodeHTTPManager(t, chain)
		if hasHTTPFilter(candidate, admissionControlFilterName) {
			manager = candidate
			break
		}
	}
	if manager == nil {
		t.Fatal("no HTTP manager contains the admission control filter")
	}
	filter := generatedHTTPFilter(manager, admissionControlFilterName)
	if filter.GetDisabled() {
		t.Fatal("admission control filter should be enabled at the HTTP manager")
	}
	var global admissioncontrol.AdmissionControl
	if err := filter.GetTypedConfig().UnmarshalTo(&global); err != nil {
		t.Fatal(err)
	}
	if !global.GetEnabled().GetDefaultValue().GetValue() {
		t.Fatal("HTTP manager admission control is not enabled")
	}
	if got := global.GetSamplingWindow().AsDuration(); got != 45*time.Second {
		t.Errorf("sampling window = %s, want 45s", got)
	}
	if got := global.GetSrThreshold().GetDefaultValue().GetValue(); got != 91.5 {
		t.Errorf("success rate threshold = %v, want 91.5", got)
	}
	if got := global.GetRpsThreshold().GetDefaultValue(); got != 25 {
		t.Errorf("RPS threshold = %d, want 25", got)
	}
	if got := global.GetMaxRejectionProbability().GetDefaultValue().GetValue(); got != 65 {
		t.Errorf("maximum rejection probability = %v, want 65", got)
	}

	routes := make(map[string]*routev3.Route)
	for _, host := range manager.GetRouteConfig().GetVirtualHosts() {
		for _, generatedRoute := range host.GetRoutes() {
			routes[generatedRoute.GetName()] = generatedRoute
		}
	}
	for _, name := range []string{"api-0-protected-route-0-method-0", "api-1-plain-route-0-method-0"} {
		generatedRoute := routes[name]
		if generatedRoute == nil {
			t.Fatalf("route %q is missing", name)
		}
		if generatedRoute.GetTypedPerFilterConfig()[admissionControlFilterName] != nil {
			t.Fatalf("route %q unexpectedly has route-level admission control config", name)
		}
	}
}

func TestAdmissionControlFilterIsOmittedWhenDisabled(t *testing.T) {
	config := loadConfigCase(t, "admission-control")
	config.AdmissionControl.Enabled = false
	files, err := Generate(config)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := decodeBootstrap(t, files.EnvoyBootstrap.Contents)
	for _, chain := range bootstrap.GetStaticResources().GetListeners()[0].GetFilterChains() {
		manager := decodeHTTPManager(t, chain)
		if hasHTTPFilter(manager, admissionControlFilterName) {
			t.Fatal("admission control filter was generated while disabled")
		}
	}
}

func TestAdmissionControlRejectsInvalidSettings(t *testing.T) {
	tests := []struct {
		name  string
		field string
		edit  func(*AdmissionControlConfig)
	}{
		{
			name:  "non-positive sampling window",
			field: "sampling_window",
			edit:  func(config *AdmissionControlConfig) { config.SamplingWindow = duration(0) },
		},
		{
			name:  "success rate above 100 percent",
			field: "sr_threshold",
			edit:  func(config *AdmissionControlConfig) { config.SrThreshold = new(100.1) },
		},
		{
			name:  "negative rejection probability",
			field: "max_rejection_probability",
			edit:  func(config *AdmissionControlConfig) { config.MaxRejectionProbability = new(-1.0) },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := loadConfigCase(t, "admission-control")
			test.edit(config.AdmissionControl)
			if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "admission_control."+test.field) {
				t.Fatalf("validation error = %v, want field admission_control.%s", err, test.field)
			}
		})
	}
}
