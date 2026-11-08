package config

import (
	"net/http"
	"strings"
	"testing"

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
