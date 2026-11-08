package config

import (
	"strings"
	"testing"

	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
)

func TestAPIMetricsConfigurationAndValidation(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-with-attributes")
	type apiMetricsDefaults struct {
		Configured bool
		Tenant     string
		LabelCount int
	}
	gotMetrics := make([]apiMetricsDefaults, 0, len(c.APIs))
	for _, api := range c.APIs {
		settings := apiMetricsDefaults{}
		if api.Metrics != nil {
			settings.Configured = true
			settings.Tenant = api.Metrics.Labels["tenant"]
			settings.LabelCount = len(api.Metrics.Labels)
		}
		gotMetrics = append(gotMetrics, settings)
	}
	wantMetrics := []apiMetricsDefaults{
		{Configured: true, Tenant: "tenant_id", LabelCount: 1},
		{Configured: true},
	}
	assertConfigDiff(t, "fixture API metrics", wantMetrics, gotMetrics)

	tests := []struct {
		name string
		want string
		edit func(*gatewayapi.Config)
	}{
		{name: "invalid label name", want: "apis[0].metrics.labels", edit: func(c *gatewayapi.Config) { c.APIs[0].Metrics.Labels["bad-name"] = "tenant_id" }},
		{name: "reserved API label", want: "apis[0].metrics.labels", edit: func(c *gatewayapi.Config) { c.APIs[0].Metrics.Labels["api"] = "tenant_id" }},
		{name: "reserved status label", want: "apis[0].metrics.labels", edit: func(c *gatewayapi.Config) { c.APIs[0].Metrics.Labels["http_status_code"] = "tenant_id" }},
		{name: "reserved Prometheus prefix", want: "apis[0].metrics.labels", edit: func(c *gatewayapi.Config) { c.APIs[0].Metrics.Labels["__internal"] = "tenant_id" }},
		{name: "reserved Envoy label", want: "apis[0].metrics.labels", edit: func(c *gatewayapi.Config) { c.APIs[0].Metrics.Labels["envoy_http_conn_manager_prefix"] = "tenant_id" }},
		{name: "invalid attribute name", want: "apis[0].metrics.labels.tenant", edit: func(c *gatewayapi.Config) { c.APIs[0].Metrics.Labels["tenant"] = "TenantID" }},
		{name: "unknown attribute", want: "apis[0].metrics.labels.tenant references unknown authenticator attribute", edit: func(c *gatewayapi.Config) { c.APIs[0].Metrics.Labels["tenant"] = "unknown" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := loadConfigCase(t, "jwt-auth-with-attributes")
			test.edit(&config)
			if err := Validate(config); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestRequestMetricNameConfigurationAndValidation(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-with-attributes")
	c.Observability.Metrics.CustomMetricName = new("gateway_http_requests_total")
	if err := Validate(c); err != nil {
		t.Fatalf("valid custom metric name was rejected: %v", err)
	}
	for _, test := range []struct{ name, value string }{
		{name: "empty"},
		{name: "leading digit", value: "9requests_total"},
		{name: "hyphen", value: "bad-name"},
		{name: "period", value: "bad.name"},
		{name: "stat delimiter", value: "bad|name"},
		{name: "reserved prefix", value: "__reserved"},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := loadConfigCase(t, "jwt-auth-with-attributes")
			config.Observability.Metrics.CustomMetricName = new(test.value)
			if err := Validate(config); err == nil || !strings.Contains(err.Error(), "observability.metrics.custom_metric_name") {
				t.Fatalf("Validate error = %v, want observability.metrics.custom_metric_name", err)
			}
		})
	}
}
