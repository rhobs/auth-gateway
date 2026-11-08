package config

import (
	"strings"
	"testing"
	"time"

	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
)

func TestObservabilityDefaults(t *testing.T) {
	c := loadTestConfig(t, readFixture(t, "defaults.yaml"), "defaults fixture")
	wantObservability := gatewayapi.ObservabilityConfig{Metrics: gatewayapi.ObservabilityMetrics{
		Enabled: new(true), ScrapeInterval: duration(30 * time.Second), ScrapeTimeout: duration(10 * time.Second),
	}, Tracing: gatewayapi.ObservabilityTracing{
		Enabled: new(false), ServiceName: "auth-gateway", SamplingPercentage: new(100.0), Insecure: new(false),
	}}
	assertConfigDiff(t, "observability defaults", wantObservability, c.Observability)
	wantCollectorResources := gatewayapi.KubernetesResourceRequirements{
		Requests: map[string]string{"cpu": "20m", "memory": "64Mi"},
		Limits:   map[string]string{"memory": "256Mi"},
	}
	if got, want := c.Kubernetes.OTelCollectorImage, DefaultOTelCollectorImage; got != want {
		t.Errorf("collector image = %q, want %q", got, want)
	}
	assertConfigDiff(t, "collector resources defaults", wantCollectorResources, c.Kubernetes.Metrics.Resources)
}

func TestObservabilityDefaultsDoNotMutateInput(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-with-attributes")
	c.Observability.Metrics.CustomMetricName = new("gateway_http_requests_total")
	defaulted := withDefaultsConfig(c)
	defaulted.APIs[0].Metrics.Labels["tenant"] = "writer_id"
	*defaulted.Observability.Metrics.CustomMetricName = "changed_requests_total"
	*defaulted.Observability.Metrics.ScrapeInterval = gatewayapi.Duration(time.Second)
	defaulted.Kubernetes.Metrics.Resources.Requests["cpu"] = "10m"
	got := struct {
		TenantLabel      string
		CustomMetricName string
		ScrapeInterval   gatewayapi.Duration
		CPURequest       string
	}{
		TenantLabel:      c.APIs[0].Metrics.Labels["tenant"],
		CustomMetricName: *c.Observability.Metrics.CustomMetricName,
		ScrapeInterval:   *c.Observability.Metrics.ScrapeInterval,
		CPURequest:       c.Kubernetes.Metrics.Resources.Requests["cpu"],
	}
	want := struct {
		TenantLabel      string
		CustomMetricName string
		ScrapeInterval   gatewayapi.Duration
		CPURequest       string
	}{
		TenantLabel:      "tenant_id",
		CustomMetricName: "gateway_http_requests_total",
		ScrapeInterval:   gatewayapi.Duration(30 * time.Second),
		CPURequest:       "20m",
	}
	assertConfigDiff(t, "input after defaulting", want, got)
}

func TestTracingRequiresValidEndpointAndSampling(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*gatewayapi.Config)
		wantErr string
	}{
		{
			name: "endpoint required",
			mutate: func(c *gatewayapi.Config) {
				c.Observability.Tracing.Enabled = new(true)
			},
			wantErr: "observability.tracing.endpoint is required",
		},
		{
			name: "endpoint must be host and port",
			mutate: func(c *gatewayapi.Config) {
				c.Observability.Tracing.Enabled = new(true)
				c.Observability.Tracing.Endpoint = "https://collector.example.com:4317"
			},
			wantErr: "observability.tracing.endpoint must be a host:port",
		},
		{
			name: "sampling is bounded",
			mutate: func(c *gatewayapi.Config) {
				c.Observability.Tracing.Enabled = new(true)
				c.Observability.Tracing.Endpoint = "collector.example.com:4317"
				c.Observability.Tracing.SamplingPercentage = new(100.1)
			},
			wantErr: "observability.tracing.sampling_percentage must be between 0 and 100",
		},
		{
			name: "trace collector port is reserved",
			mutate: func(c *gatewayapi.Config) {
				c.Observability.Tracing.Enabled = new(true)
				c.Observability.Tracing.Endpoint = "collector.example.com:4317"
				c.Listener.Port = new(uint32(DefaultOTelTracePort))
			},
			wantErr: "listener.port must not conflict with the OTLP trace collector port",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := loadConfigCase(t, "public-routing")
			test.mutate(&c)
			err := Validate(c)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("Validate() error = %v, want %q", err, test.wantErr)
			}
		})
	}
}

func TestObservabilityMetricsValidation(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
		field   string
		edit    func(*gatewayapi.Config)
	}{
		{name: "zero interval", fixture: "public-routing", field: "observability.metrics.scrape_interval", edit: func(c *gatewayapi.Config) { c.Observability.Metrics.ScrapeInterval = duration(0) }},
		{name: "zero timeout", fixture: "public-routing", field: "observability.metrics.scrape_timeout", edit: func(c *gatewayapi.Config) { c.Observability.Metrics.ScrapeTimeout = duration(0) }},
		{name: "timeout exceeds interval", fixture: "public-routing", field: "observability.metrics.scrape_timeout", edit: func(c *gatewayapi.Config) { c.Observability.Metrics.ScrapeInterval = duration(time.Second) }},
		{name: "fractional milliseconds", fixture: "public-routing", field: "observability.metrics.scrape_timeout", edit: func(c *gatewayapi.Config) {
			c.Observability.Metrics.ScrapeTimeout = duration(time.Millisecond + time.Microsecond)
		}},
		{name: "collector request exceeds limit", fixture: "public-routing", field: "kubernetes.metrics.resources.requests.memory", edit: func(c *gatewayapi.Config) { c.Kubernetes.Metrics.Resources.Requests["memory"] = "257Mi" }},
		{name: "invalid collector quantity", fixture: "public-routing", field: "kubernetes.metrics.resources.limits.memory", edit: func(c *gatewayapi.Config) { c.Kubernetes.Metrics.Resources.Limits["memory"] = "invalid" }},
		{name: "negative collector quantity", fixture: "public-routing", field: "kubernetes.metrics.resources.requests.cpu", edit: func(c *gatewayapi.Config) { c.Kubernetes.Metrics.Resources.Requests["cpu"] = "-1m" }},
		{name: "listener port conflicts with metrics collector", fixture: "public-routing", field: "listener.port must not conflict with admin port", edit: func(c *gatewayapi.Config) { c.Listener.Port = new(uint32(DefaultOTelMetricsPort)) }},
		{name: "HTTP Service port conflict", fixture: "public-routing", field: "kubernetes.service_port", edit: func(c *gatewayapi.Config) {
			c.Kubernetes.ServicePort = new(int32(DefaultOTelMetricsPort))
		}},
		{name: "HTTPS Service port conflict", fixture: "server-tls", field: "kubernetes.https_service_port", edit: func(c *gatewayapi.Config) {
			c.Kubernetes.HTTPSServicePort = new(int32(DefaultOTelMetricsPort))
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := loadConfigCase(t, test.fixture)
			test.edit(&c)
			if err := Validate(c); err == nil || !strings.Contains(err.Error(), test.field) {
				t.Fatalf("validation = %v, want %s", err, test.field)
			}
		})
	}
}

func TestMetricsCollectorPortAvailableWithoutKubernetes(t *testing.T) {
	c := loadConfigCase(t, "public-routing")
	c.Kubernetes = nil
	c.Listener.Port = new(uint32(DefaultOTelMetricsPort))
	if err := Validate(c); err != nil {
		t.Fatalf("file-only configuration rejected the metrics collector port: %v", err)
	}
}
