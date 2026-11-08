package config

import (
	"math"
	"strings"
	"testing"
	"time"

	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
)

func TestKubernetesYAMLOptions(t *testing.T) {
	c := loadTestConfig(t, readFixture(t, "kubernetes-options/nested-null.yaml"), "nested nulls")
	if c.Overload != nil || c.Kubernetes.EnvoyConcurrency != nil {
		t.Fatalf("defaulted Kubernetes settings = %#v", c.Kubernetes)
	}

	c = loadTestConfig(t, readFixture(t, "kubernetes-options/empty-resource-maps.yaml"), "empty resource maps")
	if c.Kubernetes.Resources.Requests == nil || c.Kubernetes.Resources.Limits == nil ||
		len(c.Kubernetes.Resources.Requests) != 0 || len(c.Kubernetes.Resources.Limits) != 0 {
		t.Fatal("supplied empty resource maps were merged with defaults")
	}
	if _, err := Load(strings.NewReader(readFixture(t, "kubernetes-options/overload-empty.yaml"))); err == nil || !strings.Contains(err.Error(), "overload.max_heap_bytes") {
		t.Fatalf("empty overload accepted: %v", err)
	}
}

func TestKubernetesObservabilityDefaults(t *testing.T) {
	defaults := []struct {
		name string
		file string
	}{
		{name: "metrics omitted", file: "public-routing/config.yaml"},
		{name: "metrics null", file: "kubernetes-options/metrics-null.yaml"},
		{name: "metrics empty", file: "kubernetes-options/metrics-empty.yaml"},
		{name: "nested nulls", file: "kubernetes-options/nested-null.yaml"},
	}
	for _, test := range defaults {
		t.Run(test.name, func(t *testing.T) {
			c := loadTestConfig(t, readFixture(t, test.file), test.name)
			metrics := c.Observability.Metrics
			collectorResources := c.Kubernetes.Metrics.Resources
			wantResources := gatewayapi.KubernetesResourceRequirements{
				Requests: map[string]string{"cpu": "20m", "memory": "64Mi"},
				Limits:   map[string]string{"memory": "256Mi"},
			}
			type metricDefaults struct {
				Enabled        *bool
				ScrapeInterval *gatewayapi.Duration
				ScrapeTimeout  *gatewayapi.Duration
			}
			gotMetrics := metricDefaults{
				Enabled:        metrics.Enabled,
				ScrapeInterval: metrics.ScrapeInterval,
				ScrapeTimeout:  metrics.ScrapeTimeout,
			}
			wantMetrics := metricDefaults{
				Enabled:        new(true),
				ScrapeInterval: duration(30 * time.Second),
				ScrapeTimeout:  duration(10 * time.Second),
			}
			assertConfigDiff(t, "defaulted metrics", wantMetrics, gotMetrics)
			assertConfigDiff(t, "defaulted collector resources", wantResources, collectorResources)
			if got, want := c.Kubernetes.OTelCollectorImage, DefaultOTelCollectorImage; got != want {
				t.Errorf("collector image = %q, want %q", got, want)
			}
		})
	}
}

func TestKubernetesObservabilityDefaultsPreserveExplicitResourceMaps(t *testing.T) {
	c := loadTestConfig(t, readFixture(t, "kubernetes-options/empty-resource-maps.yaml"), "empty resource maps")
	resources := c.Kubernetes.Metrics.Resources
	if resources.Limits == nil {
		t.Error("collector resource defaults replaced the explicitly empty limits map with nil")
	}
	if len(resources.Limits) != 0 {
		t.Errorf("collector limits = %v, want an empty map", resources.Limits)
	}
	assertConfigDiff(t, "collector requests", map[string]string{"cpu": "5m"}, resources.Requests)
}

func TestKubernetesImageDefaultsToSharedImages(t *testing.T) {
	c := loadConfigCase(t, "public-routing")
	c.Kubernetes.Image = ""
	c.Kubernetes.OTelCollectorImage = ""
	defaulted := withDefaultsConfig(c)
	got := []string{defaulted.Kubernetes.Image, defaulted.Kubernetes.OTelCollectorImage}
	want := []string{DefaultEnvoyImage, DefaultOTelCollectorImage}
	assertConfigDiff(t, "defaulted Kubernetes images", want, got)
}

func TestKubernetesResourceRequirementsRejectsInvalidQuantity(t *testing.T) {
	_, err := KubernetesResourceRequirements("kubernetes.resources", gatewayapi.KubernetesResourceRequirements{
		Requests: map[string]string{"cpu": "not-a-quantity"},
	})
	if err == nil || !strings.Contains(err.Error(), "kubernetes.resources.requests.cpu") {
		t.Fatalf("resource requirements error = %v, want invalid CPU quantity error", err)
	}
}

func TestKubernetesValidationAndOverloadBudgets(t *testing.T) {
	tests := []struct {
		name  string
		field string
		edit  func(*gatewayapi.Config)
	}{
		{"empty overload", "overload.max_heap_bytes", func(c *gatewayapi.Config) { c.Overload.MaxHeapBytes = 0 }},
		{"zero connections", "overload.max_downstream_connections", func(c *gatewayapi.Config) { c.Overload.MaxDownstreamConnections = 0 }},
		{"zero threshold", "overload.heap_shrink_threshold", func(c *gatewayapi.Config) { c.Overload.HeapShrinkThreshold = new(0.0) }},
		{"unit threshold", "overload.request_reject_threshold", func(c *gatewayapi.Config) { c.Overload.RequestRejectThreshold = new(1.0) }},
		{"negative threshold", "overload.request_reject_threshold", func(c *gatewayapi.Config) { c.Overload.RequestRejectThreshold = new(-0.1) }},
		{"nan threshold", "overload.heap_shrink_threshold", func(c *gatewayapi.Config) { c.Overload.HeapShrinkThreshold = new(math.NaN()) }},
		{"infinite threshold", "overload.request_reject_threshold", func(c *gatewayapi.Config) { c.Overload.RequestRejectThreshold = new(math.Inf(1)) }},
		{"unordered thresholds", "overload.heap_shrink_threshold", func(c *gatewayapi.Config) { c.Overload.RequestRejectThreshold = new(0.9) }},
		{"missing memory limit", "kubernetes.resources.limits.memory", func(c *gatewayapi.Config) { c.Kubernetes.Resources.Limits = map[string]string{} }},
		{"zero memory limit", "kubernetes.resources.limits.memory", func(c *gatewayapi.Config) {
			c.Kubernetes.Resources.Requests = map[string]string{}
			c.Kubernetes.Resources.Limits = map[string]string{"memory": "0"}
		}},
		{"zero concurrency", "kubernetes.envoy_concurrency", func(c *gatewayapi.Config) { c.Kubernetes.EnvoyConcurrency = new(uint32(0)) }},
		{"envoy request exceeds limit", "kubernetes.resources.requests.cpu", func(c *gatewayapi.Config) { c.Kubernetes.Resources.Requests["cpu"] = "1001m" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := loadConfigCase(t, "public-routing")
			c.Overload = &gatewayapi.OverloadConfig{MaxHeapBytes: 128 << 20, MaxDownstreamConnections: 1024}
			tt.edit(&c)
			if err := Validate(c); err == nil || !strings.Contains(err.Error(), tt.field) {
				t.Fatalf("validation = %v, want %s", err, tt.field)
			}
		})
	}
}
