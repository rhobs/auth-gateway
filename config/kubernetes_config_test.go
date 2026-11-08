package config

import (
	"strings"
	"testing"
	"time"
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
			wantResources := KubernetesResourceRequirements{
				Requests: map[string]string{"cpu": "20m", "memory": "64Mi"},
				Limits:   map[string]string{"memory": "256Mi"},
			}
			type metricDefaults struct {
				Enabled        *bool
				ScrapeInterval *Duration
				ScrapeTimeout  *Duration
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
