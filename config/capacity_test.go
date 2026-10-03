package config

import (
	"math"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	connections "github.com/envoyproxy/go-control-plane/envoy/extensions/resource_monitors/downstream_connections/v3"
	heap "github.com/envoyproxy/go-control-plane/envoy/extensions/resource_monitors/fixed_heap/v3"
	"go.yaml.in/yaml/v3"
	"k8s.io/apimachinery/pkg/api/resource"
)

func TestOverloadGeneration(t *testing.T) {
	c := loadConfigCase(t, "public-routing")
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	if decodeBootstrap(t, files["envoy.yaml"]).OverloadManager != nil {
		t.Fatal("overload enabled without explicit budgets")
	}
	c.Overload = &OverloadConfig{MaxHeapBytes: 128 << 20, MaxDownstreamConnections: 1024, HeapShrinkThreshold: new(0.8), RequestRejectThreshold: new(0.85)}
	files, err = Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	o := decodeBootstrap(t, files["envoy.yaml"]).OverloadManager
	if o == nil || o.RefreshInterval.AsDuration() != 250*time.Millisecond || len(o.ResourceMonitors) != 2 || len(o.Actions) != 2 || len(o.LoadshedPoints) != 0 {
		t.Fatalf("overload manager = %v", o)
	}
	var h heap.FixedHeapConfig
	if err := o.ResourceMonitors[0].GetTypedConfig().UnmarshalTo(&h); err != nil {
		t.Fatal(err)
	}
	var connectionsConfig connections.DownstreamConnectionsConfig
	if err := o.ResourceMonitors[1].GetTypedConfig().UnmarshalTo(&connectionsConfig); err != nil {
		t.Fatal(err)
	}
	if h.MaxHeapSizeBytes != 128<<20 || connectionsConfig.MaxActiveDownstreamConnections != 1024 || o.ResourceMonitors[0].Name != "envoy.resource_monitors.fixed_heap" || o.ResourceMonitors[1].Name != "envoy.resource_monitors.global_downstream_max_connections" {
		t.Fatalf("resource monitors = %v", o.ResourceMonitors)
	}
	for i, want := range []struct {
		name      string
		threshold float64
	}{{"envoy.overload_actions.shrink_heap", 0.8}, {"envoy.overload_actions.stop_accepting_requests", 0.85}} {
		action := o.Actions[i]
		if action.Name != want.name || len(action.Triggers) != 1 || action.Triggers[0].Name != "envoy.resource_monitors.fixed_heap" || action.Triggers[0].GetThreshold().Value != want.threshold {
			t.Fatalf("action %d = %v", i, action)
		}
	}
}

func TestCapacityValidation(t *testing.T) {
	tests := []struct {
		name  string
		field string
		edit  func(*Config)
	}{
		{"empty overload", "overload.max_heap_bytes", func(c *Config) { c.Overload.MaxHeapBytes = 0 }},
		{"zero connections", "overload.max_downstream_connections", func(c *Config) { c.Overload.MaxDownstreamConnections = 0 }},
		{"zero threshold", "overload.heap_shrink_threshold", func(c *Config) { c.Overload.HeapShrinkThreshold = new(0.0) }},
		{"unit threshold", "overload.request_reject_threshold", func(c *Config) { c.Overload.RequestRejectThreshold = new(1.0) }},
		{"negative threshold", "overload.request_reject_threshold", func(c *Config) { c.Overload.RequestRejectThreshold = new(-0.1) }},
		{"nan threshold", "overload.heap_shrink_threshold", func(c *Config) { c.Overload.HeapShrinkThreshold = new(math.NaN()) }},
		{"infinite threshold", "overload.request_reject_threshold", func(c *Config) { c.Overload.RequestRejectThreshold = new(math.Inf(1)) }},
		{"unordered thresholds", "overload.heap_shrink_threshold", func(c *Config) { c.Overload.RequestRejectThreshold = new(0.9) }},
		{"missing memory limit", "kubernetes.resources.limits.memory", func(c *Config) { c.Kubernetes.Resources.Limits = map[string]string{} }},
		{"zero memory limit", "kubernetes.resources.limits.memory", func(c *Config) {
			c.Kubernetes.Resources.Requests = map[string]string{}
			c.Kubernetes.Resources.Limits = map[string]string{"memory": "0"}
		}},
		{"zero concurrency", "kubernetes.envoy_concurrency", func(c *Config) { c.Kubernetes.EnvoyConcurrency = new(uint32(0)) }},
		{"zero interval", "kubernetes.metrics.scrape_interval", func(c *Config) { c.Kubernetes.Metrics.ScrapeInterval = duration(0) }},
		{"zero timeout", "kubernetes.metrics.scrape_timeout", func(c *Config) { c.Kubernetes.Metrics.ScrapeTimeout = duration(0) }},
		{"timeout exceeds interval", "kubernetes.metrics.scrape_timeout", func(c *Config) { c.Kubernetes.Metrics.ScrapeInterval = duration(time.Second) }},
		{"fractional milliseconds", "kubernetes.metrics.scrape_timeout", func(c *Config) { c.Kubernetes.Metrics.ScrapeTimeout = duration(time.Millisecond + time.Microsecond) }},
		{"envoy request exceeds limit", "kubernetes.resources.requests.cpu", func(c *Config) { c.Kubernetes.Resources.Requests["cpu"] = "1001m" }},
		{"collector request exceeds limit", "kubernetes.metrics.resources.requests.memory", func(c *Config) { c.Kubernetes.Metrics.Resources.Requests["memory"] = "257Mi" }},
		{"invalid collector quantity", "kubernetes.metrics.resources.limits.memory", func(c *Config) { c.Kubernetes.Metrics.Resources.Limits["memory"] = "invalid" }},
		{"negative collector quantity", "kubernetes.metrics.resources.requests.cpu", func(c *Config) { c.Kubernetes.Metrics.Resources.Requests["cpu"] = "-1m" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := loadConfigCase(t, "public-routing")
			c.Overload = &OverloadConfig{MaxHeapBytes: 128 << 20, MaxDownstreamConnections: 1024}
			tt.edit(&c)
			if err := c.Validate(); err == nil || !strings.Contains(err.Error(), tt.field) {
				t.Fatalf("validation = %v, want %s", err, tt.field)
			}
		})
	}
}

func TestHeapBudgetComparedExactly(t *testing.T) {
	for _, tt := range []struct {
		limit string
		heap  uint64
		valid bool
	}{
		{"256Mi", 268435455, true},
		{"256Mi", 268435456, false},
		{"256Mi", 268435457, false},
		{"100.1", 100, true},
		{"100", 100, false},
		{"9223372036854775808", uint64(1) << 63, false},
		{"9223372036854775809", uint64(1) << 63, true},
		{"18446744073709551615", math.MaxUint64, false},
		{"18446744073709551616", math.MaxUint64, true},
		{"256Mi", math.MaxUint64, false},
	} {
		t.Run(tt.limit, func(t *testing.T) {
			c := loadConfigCase(t, "public-routing")
			c.Kubernetes.Resources = KubernetesResourceRequirements{Requests: map[string]string{}, Limits: map[string]string{"memory": tt.limit}}
			c.Overload = &OverloadConfig{MaxHeapBytes: tt.heap, MaxDownstreamConnections: 1}
			if err := c.Validate(); (err == nil) != tt.valid {
				t.Fatalf("heap %d, limit %s: %v", tt.heap, tt.limit, err)
			}
			c.Kubernetes = nil
			if _, err := Generate(c); err != nil {
				t.Fatalf("file-only heap budget: %v", err)
			}
		})
	}
}

func TestMetricsAndConcurrencyGeneration(t *testing.T) {
	c := loadConfigCase(t, "public-routing")
	c.Kubernetes.EnvoyConcurrency = new(uint32(3))
	c.Kubernetes.Metrics = KubernetesMetrics{
		ScrapeInterval: duration(1500 * time.Millisecond), ScrapeTimeout: duration(250 * time.Millisecond),
		Resources: KubernetesResourceRequirements{Requests: map[string]string{"cpu": "30m"}, Limits: map[string]string{}},
	}
	r, err := GenerateKubernetes(c)
	if err != nil {
		t.Fatal(err)
	}
	args := r.Deployment.Spec.Template.Spec.Containers[0].Args
	index := slices.Index(args, "--concurrency")
	if index < 0 || index+1 == len(args) || args[index+1] != "3" {
		t.Fatalf("Envoy args = %v", args)
	}
	var collector struct {
		Receivers struct {
			Prometheus struct {
				Config struct {
					Scrapes []struct {
						Interval string `yaml:"scrape_interval"`
						Timeout  string `yaml:"scrape_timeout"`
					} `yaml:"scrape_configs"`
				} `yaml:"config"`
			} `yaml:"prometheus"`
		} `yaml:"receivers"`
	}
	if err := yaml.Unmarshal([]byte(r.OTelCollectorConfigMap.Data["config.yaml"]), &collector); err != nil {
		t.Fatal(err)
	}
	scrapes := collector.Receivers.Prometheus.Config.Scrapes
	if len(scrapes) != 1 || scrapes[0].Interval != "1500ms" || scrapes[0].Timeout != "250ms" {
		t.Fatalf("scrape timing = %+v", scrapes)
	}
	resources := r.Deployment.Spec.Template.Spec.Containers[1].Resources
	if len(resources.Requests) != 1 || resources.Requests.Cpu().Cmp(resource.MustParse("30m")) != 0 || len(resources.Limits) != 0 {
		t.Fatalf("collector resource overrides = %v", resources)
	}
	c.Kubernetes.EnvoyConcurrency = nil
	c.Kubernetes.Resources.Limits["cpu"] = "4"
	r, err = GenerateKubernetes(c)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(r.Deployment.Spec.Template.Spec.Containers[0].Args, "--concurrency") {
		t.Fatal("worker count inferred from CPU limit")
	}
}

func TestCapacityDefaultsCloneInputs(t *testing.T) {
	c := loadConfigCase(t, "public-routing")
	c.Overload = &OverloadConfig{MaxHeapBytes: 128 << 20, MaxDownstreamConnections: 1, HeapShrinkThreshold: new(0.7)}
	c.Kubernetes.EnvoyConcurrency = new(uint32(2))
	c.Kubernetes.Resources.Limits = map[string]string{}
	c.Kubernetes.Metrics.Resources = KubernetesResourceRequirements{Requests: map[string]string{"cpu": "5m"}, Limits: map[string]string{}}
	copy := c.withDefaults()
	if len(copy.Kubernetes.Resources.Limits) != 0 || len(copy.Kubernetes.Metrics.Resources.Limits) != 0 || !reflect.DeepEqual(copy.Kubernetes.Metrics.Resources.Requests, map[string]string{"cpu": "5m"}) {
		t.Fatal("resource defaults merged into supplied maps")
	}
	*copy.Overload.HeapShrinkThreshold = 0.2
	*copy.Kubernetes.EnvoyConcurrency = 3
	*copy.Kubernetes.Metrics.ScrapeInterval = Duration(time.Second)
	copy.Kubernetes.Metrics.Resources.Requests["cpu"] = "10m"
	copy.Kubernetes.Resources.Limits["memory"] = "512Mi"
	if *c.Overload.HeapShrinkThreshold != 0.7 || *c.Kubernetes.EnvoyConcurrency != 2 || *c.Kubernetes.Metrics.ScrapeInterval != Duration(30*time.Second) || c.Kubernetes.Metrics.Resources.Requests["cpu"] != "5m" || len(c.Kubernetes.Resources.Limits) != 0 {
		t.Fatal("defaulting aliases caller-owned capacity settings")
	}
}

func TestCapacityYAMLOptions(t *testing.T) {
	base, _, _ := strings.Cut(readFixture(t, "public-routing/config.yaml"), "kubernetes:\n")
	base += "kubernetes:\n  name: gateway\n  namespace: observability\n  image: envoyproxy/envoy:v1.39.1\n"
	for _, settings := range []string{"", "  metrics: null\n", "  metrics: {}\n", "  metrics:\n    scrape_interval: null\n    scrape_timeout: null\n    resources: {requests: null, limits: null}\n"} {
		c, err := Load(strings.NewReader(base + settings + "overload: null\n"))
		if err != nil {
			t.Fatal(err)
		}
		if c.Overload != nil || c.Kubernetes.EnvoyConcurrency != nil || *c.Kubernetes.Metrics.ScrapeInterval != Duration(30*time.Second) || *c.Kubernetes.Metrics.ScrapeTimeout != Duration(10*time.Second) || !reflect.DeepEqual(c.Kubernetes.Metrics.Resources.Requests, map[string]string{"cpu": "20m", "memory": "64Mi"}) || !reflect.DeepEqual(c.Kubernetes.Metrics.Resources.Limits, map[string]string{"memory": "256Mi"}) {
			t.Fatalf("defaults for %q = %#v", settings, c.Kubernetes.Metrics)
		}
	}
	c, err := Load(strings.NewReader(base + "  resources: {requests: {}, limits: {}}\n  metrics:\n    resources: {requests: {cpu: 5m}, limits: {}}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Kubernetes.Resources.Requests) != 0 || len(c.Kubernetes.Resources.Limits) != 0 || len(c.Kubernetes.Metrics.Resources.Limits) != 0 || !reflect.DeepEqual(c.Kubernetes.Metrics.Resources.Requests, map[string]string{"cpu": "5m"}) {
		t.Fatal("supplied YAML resource maps were merged with defaults")
	}
	if _, err := Load(strings.NewReader(base + "overload: {}\n")); err == nil || !strings.Contains(err.Error(), "overload.max_heap_bytes") {
		t.Fatalf("empty overload accepted: %v", err)
	}
}
