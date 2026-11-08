package gateway

import (
	"math"
	"strings"
	"testing"
	"time"

	connections "github.com/envoyproxy/go-control-plane/envoy/extensions/resource_monitors/downstream_connections/v3"
	heap "github.com/envoyproxy/go-control-plane/envoy/extensions/resource_monitors/fixed_heap/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
)

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

func TestValidateRejectsInvalidOverloadConfiguration(t *testing.T) {
	exampleConfig := readFixture(t, "public-routing/config.yaml")
	validOverload := func() *gatewayapi.OverloadConfig {
		return &gatewayapi.OverloadConfig{
			MaxHeapBytes:             128 << 20,
			MaxDownstreamConnections: 1024,
			HeapShrinkThreshold:      new(0.70),
			RequestRejectThreshold:   new(0.85),
		}
	}
	tests := []struct {
		name string
		want string
		edit func(*gatewayapi.Config)
	}{
		{name: "zero max downstream connections", want: "overload.max_downstream_connections", edit: func(c *gatewayapi.Config) {
			o := validOverload()
			o.MaxDownstreamConnections = 0
			c.Overload = o
		}},
		{name: "heap shrink threshold not finite", want: "overload.heap_shrink_threshold", edit: func(c *gatewayapi.Config) {
			o := validOverload()
			o.HeapShrinkThreshold = new(math.NaN())
			c.Overload = o
		}},
		{name: "heap shrink threshold out of range", want: "overload.heap_shrink_threshold", edit: func(c *gatewayapi.Config) {
			o := validOverload()
			o.HeapShrinkThreshold = new(0.0)
			c.Overload = o
		}},
		{name: "request reject threshold out of range", want: "overload.request_reject_threshold", edit: func(c *gatewayapi.Config) {
			o := validOverload()
			o.RequestRejectThreshold = new(1.0)
			c.Overload = o
		}},
		{name: "shrink threshold not below reject threshold", want: "overload.heap_shrink_threshold must be less than overload.request_reject_threshold", edit: func(c *gatewayapi.Config) {
			o := validOverload()
			o.HeapShrinkThreshold = new(0.90)
			o.RequestRejectThreshold = new(0.80)
			c.Overload = o
		}},
		{name: "missing kubernetes memory limit", want: "overload requires a positive kubernetes.resources.limits.memory", edit: func(c *gatewayapi.Config) {
			c.Overload = validOverload()
			c.Kubernetes.Resources.Limits = map[string]string{}
		}},
		{name: "heap budget exceeds memory limit", want: "overload.max_heap_bytes", edit: func(c *gatewayapi.Config) {
			o := validOverload()
			o.MaxHeapBytes = 512 << 20
			c.Overload = o
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := loadTestConfig(t, exampleConfig, "valid baseline")
			test.edit(&config)
			if err := Validate(config); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validation error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestOptInOverloadDefaults(t *testing.T) {
	c := loadConfigCase(t, "public-routing")
	c.Overload = &gatewayapi.OverloadConfig{MaxHeapBytes: 201326592, MaxDownstreamConnections: 2048}
	resolved, err := resolveConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	want := &gatewayapi.OverloadConfig{MaxHeapBytes: 201326592, MaxDownstreamConnections: 2048, HeapShrinkThreshold: new(0.90), RequestRejectThreshold: new(0.95)}
	assertConfigDiff(t, "overload defaults", want, resolved.Overload)
	if c.Overload.HeapShrinkThreshold != nil {
		t.Error("default resolution added heap_shrink_threshold to the caller's configuration")
	}
	if c.Overload.RequestRejectThreshold != nil {
		t.Error("default resolution added request_reject_threshold to the caller's configuration")
	}
}

func TestOverloadGeneration(t *testing.T) {
	c := loadConfigCase(t, "public-routing")
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	if decodeBootstrap(t, files.EnvoyBootstrap.Contents).OverloadManager != nil {
		t.Fatal("overload enabled without explicit budgets")
	}
	c.Overload = &gatewayapi.OverloadConfig{MaxHeapBytes: 128 << 20, MaxDownstreamConnections: 1024, HeapShrinkThreshold: new(0.8), RequestRejectThreshold: new(0.85)}
	files, err = Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	o := decodeBootstrap(t, files.EnvoyBootstrap.Contents).OverloadManager
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
			c.Kubernetes.Resources = gatewayapi.KubernetesResourceRequirements{Requests: map[string]string{}, Limits: map[string]string{"memory": tt.limit}}
			c.Overload = &gatewayapi.OverloadConfig{MaxHeapBytes: tt.heap, MaxDownstreamConnections: 1}
			if err := Validate(c); (err == nil) != tt.valid {
				t.Fatalf("heap %d, limit %s: %v", tt.heap, tt.limit, err)
			}
			c.Kubernetes = nil
			if _, err := Generate(c); err != nil {
				t.Fatalf("file-only heap budget: %v", err)
			}
		})
	}
}
