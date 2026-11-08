package envoy

import (
	"math"
	"testing"
	"time"

	connections "github.com/envoyproxy/go-control-plane/envoy/extensions/resource_monitors/downstream_connections/v3"
	heap "github.com/envoyproxy/go-control-plane/envoy/extensions/resource_monitors/fixed_heap/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	configuration "github.com/rhobs/auth-gateway/pkg/config"
)

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
			if err := configuration.Validate(c); (err == nil) != tt.valid {
				t.Fatalf("heap %d, limit %s: %v", tt.heap, tt.limit, err)
			}
			c.Kubernetes = nil
			if _, err := Generate(c); err != nil {
				t.Fatalf("file-only heap budget: %v", err)
			}
		})
	}
}
