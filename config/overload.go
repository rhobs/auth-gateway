package config

import (
	"fmt"
	"math"
	"strconv"
	"time"

	overload "github.com/envoyproxy/go-control-plane/envoy/config/overload/v3"
	connections "github.com/envoyproxy/go-control-plane/envoy/extensions/resource_monitors/downstream_connections/v3"
	heap "github.com/envoyproxy/go-control-plane/envoy/extensions/resource_monitors/fixed_heap/v3"
	"google.golang.org/protobuf/types/known/durationpb"
	"k8s.io/apimachinery/pkg/api/resource"
)

// OverloadConfig enables process safeguards with explicit capacity budgets.
type OverloadConfig struct {
	MaxHeapBytes             uint64   `yaml:"max_heap_bytes"`
	MaxDownstreamConnections uint32   `yaml:"max_downstream_connections"`
	HeapShrinkThreshold      *float64 `yaml:"heap_shrink_threshold,omitempty"`
	RequestRejectThreshold   *float64 `yaml:"request_reject_threshold,omitempty"`
}

func (o *OverloadConfig) withDefaults() *OverloadConfig {
	if o == nil {
		return nil
	}
	copy := *o
	copy.HeapShrinkThreshold = defaultValue(o.HeapShrinkThreshold, 0.90)
	copy.RequestRejectThreshold = defaultValue(o.RequestRejectThreshold, 0.95)
	return &copy
}

func (o *OverloadConfig) validate(k *Kubernetes) error {
	if o == nil {
		return nil
	}
	if o.MaxHeapBytes == 0 {
		return fmt.Errorf("overload.max_heap_bytes must be positive")
	}
	if o.MaxDownstreamConnections == 0 {
		return fmt.Errorf("overload.max_downstream_connections must be positive")
	}
	for _, field := range []struct {
		name  string
		value float64
	}{{"heap_shrink_threshold", *o.HeapShrinkThreshold}, {"request_reject_threshold", *o.RequestRejectThreshold}} {
		if math.IsNaN(field.value) || math.IsInf(field.value, 0) || field.value <= 0 || field.value >= 1 {
			return fmt.Errorf("overload.%s must be finite and between 0 and 1 (exclusive)", field.name)
		}
	}
	if *o.HeapShrinkThreshold >= *o.RequestRejectThreshold {
		return fmt.Errorf("overload.heap_shrink_threshold must be less than overload.request_reject_threshold")
	}
	if k != nil {
		limit, err := resource.ParseQuantity(k.Resources.Limits["memory"])
		if err != nil || limit.Sign() <= 0 {
			return fmt.Errorf("overload requires a positive kubernetes.resources.limits.memory")
		}
		// Decimal quantities preserve the full uint64 budget without an int64 cast.
		heapSize := resource.MustParse(strconv.FormatUint(o.MaxHeapBytes, 10))
		if heapSize.Cmp(limit) >= 0 {
			return fmt.Errorf("overload.max_heap_bytes (%d) must be less than kubernetes.resources.limits.memory (%s)", o.MaxHeapBytes, limit.String())
		}
	}
	return nil
}

func overloadManager(o *OverloadConfig) (*overload.OverloadManager, error) {
	if o == nil {
		return nil, nil
	}
	heapConfig, err := packEnvoy(&heap.FixedHeapConfig{MaxHeapSizeBytes: o.MaxHeapBytes})
	if err != nil {
		return nil, fmt.Errorf("encode heap resource monitor: %w", err)
	}
	connectionConfig, err := packEnvoy(&connections.DownstreamConnectionsConfig{MaxActiveDownstreamConnections: int64(o.MaxDownstreamConnections)})
	if err != nil {
		return nil, fmt.Errorf("encode downstream connection resource monitor: %w", err)
	}
	const heapMonitor = "envoy.resource_monitors.fixed_heap"
	manager := &overload.OverloadManager{
		RefreshInterval: durationpb.New(250 * time.Millisecond),
		ResourceMonitors: []*overload.ResourceMonitor{
			{Name: heapMonitor, ConfigType: &overload.ResourceMonitor_TypedConfig{TypedConfig: heapConfig}},
			{Name: "envoy.resource_monitors.global_downstream_max_connections", ConfigType: &overload.ResourceMonitor_TypedConfig{TypedConfig: connectionConfig}},
		},
	}
	for _, action := range []struct {
		name      string
		threshold float64
	}{{"envoy.overload_actions.shrink_heap", *o.HeapShrinkThreshold}, {"envoy.overload_actions.stop_accepting_requests", *o.RequestRejectThreshold}} {
		manager.Actions = append(manager.Actions, &overload.OverloadAction{
			Name:     action.name,
			Triggers: []*overload.Trigger{{Name: heapMonitor, TriggerOneof: &overload.Trigger_Threshold{Threshold: &overload.ThresholdTrigger{Value: action.threshold}}}},
		})
	}
	return manager, nil
}
