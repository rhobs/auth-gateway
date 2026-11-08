package gateway

import (
	"fmt"
	"math"
	"strconv"
	"time"

	overload "github.com/envoyproxy/go-control-plane/envoy/config/overload/v3"
	connections "github.com/envoyproxy/go-control-plane/envoy/extensions/resource_monitors/downstream_connections/v3"
	heap "github.com/envoyproxy/go-control-plane/envoy/extensions/resource_monitors/fixed_heap/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	"google.golang.org/protobuf/types/known/durationpb"
	"k8s.io/apimachinery/pkg/api/resource"
)

const (
	heapMonitor = "envoy.resource_monitors.fixed_heap"
)

func withDefaultsOverloadConfig(o gatewayapi.OverloadConfig) gatewayapi.OverloadConfig {
	o.HeapShrinkThreshold = defaultValue(o.HeapShrinkThreshold, 0.90)
	o.RequestRejectThreshold = defaultValue(o.RequestRejectThreshold, 0.95)
	return o
}

func cloneOverloadConfig(o gatewayapi.OverloadConfig) gatewayapi.OverloadConfig {
	o.HeapShrinkThreshold = clonePointer(o.HeapShrinkThreshold)
	o.RequestRejectThreshold = clonePointer(o.RequestRejectThreshold)
	return o
}

func validateOverloadConfig(o gatewayapi.OverloadConfig, k *gatewayapi.Kubernetes) error {
	if o.MaxHeapBytes == 0 {
		return fmt.Errorf("overload.max_heap_bytes must be positive")
	}
	if o.MaxDownstreamConnections == 0 {
		return fmt.Errorf("overload.max_downstream_connections must be positive")
	}
	for _, field := range []struct {
		Name  string
		Value float64
	}{{"heap_shrink_threshold", *o.HeapShrinkThreshold}, {"request_reject_threshold", *o.RequestRejectThreshold}} {
		if math.IsNaN(field.Value) || math.IsInf(field.Value, 0) || field.Value <= 0 || field.Value >= 1 {
			return fmt.Errorf("overload.%s must be finite and between 0 and 1 (exclusive)", field.Name)
		}
	}
	if *o.HeapShrinkThreshold >= *o.RequestRejectThreshold {
		return fmt.Errorf("overload.heap_shrink_threshold must be less than overload.request_reject_threshold")
	}
	if k != nil {
		limit, err := resource.ParseQuantity(k.Resources.Limits[kubernetesMemoryResourceName])
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

func downstreamConnectionsResourceMonitor(maxConnections uint32) (*overload.ResourceMonitor, error) {
	connectionConfig, err := packEnvoy(&connections.DownstreamConnectionsConfig{MaxActiveDownstreamConnections: int64(maxConnections)})
	if err != nil {
		return nil, fmt.Errorf("encode downstream connection resource monitor: %w", err)
	}
	return &overload.ResourceMonitor{Name: "envoy.resource_monitors.global_downstream_max_connections", ConfigType: &overload.ResourceMonitor_TypedConfig{TypedConfig: connectionConfig}}, nil
}

func fixedHeapResourceMonitor(maxHeapBytes uint64) (*overload.ResourceMonitor, error) {
	heapConfig, err := packEnvoy(&heap.FixedHeapConfig{MaxHeapSizeBytes: maxHeapBytes})
	if err != nil {
		return nil, fmt.Errorf("encode heap resource monitor: %w", err)
	}
	return &overload.ResourceMonitor{Name: heapMonitor, ConfigType: &overload.ResourceMonitor_TypedConfig{TypedConfig: heapConfig}}, nil
}

func overloadManagerOverloadConfig(o gatewayapi.OverloadConfig) (*overload.OverloadManager, error) {
	heapMonitorConfig, err := fixedHeapResourceMonitor(o.MaxHeapBytes)
	if err != nil {
		return nil, err
	}
	connectionMonitorConfig, err := downstreamConnectionsResourceMonitor(o.MaxDownstreamConnections)
	if err != nil {
		return nil, err
	}
	manager := &overload.OverloadManager{
		RefreshInterval: durationpb.New(250 * time.Millisecond),
		ResourceMonitors: []*overload.ResourceMonitor{
			heapMonitorConfig,
			connectionMonitorConfig,
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
