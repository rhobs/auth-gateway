package envoy

import (
	"fmt"

	overload "github.com/envoyproxy/go-control-plane/envoy/config/overload/v3"
	heap "github.com/envoyproxy/go-control-plane/envoy/extensions/resource_monitors/fixed_heap/v3"
)

const heapMonitor = "envoy.resource_monitors.fixed_heap"

func fixedHeapResourceMonitor(maxHeapBytes uint64) (*overload.ResourceMonitor, error) {
	heapConfig, err := packEnvoy(&heap.FixedHeapConfig{MaxHeapSizeBytes: maxHeapBytes})
	if err != nil {
		return nil, fmt.Errorf("encode heap resource monitor: %w", err)
	}
	return &overload.ResourceMonitor{Name: heapMonitor, ConfigType: &overload.ResourceMonitor_TypedConfig{TypedConfig: heapConfig}}, nil
}
