package config

import (
	"fmt"
	"math"
	"strconv"

	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	"k8s.io/apimachinery/pkg/api/resource"
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
		limit, err := resource.ParseQuantity(k.Resources.Limits[KubernetesMemoryResourceName])
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
