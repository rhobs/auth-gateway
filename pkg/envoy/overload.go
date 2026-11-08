package envoy

import (
	"time"

	overload "github.com/envoyproxy/go-control-plane/envoy/config/overload/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	"google.golang.org/protobuf/types/known/durationpb"
)

func toOverloadManagerOverloadConfig(o gatewayapi.OverloadConfig) (*overload.OverloadManager, error) {
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
