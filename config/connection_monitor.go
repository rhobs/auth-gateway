package config

import (
	"fmt"

	overload "github.com/envoyproxy/go-control-plane/envoy/config/overload/v3"
	connections "github.com/envoyproxy/go-control-plane/envoy/extensions/resource_monitors/downstream_connections/v3"
)

func downstreamConnectionsResourceMonitor(maxConnections uint32) (*overload.ResourceMonitor, error) {
	connectionConfig, err := packEnvoy(&connections.DownstreamConnectionsConfig{MaxActiveDownstreamConnections: int64(maxConnections)})
	if err != nil {
		return nil, fmt.Errorf("encode downstream connection resource monitor: %w", err)
	}
	return &overload.ResourceMonitor{Name: "envoy.resource_monitors.global_downstream_max_connections", ConfigType: &overload.ResourceMonitor_TypedConfig{TypedConfig: connectionConfig}}, nil
}
