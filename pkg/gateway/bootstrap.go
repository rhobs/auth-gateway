package gateway

import (
	"fmt"

	bootstrap "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
)

func generateBootstrap(c resolvedConfig) (*bootstrap.Bootstrap, error) {
	clusters, err := generateClusters(c)
	if err != nil {
		return nil, err
	}
	filterChains, err := generateFilterChains(c)
	if err != nil {
		return nil, err
	}
	listenerFilters, err := generateListenerFilters(c)
	if err != nil {
		return nil, err
	}
	bootstrapConfig := &bootstrap.Bootstrap{
		Node:  &core.Node{Id: c.Node.ID, Cluster: c.Node.Cluster},
		Admin: &bootstrap.Admin{Address: socket(envoyAdminAddress, envoyAdminPort)},
		StaticResources: &bootstrap.Bootstrap_StaticResources{
			Listeners: []*listener.Listener{{
				Name:                          ingestionListenerName,
				Address:                       socket(envoyListenerAddress, *c.Listener.Port),
				PerConnectionBufferLimitBytes: optionalUint32(c.Listener.PerConnectionBufferLimitBytes),
				ListenerFilters:               listenerFilters,
				FilterChains:                  filterChains,
			}},
			Clusters: clusters,
		},
	}
	if c.Overload != nil {
		bootstrapConfig.OverloadManager, err = overloadManagerOverloadConfig(*c.Overload)
		if err != nil {
			return nil, err
		}
	}
	if hasRequestMetrics(c.Config) {
		bootstrapConfig.StatsConfig = requestMetricsStatsConfig(c.APIs, requestMetricName(c.Config))
	}
	return bootstrapConfig, nil
}

func generateClusters(c resolvedConfig) ([]*cluster.Cluster, error) {
	clusters, err := apiClusters(c.APIs)
	if err != nil {
		return nil, err
	}
	jwks, err := jwksClusters(c)
	if err != nil {
		return nil, err
	}
	clusters = append(clusters, jwks...)
	if enabledObservabilityTracing(c.Observability.Tracing) {
		tracingCluster, err := otelTraceCluster()
		if err != nil {
			return nil, fmt.Errorf("OpenTelemetry trace cluster: %w", err)
		}
		clusters = append(clusters, tracingCluster)
	}
	return clusters, nil
}
