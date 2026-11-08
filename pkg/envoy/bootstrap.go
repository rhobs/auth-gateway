package envoy

import (
	"fmt"

	bootstrap "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	configuration "github.com/rhobs/auth-gateway/pkg/config"
)

func generateBootstrap(c configuration.ResolvedConfig) (*bootstrap.Bootstrap, error) {
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
		Admin: &bootstrap.Admin{Address: socket(configuration.EnvoyAdminAddress, configuration.EnvoyAdminPort)},
		StaticResources: &bootstrap.Bootstrap_StaticResources{
			Listeners: []*listener.Listener{{
				Name:                          configuration.IngestionListenerName,
				Address:                       socket(configuration.EnvoyListenerAddress, *c.Listener.Port),
				PerConnectionBufferLimitBytes: optionalUint32(c.Listener.PerConnectionBufferLimitBytes),
				ListenerFilters:               listenerFilters,
				FilterChains:                  filterChains,
			}},
			Clusters: clusters,
		},
	}
	if c.Overload != nil {
		bootstrapConfig.OverloadManager, err = toOverloadManagerOverloadConfig(*c.Overload)
		if err != nil {
			return nil, err
		}
	}
	if configuration.HasRequestMetricsConfig(c.Config) {
		bootstrapConfig.StatsConfig = requestMetricsStatsConfig(c.APIs, configuration.RequestMetricNameConfig(c.Config))
	}
	return bootstrapConfig, nil
}

func generateClusters(c configuration.ResolvedConfig) ([]*cluster.Cluster, error) {
	clusters, err := apiClusters(c.APIs)
	if err != nil {
		return nil, err
	}
	jwks, err := jwksClusters(c)
	if err != nil {
		return nil, err
	}
	clusters = append(clusters, jwks...)
	if configuration.EnabledObservabilityTracing(c.Observability.Tracing) {
		tracingCluster, err := otelTraceCluster()
		if err != nil {
			return nil, fmt.Errorf("OpenTelemetry trace cluster: %w", err)
		}
		clusters = append(clusters, tracingCluster)
	}
	return clusters, nil
}
