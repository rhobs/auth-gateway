package config

import (
	"fmt"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	traceconfig "github.com/envoyproxy/go-control-plane/envoy/config/trace/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoytype "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const envoyOTelTracerName = "envoy.tracers.opentelemetry"

func (config ObservabilityTracing) toEnvoyTracingConfig() (*hcm.HttpConnectionManager_Tracing, error) {
	if !config.enabled() {
		return nil, nil
	}
	providerConfig, err := packEnvoy(&traceconfig.OpenTelemetryConfig{
		GrpcService: &core.GrpcService{TargetSpecifier: &core.GrpcService_EnvoyGrpc_{EnvoyGrpc: &core.GrpcService_EnvoyGrpc{
			ClusterName: envoyTraceClusterName,
		}}},
		ServiceName: config.ServiceName,
	})
	if err != nil {
		return nil, fmt.Errorf("encode OpenTelemetry tracing provider: %w", err)
	}
	percentage := *config.SamplingPercentage
	return &hcm.HttpConnectionManager_Tracing{
		ClientSampling:    &envoytype.Percent{Value: percentage},
		RandomSampling:    &envoytype.Percent{Value: percentage},
		OverallSampling:   &envoytype.Percent{Value: percentage},
		SpawnUpstreamSpan: wrapperspb.Bool(true),
		Provider: &traceconfig.Tracing_Http{
			Name:       envoyOTelTracerName,
			ConfigType: &traceconfig.Tracing_Http_TypedConfig{TypedConfig: providerConfig},
		},
	}, nil
}
