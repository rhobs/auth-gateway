package gateway

import (
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	traceconfig "github.com/envoyproxy/go-control-plane/envoy/config/trace/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoytype "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	defaultOTelTracePort            = 4317
	defaultOTelTraceReceiverAddress = "127.0.0.1"
)

func validateOTelTraceEndpoint(endpoint string) error {
	host, portText, err := net.SplitHostPort(endpoint)
	if err != nil || !validHost(host) {
		return fmt.Errorf("observability.tracing.endpoint must be a host:port for an OTLP gRPC endpoint")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return fmt.Errorf("observability.tracing.endpoint port must be between 1 and 65535")
	}
	if strings.ContainsAny(endpoint, invalidControlCharacters) {
		return fmt.Errorf("observability.tracing.endpoint must not contain control characters")
	}
	return nil
}

func cloneObservabilityTracing(t gatewayapi.ObservabilityTracing) gatewayapi.ObservabilityTracing {
	t.Enabled = clonePointer(t.Enabled)
	t.SamplingPercentage = clonePointer(t.SamplingPercentage)
	t.Insecure = clonePointer(t.Insecure)
	return t
}

func enabledObservabilityTracing(t gatewayapi.ObservabilityTracing) bool {
	return t.Enabled != nil && *t.Enabled
}

func validateObservabilityTracing(t gatewayapi.ObservabilityTracing) error {
	if enabledObservabilityTracing(t) && (strings.TrimSpace(t.ServiceName) == "" || strings.ContainsAny(t.ServiceName, invalidControlCharacters)) {
		return fmt.Errorf("observability.tracing.service_name must not be empty or contain control characters")
	}
	if percentage := *t.SamplingPercentage; math.IsNaN(percentage) || math.IsInf(percentage, 0) || percentage < 0 || percentage > 100 {
		return fmt.Errorf("observability.tracing.sampling_percentage must be between 0 and 100")
	}
	if t.Endpoint != "" {
		if err := validateOTelTraceEndpoint(t.Endpoint); err != nil {
			return err
		}
	}
	if enabledObservabilityTracing(t) && t.Endpoint == "" {
		return fmt.Errorf("observability.tracing.endpoint is required when tracing is enabled")
	}
	return nil
}

func tracingConfig(config gatewayapi.ObservabilityTracing) (*hcm.HttpConnectionManager_Tracing, error) {
	if !enabledObservabilityTracing(config) {
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
