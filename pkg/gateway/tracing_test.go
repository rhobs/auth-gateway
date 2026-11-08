package gateway

import (
	"strings"
	"testing"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	traceconfig "github.com/envoyproxy/go-control-plane/envoy/config/trace/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	upstreamhttp "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
)

func TestTracingRequiresValidEndpointAndSampling(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*gatewayapi.Config)
		wantErr string
	}{
		{
			name: "endpoint required",
			mutate: func(c *gatewayapi.Config) {
				c.Observability.Tracing.Enabled = new(true)
			},
			wantErr: "observability.tracing.endpoint is required",
		},
		{
			name: "endpoint must be host and port",
			mutate: func(c *gatewayapi.Config) {
				c.Observability.Tracing.Enabled = new(true)
				c.Observability.Tracing.Endpoint = "https://collector.example.com:4317"
			},
			wantErr: "observability.tracing.endpoint must be a host:port",
		},
		{
			name: "sampling is bounded",
			mutate: func(c *gatewayapi.Config) {
				c.Observability.Tracing.Enabled = new(true)
				c.Observability.Tracing.Endpoint = "collector.example.com:4317"
				c.Observability.Tracing.SamplingPercentage = new(100.1)
			},
			wantErr: "observability.tracing.sampling_percentage must be between 0 and 100",
		},
		{
			name: "trace collector port is reserved",
			mutate: func(c *gatewayapi.Config) {
				c.Observability.Tracing.Enabled = new(true)
				c.Observability.Tracing.Endpoint = "collector.example.com:4317"
				c.Listener.Port = new(uint32(defaultOTelTracePort))
			},
			wantErr: "listener.port must not conflict with the OTLP trace collector port",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := loadConfigCase(t, "public-routing")
			test.mutate(&c)
			err := Validate(c)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("Validate() error = %v, want %q", err, test.wantErr)
			}
		})
	}
}

func TestGenerateEnvoyOpenTelemetryTracing(t *testing.T) {
	c := loadConfigCase(t, "public-routing")
	c.Observability.Tracing = gatewayapi.ObservabilityTracing{
		Enabled:            new(true),
		Endpoint:           "otel-collector.observability.svc:4317",
		ServiceName:        "auth-gateway-test",
		SamplingPercentage: new(12.5),
		Insecure:           new(true),
	}

	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	bootstrapConfig := decodeBootstrap(t, files.EnvoyBootstrap.Contents)
	var traceCluster *cluster.Cluster
	for _, generatedCluster := range bootstrapConfig.GetStaticResources().GetClusters() {
		if generatedCluster.GetName() == envoyTraceClusterName {
			traceCluster = generatedCluster
			break
		}
	}
	if traceCluster == nil {
		t.Fatal("trace collector cluster is missing")
	}
	if traceCluster.GetType() != cluster.Cluster_STATIC {
		t.Fatalf("trace cluster type = %s, want STATIC", traceCluster.GetType())
	}
	if got := traceCluster.GetLoadAssignment().GetEndpoints()[0].GetLbEndpoints()[0].GetEndpoint().GetAddress().GetSocketAddress(); got.GetAddress() != defaultOTelTraceReceiverAddress || got.GetPortValue() != defaultOTelTracePort {
		t.Fatalf("trace collector address = %s:%d", got.GetAddress(), got.GetPortValue())
	}
	var protocolOptions upstreamhttp.HttpProtocolOptions
	if err := traceCluster.GetTypedExtensionProtocolOptions()["envoy.extensions.upstreams.http.v3.HttpProtocolOptions"].UnmarshalTo(&protocolOptions); err != nil {
		t.Fatal(err)
	}
	if protocolOptions.GetExplicitHttpConfig().GetHttp2ProtocolOptions() == nil {
		t.Fatal("trace collector cluster does not use HTTP/2")
	}

	listener := bootstrapConfig.GetStaticResources().GetListeners()[0]
	var manager hcm.HttpConnectionManager
	if err := listener.GetFilterChains()[0].GetFilters()[0].GetTypedConfig().UnmarshalTo(&manager); err != nil {
		t.Fatal(err)
	}
	tracing := manager.GetTracing()
	if tracing == nil || tracing.GetRandomSampling().GetValue() != 12.5 || tracing.GetOverallSampling().GetValue() != 12.5 || !tracing.GetSpawnUpstreamSpan().GetValue() {
		t.Fatalf("HTTP tracing settings = %#v", tracing)
	}
	if tracing.GetProvider().GetName() != envoyOTelTracerName {
		t.Fatalf("tracing provider = %q", tracing.GetProvider().GetName())
	}
	var provider traceconfig.OpenTelemetryConfig
	if err := tracing.GetProvider().GetTypedConfig().UnmarshalTo(&provider); err != nil {
		t.Fatal(err)
	}
	if provider.GetServiceName() != "auth-gateway-test" || provider.GetGrpcService().GetEnvoyGrpc().GetClusterName() != envoyTraceClusterName {
		t.Fatalf("OpenTelemetry service and cluster = %q/%q", provider.GetServiceName(), provider.GetGrpcService().GetEnvoyGrpc().GetClusterName())
	}
}
