package config

import (
	"testing"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	traceconfig "github.com/envoyproxy/go-control-plane/envoy/config/trace/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	upstreamhttp "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
)

func TestGenerateEnvoyOpenTelemetryTracing(t *testing.T) {
	c := loadConfigCase(t, "public-routing")
	c.Observability.Tracing = ObservabilityTracing{
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
