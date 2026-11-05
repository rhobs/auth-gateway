package config

import (
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	traceconfig "github.com/envoyproxy/go-control-plane/envoy/config/trace/v3"
	lua "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/lua/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	upstreamhttp "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	"go.yaml.in/yaml/v3"
	"k8s.io/apimachinery/pkg/api/resource"
)

func TestObservabilityDefaults(t *testing.T) {
	c := loadTestConfig(t, readFixture(t, "defaults.yaml"), "defaults fixture")
	wantObservability := ObservabilityConfig{Metrics: ObservabilityMetrics{
		Enabled: new(true), ScrapeInterval: duration(30 * time.Second), ScrapeTimeout: duration(10 * time.Second),
	}, Tracing: ObservabilityTracing{
		Enabled: new(false), ServiceName: "auth-gateway", SamplingPercentage: new(100.0), Insecure: new(false),
	}}
	assertConfigDiff(t, "observability defaults", wantObservability, c.Observability)
	wantCollectorResources := KubernetesResourceRequirements{
		Requests: map[string]string{"cpu": "20m", "memory": "64Mi"},
		Limits:   map[string]string{"memory": "256Mi"},
	}
	if got, want := c.Kubernetes.OTelCollectorImage, DefaultOTelCollectorImage; got != want {
		t.Errorf("collector image = %q, want %q", got, want)
	}
	assertConfigDiff(t, "collector resources defaults", wantCollectorResources, c.Kubernetes.Metrics.Resources)
}

func TestObservabilityDefaultsDoNotMutateInput(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-with-attributes")
	c.Observability.Metrics.CustomMetricName = new("gateway_http_requests_total")
	defaulted := c.withDefaults()
	defaulted.APIs[0].Metrics.Labels["tenant"] = "writer_id"
	*defaulted.Observability.Metrics.CustomMetricName = "changed_requests_total"
	*defaulted.Observability.Metrics.ScrapeInterval = Duration(time.Second)
	defaulted.Kubernetes.Metrics.Resources.Requests["cpu"] = "10m"
	got := struct {
		TenantLabel      string
		CustomMetricName string
		ScrapeInterval   Duration
		CPURequest       string
	}{
		TenantLabel:      c.APIs[0].Metrics.Labels["tenant"],
		CustomMetricName: *c.Observability.Metrics.CustomMetricName,
		ScrapeInterval:   *c.Observability.Metrics.ScrapeInterval,
		CPURequest:       c.Kubernetes.Metrics.Resources.Requests["cpu"],
	}
	want := struct {
		TenantLabel      string
		CustomMetricName string
		ScrapeInterval   Duration
		CPURequest       string
	}{
		TenantLabel:      "tenant_id",
		CustomMetricName: "gateway_http_requests_total",
		ScrapeInterval:   Duration(30 * time.Second),
		CPURequest:       "20m",
	}
	assertConfigDiff(t, "input after defaulting", want, got)
}

func TestKubernetesObservabilityDefaults(t *testing.T) {
	defaults := []struct {
		name string
		file string
	}{
		{name: "metrics omitted", file: "public-routing/config.yaml"},
		{name: "metrics null", file: "kubernetes-options/metrics-null.yaml"},
		{name: "metrics empty", file: "kubernetes-options/metrics-empty.yaml"},
		{name: "nested nulls", file: "kubernetes-options/nested-null.yaml"},
	}
	for _, test := range defaults {
		t.Run(test.name, func(t *testing.T) {
			c := loadTestConfig(t, readFixture(t, test.file), test.name)
			metrics := c.Observability.Metrics
			collectorResources := c.Kubernetes.Metrics.Resources
			wantResources := KubernetesResourceRequirements{
				Requests: map[string]string{"cpu": "20m", "memory": "64Mi"},
				Limits:   map[string]string{"memory": "256Mi"},
			}
			type metricDefaults struct {
				Enabled        *bool
				ScrapeInterval *Duration
				ScrapeTimeout  *Duration
			}
			gotMetrics := metricDefaults{
				Enabled:        metrics.Enabled,
				ScrapeInterval: metrics.ScrapeInterval,
				ScrapeTimeout:  metrics.ScrapeTimeout,
			}
			wantMetrics := metricDefaults{
				Enabled:        new(true),
				ScrapeInterval: duration(30 * time.Second),
				ScrapeTimeout:  duration(10 * time.Second),
			}
			assertConfigDiff(t, "defaulted metrics", wantMetrics, gotMetrics)
			assertConfigDiff(t, "defaulted collector resources", wantResources, collectorResources)
			if got, want := c.Kubernetes.OTelCollectorImage, DefaultOTelCollectorImage; got != want {
				t.Errorf("collector image = %q, want %q", got, want)
			}
		})
	}
}

func TestKubernetesObservabilityDefaultsPreserveExplicitResourceMaps(t *testing.T) {
	c := loadTestConfig(t, readFixture(t, "kubernetes-options/empty-resource-maps.yaml"), "empty resource maps")
	resources := c.Kubernetes.Metrics.Resources
	if resources.Limits == nil {
		t.Error("collector resource defaults replaced the explicitly empty limits map with nil")
	}
	if len(resources.Limits) != 0 {
		t.Errorf("collector limits = %v, want an empty map", resources.Limits)
	}
	assertConfigDiff(t, "collector requests", map[string]string{"cpu": "5m"}, resources.Requests)
}

func TestAPIMetricsConfigurationAndValidation(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-with-attributes")
	type apiMetricsDefaults struct {
		Configured bool
		Tenant     string
		LabelCount int
	}
	gotMetrics := make([]apiMetricsDefaults, 0, len(c.APIs))
	for _, api := range c.APIs {
		settings := apiMetricsDefaults{}
		if api.Metrics != nil {
			settings.Configured = true
			settings.Tenant = api.Metrics.Labels["tenant"]
			settings.LabelCount = len(api.Metrics.Labels)
		}
		gotMetrics = append(gotMetrics, settings)
	}
	wantMetrics := []apiMetricsDefaults{
		{Configured: true, Tenant: "tenant_id", LabelCount: 1},
		{Configured: true},
	}
	assertConfigDiff(t, "fixture API metrics", wantMetrics, gotMetrics)

	tests := []struct {
		name string
		want string
		edit func(*Config)
	}{
		{name: "invalid label name", want: "apis[0].metrics.labels", edit: func(c *Config) { c.APIs[0].Metrics.Labels["bad-name"] = "tenant_id" }},
		{name: "reserved API label", want: "apis[0].metrics.labels", edit: func(c *Config) { c.APIs[0].Metrics.Labels["api"] = "tenant_id" }},
		{name: "reserved status label", want: "apis[0].metrics.labels", edit: func(c *Config) { c.APIs[0].Metrics.Labels["http_status_code"] = "tenant_id" }},
		{name: "reserved Prometheus prefix", want: "apis[0].metrics.labels", edit: func(c *Config) { c.APIs[0].Metrics.Labels["__internal"] = "tenant_id" }},
		{name: "reserved Envoy label", want: "apis[0].metrics.labels", edit: func(c *Config) { c.APIs[0].Metrics.Labels["envoy_http_conn_manager_prefix"] = "tenant_id" }},
		{name: "invalid attribute name", want: "apis[0].metrics.labels.tenant", edit: func(c *Config) { c.APIs[0].Metrics.Labels["tenant"] = "TenantID" }},
		{name: "unknown attribute", want: "apis[0].metrics.labels.tenant references unknown authenticator attribute", edit: func(c *Config) { c.APIs[0].Metrics.Labels["tenant"] = "unknown" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := loadConfigCase(t, "jwt-auth-with-attributes")
			test.edit(&config)
			if err := config.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestRequestMetricNameConfigurationAndValidation(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-with-attributes")
	c.Observability.Metrics.CustomMetricName = new("gateway_http_requests_total")
	if err := c.Validate(); err != nil {
		t.Fatalf("valid custom metric name was rejected: %v", err)
	}
	for _, test := range []struct{ name, value string }{
		{name: "empty"},
		{name: "leading digit", value: "9requests_total"},
		{name: "hyphen", value: "bad-name"},
		{name: "period", value: "bad.name"},
		{name: "stat delimiter", value: "bad|name"},
		{name: "reserved prefix", value: "__reserved"},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := loadConfigCase(t, "jwt-auth-with-attributes")
			config.Observability.Metrics.CustomMetricName = new(test.value)
			if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "observability.metrics.custom_metric_name") {
				t.Fatalf("Validate error = %v, want observability.metrics.custom_metric_name", err)
			}
		})
	}
}

func TestRequestMetricsGenerateTagsAndRouteMetadata(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-with-attributes")
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := decodeBootstrap(t, files.EnvoyBootstrap.Contents)
	tags := bootstrap.GetStatsConfig().GetStatsTags()
	if len(tags) != 3 {
		t.Fatalf("stats tags = %#v, want API, status, and tenant", tags)
	}
	raw := "http.ingress.lua.gateway_http_requests_total|api=metrics-write|http_status_code=403|tenant=team-a"
	for i, want := range []struct{ label, value string }{{"api", "metrics-write"}, {"http_status_code", "403"}, {"tenant", "team-a"}} {
		if tags[i].GetTagName() != want.label {
			t.Fatalf("tag %d name = %q, want %q", i, tags[i].GetTagName(), want.label)
		}
		pattern, err := regexp.Compile(tags[i].GetRegex())
		if err != nil {
			t.Fatal(err)
		}
		groups := pattern.FindStringSubmatch(raw)
		if len(groups) != 3 || groups[2] != want.value {
			t.Fatalf("tag %q matched %q with groups %v", want.label, raw, groups)
		}
	}

	manager := firstHTTPManager(t, files.EnvoyBootstrap.Contents)
	var luaConfig lua.Lua
	for _, filter := range manager.HttpFilters {
		if filter.Name == requestMetricsFilterName {
			if err := filter.GetTypedConfig().UnmarshalTo(&luaConfig); err != nil {
				t.Fatal(err)
			}
		}
	}
	script := luaConfig.GetDefaultSourceCode().GetInlineString()
	if !strings.Contains(script, `local counter_name = "gateway_http_requests_total"`) ||
		!strings.Contains(script, "function envoy_on_response(response_handle)") ||
		!strings.Contains(script, `filter_state:get("auth_gateway.attributes." .. attribute)`) ||
		strings.Contains(script, "function envoy_on_request") {
		t.Fatalf("generated Lua is missing response-only metric collection: %s", script)
	}

	routes := manager.GetRouteConfig().GetVirtualHosts()[0].GetRoutes()
	metricRoute := namedRoute(routes, apiRouteName(0, "metrics-write", 0, 0))
	if metricRoute == nil {
		t.Fatal("metrics-write route is missing")
	}
	metricMetadata := metricRoute.GetMetadata().GetFilterMetadata()[requestMetricsFilterName]
	if metricMetadata == nil || metricMetadata.Fields[apiMetadataName].GetStringValue() != "metrics-write" ||
		metricMetadata.Fields["labels"].GetStructValue().Fields["tenant"].GetStringValue() != "tenant_id" {
		t.Fatalf("metrics-write route metadata = %#v", metricMetadata)
	}
	statusOnlyRoute := namedRoute(routes, apiRouteName(1, "logs", 0, 0))
	if statusOnlyRoute == nil {
		t.Fatal("logs route is missing")
	}
	statusMetadata := statusOnlyRoute.GetMetadata().GetFilterMetadata()[requestMetricsFilterName]
	if statusMetadata == nil || statusMetadata.Fields[apiMetadataName].GetStringValue() != "logs" ||
		len(statusMetadata.Fields["labels"].GetStructValue().Fields) != 0 {
		t.Fatalf("status-only route metadata = %#v", statusMetadata)
	}
	for _, generated := range routes {
		if strings.HasPrefix(generated.Name, "method-not-allowed-") || generated.Name == "not-found" {
			if generated.GetMetadata().GetFilterMetadata()[requestMetricsFilterName] != nil {
				t.Fatalf("fallback route %q has request metric metadata", generated.Name)
			}
		}
	}
}

func TestRequestMetricsDefaultCounterName(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-with-attributes")
	c.Observability.Metrics.CustomMetricName = nil
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := decodeBootstrap(t, files.EnvoyBootstrap.Contents)
	if tags := bootstrap.GetStatsConfig().GetStatsTags(); len(tags) == 0 ||
		!strings.Contains(tags[0].GetRegex(), "auth_gateway_http_requests_total") {
		t.Fatalf("default request metric stats tags = %#v", tags)
	}
	if !strings.Contains(string(files.EnvoyBootstrap.Contents), `local counter_name = "auth_gateway_http_requests_total"`) {
		t.Fatal("default request metric name is missing from Lua")
	}
}

func TestRequestMetricNameAloneDoesNotEnableCounter(t *testing.T) {
	c := loadConfigCase(t, "public-routing")
	c.Observability.Metrics.CustomMetricName = new("gateway_http_requests_total")
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := decodeBootstrap(t, files.EnvoyBootstrap.Contents)
	if bootstrap.GetStatsConfig() != nil {
		t.Fatal("name-only request metric configuration added stats tags")
	}
	manager := decodeHTTPManager(t, bootstrap.StaticResources.Listeners[0].FilterChains[0])
	if containsFilter(manager, requestMetricsFilterName) {
		t.Fatal("name-only request metric configuration added Lua")
	}
}

func TestRequestMetricsUseAttributesWithoutHeaderProcessing(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth")
	c.APIs[0].Metrics = &APIMetrics{Labels: map[string]string{"tenant": "tenant_id"}}
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	manager := firstHTTPManager(t, files.EnvoyBootstrap.Contents)
	want := []string{requestControlsFilterName, requestMetricsFilterName, jwtAuthnFilterName, attributeFilterName, authorizationFilterName, credentialCleanupFilterName, routerFilterName}
	if got := httpFilterNames(manager); !slices.Equal(got, want) {
		t.Fatalf("HTTP filters = %v, want %v", got, want)
	}
}

func TestRequestMetricsFilterPrecedesJWTAttributeInitialization(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-with-attributes")
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	manager := firstHTTPManager(t, files.EnvoyBootstrap.Contents)
	want := []string{
		requestControlsFilterName, requestMetricsFilterName, jwtAuthnFilterName, attributeFilterName,
		authorizationFilterName, requiredHeaderFilterName, credentialCleanupFilterName, headerMutationFilterName, routerFilterName,
	}
	if got := httpFilterNames(manager); !slices.Equal(got, want) {
		t.Fatalf("HTTP filters = %v, want %v", got, want)
	}
}

func TestRequestMetricsFilterPrecedesAPIKeyAuthentication(t *testing.T) {
	c := loadConfigCase(t, "api-key-auth")
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	manager := firstHTTPManager(t, files.EnvoyBootstrap.Contents)
	got := httpFilterNames(manager)
	want := []string{requestControlsFilterName, requestMetricsFilterName, jwtAuthnFilterName, apiKeyFilterName}
	if len(got) < len(want) || !slices.Equal(got[:len(want)], want) {
		t.Fatalf("HTTP filter prefix = %v, want %v", got, want)
	}
}

func TestStatusOnlyRequestMetricsOnPublicAPI(t *testing.T) {
	c := loadConfigCase(t, "public-routing")
	c.APIs[0].Metrics = &APIMetrics{}
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := decodeBootstrap(t, files.EnvoyBootstrap.Contents)
	if got := len(bootstrap.GetStatsConfig().GetStatsTags()); got != 2 {
		t.Fatalf("status-only stats tags = %d, want API and status", got)
	}
	manager := decodeHTTPManager(t, bootstrap.StaticResources.Listeners[0].FilterChains[0])
	want := []string{requestControlsFilterName, requestMetricsFilterName, routerFilterName}
	if got := httpFilterNames(manager); !slices.Equal(got, want) {
		t.Fatalf("public HTTP filters = %v, want %v", got, want)
	}
}

func TestRequestMetricsOnlyOnSelectedAPIs(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-with-attributes")
	c.APIs[1].Metrics = nil
	c.Servers[1].APIs = []string{"logs"}
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := decodeBootstrap(t, files.EnvoyBootstrap.Contents)
	for _, chain := range bootstrap.StaticResources.Listeners[0].FilterChains {
		manager := decodeHTTPManager(t, chain)
		metered := chain.GetFilterChainMatch().GetTransportProtocol() != "tls"
		if containsFilter(manager, requestMetricsFilterName) != metered {
			t.Fatalf("chain %q metrics filter = %t, want %t", chain.GetFilterChainMatch().GetTransportProtocol(), containsFilter(manager, requestMetricsFilterName), metered)
		}
		for _, host := range manager.GetRouteConfig().GetVirtualHosts() {
			for _, generated := range host.GetRoutes() {
				if strings.Contains(generated.Name, "-logs-") && generated.GetMetadata().GetFilterMetadata()[requestMetricsFilterName] != nil {
					t.Fatalf("unmetered logs route %q has metric metadata", generated.Name)
				}
			}
		}
	}
}

func namedRoute(routes []*route.Route, name string) *route.Route {
	for _, generated := range routes {
		if generated.Name == name {
			return generated
		}
	}
	return nil
}

func TestTracingRequiresValidEndpointAndSampling(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{
			name: "endpoint required",
			mutate: func(c *Config) {
				c.Observability.Tracing.Enabled = new(true)
			},
			wantErr: "observability.tracing.endpoint is required",
		},
		{
			name: "endpoint must be host and port",
			mutate: func(c *Config) {
				c.Observability.Tracing.Enabled = new(true)
				c.Observability.Tracing.Endpoint = "https://collector.example.com:4317"
			},
			wantErr: "observability.tracing.endpoint must be a host:port",
		},
		{
			name: "sampling is bounded",
			mutate: func(c *Config) {
				c.Observability.Tracing.Enabled = new(true)
				c.Observability.Tracing.Endpoint = "collector.example.com:4317"
				c.Observability.Tracing.SamplingPercentage = new(100.1)
			},
			wantErr: "observability.tracing.sampling_percentage must be between 0 and 100",
		},
		{
			name: "trace collector port is reserved",
			mutate: func(c *Config) {
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
			err := c.Validate()
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("Validate() error = %v, want %q", err, test.wantErr)
			}
		})
	}
}

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

func TestGenerateKubernetesTracingWithoutMetrics(t *testing.T) {
	c := loadConfigCase(t, "public-routing")
	c.Observability.Metrics.Enabled = new(false)
	c.Observability.Tracing = ObservabilityTracing{
		Enabled:            new(true),
		Endpoint:           "jaeger:4317",
		ServiceName:        "auth-gateway-test",
		SamplingPercentage: new(100.0),
		Insecure:           new(true),
	}

	resources, err := GenerateKubernetes(c)
	if err != nil {
		t.Fatal(err)
	}
	if resources.OTelCollectorConfigMap == nil {
		t.Fatal("trace-only configuration did not generate a collector ConfigMap")
	}
	containers := resources.Deployment.Spec.Template.Spec.Containers
	if len(containers) != 2 {
		t.Fatalf("deployment has %d containers, want Envoy and collector", len(containers))
	}
	collectorContainer := containers[1]
	if len(collectorContainer.Ports) != 1 || collectorContainer.Ports[0].Name != tracesPortName || collectorContainer.Ports[0].ContainerPort != defaultOTelTracePort {
		t.Fatalf("trace-only collector ports = %#v", collectorContainer.Ports)
	}
	for _, port := range resources.Service.Spec.Ports {
		if port.Name == metricsPortName || port.Name == tracesPortName {
			t.Fatalf("trace-only Service exposes collector port %q", port.Name)
		}
	}

	var collector struct {
		Receivers struct {
			OTLP struct {
				Protocols struct {
					GRPC struct {
						Endpoint string `yaml:"endpoint"`
					} `yaml:"grpc"`
				} `yaml:"protocols"`
			} `yaml:"otlp"`
		} `yaml:"receivers"`
		Exporters struct {
			OTLP struct {
				Endpoint string `yaml:"endpoint"`
				TLS      struct {
					Insecure bool `yaml:"insecure"`
				} `yaml:"tls"`
			} `yaml:"otlp"`
		} `yaml:"exporters"`
		Service struct {
			Pipelines map[string]struct {
				Receivers []string `yaml:"receivers"`
				Exporters []string `yaml:"exporters"`
			} `yaml:"pipelines"`
		} `yaml:"service"`
	}
	if err := yaml.Unmarshal([]byte(resources.OTelCollectorConfigMap.Data[collectorConfigFilename]), &collector); err != nil {
		t.Fatal(err)
	}
	if collector.Receivers.OTLP.Protocols.GRPC.Endpoint != "127.0.0.1:4317" || collector.Exporters.OTLP.Endpoint != "jaeger:4317" || !collector.Exporters.OTLP.TLS.Insecure {
		t.Fatalf("collector OTLP config = %#v", collector)
	}
	tracePipeline, exists := collector.Service.Pipelines["traces"]
	if !exists || len(tracePipeline.Receivers) != 1 || tracePipeline.Receivers[0] != "otlp" || len(tracePipeline.Exporters) != 1 || tracePipeline.Exporters[0] != "otlp" {
		t.Fatalf("collector trace pipeline = %#v", tracePipeline)
	}
}

func TestRequestMetricBindingChangesBootstrapOnly(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-with-attributes")
	before, err := GenerateKubernetes(c)
	if err != nil {
		t.Fatal(err)
	}
	c.APIs[0].Metrics.Labels["tenant"] = "writer_id"
	after, err := GenerateKubernetes(c)
	if err != nil {
		t.Fatal(err)
	}
	if before.ConfigMap.Data[envoyConfigFilename] == after.ConfigMap.Data[envoyConfigFilename] {
		t.Fatal("changing a metric label binding did not change the static Envoy bootstrap")
	}
	if !reflect.DeepEqual(before.Deployment.Spec.Template, after.Deployment.Spec.Template) {
		t.Fatal("changing a metric label binding changed the Deployment template")
	}
}

func TestRequestMetricNameChangesBootstrapOnly(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-with-attributes")
	before, err := GenerateKubernetes(c)
	if err != nil {
		t.Fatal(err)
	}
	*c.Observability.Metrics.CustomMetricName = "renamed_gateway_requests_total"
	after, err := GenerateKubernetes(c)
	if err != nil {
		t.Fatal(err)
	}
	if before.ConfigMap.Data[envoyConfigFilename] == after.ConfigMap.Data[envoyConfigFilename] {
		t.Fatal("changing the request metric name did not change the static Envoy bootstrap")
	}
	if !reflect.DeepEqual(before.Deployment.Spec.Template, after.Deployment.Spec.Template) {
		t.Fatal("changing the request metric name changed the Deployment template")
	}
}

func TestGenerateKubernetesExposesMetricsWithoutAdminPort(t *testing.T) {
	config, err := Load(strings.NewReader(readFixture(t, "public-routing/config.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	resources, err := GenerateKubernetes(config)
	if err != nil {
		t.Fatal(err)
	}

	ports := make(map[string]struct {
		port       int32
		targetPort string
	}, len(resources.Service.Spec.Ports))
	for _, port := range resources.Service.Spec.Ports {
		ports[port.Name] = struct {
			port       int32
			targetPort string
		}{port: port.Port, targetPort: port.TargetPort.String()}
	}
	if len(ports) != 2 {
		t.Fatalf("Service ports = %#v, want only HTTP and metrics ports", ports)
	}
	if got := ports["http"]; got.port != defaultServicePort || got.targetPort != "http" {
		t.Fatalf("HTTP Service port = %#v, want port %d targeting Envoy HTTP", got, defaultServicePort)
	}
	if got := ports["metrics"]; got.port != defaultOTelMetricsPort || got.targetPort != "metrics" {
		t.Fatalf("metrics Service port = %#v, want port %d targeting the collector", got, defaultOTelMetricsPort)
	}
}

func TestGenerateKubernetesOmitsCollectorWhenMetricsAreDisabled(t *testing.T) {
	c := loadConfigCase(t, "api-key-auth")
	enabled, err := GenerateKubernetes(c)
	if err != nil {
		t.Fatal(err)
	}
	c.Observability.Metrics.Enabled = new(false)
	// With no collector port reserved, the HTTP Service can use 8889.
	c.Kubernetes.ServicePort = new(int32(defaultOTelMetricsPort))
	disabled, err := GenerateKubernetes(c)
	if err != nil {
		t.Fatal(err)
	}
	if enabled.OTelCollectorConfigMap == nil || disabled.OTelCollectorConfigMap != nil {
		t.Fatalf("collector ConfigMaps when enabled/disabled = %v/%v", enabled.OTelCollectorConfigMap != nil, disabled.OTelCollectorConfigMap != nil)
	}
	if got := len(disabled.Deployment.Spec.Template.Spec.Containers); got != 1 {
		t.Fatalf("disabled metrics deployment has %d containers, want only Envoy", got)
	}
	for _, volume := range disabled.Deployment.Spec.Template.Spec.Volumes {
		if volume.Name == metricsConfigVolumeName {
			t.Fatal("disabled metrics generated a collector config volume")
		}
	}
	servicePorts := make(map[string]int32, len(disabled.Service.Spec.Ports))
	for _, port := range disabled.Service.Spec.Ports {
		servicePorts[port.Name] = port.Port
	}
	if servicePorts["http"] != defaultOTelMetricsPort {
		t.Fatalf("disabled metrics HTTP Service port = %d, want %d", servicePorts["http"], defaultOTelMetricsPort)
	}
	if _, exists := servicePorts[metricsPortName]; exists {
		t.Fatalf("disabled metrics Service still exposes the collector port: %#v", servicePorts)
	}
	if !reflect.DeepEqual(enabled.ConfigMap.Data, disabled.ConfigMap.Data) {
		t.Fatal("disabling collector metrics changed the Envoy bootstrap")
	}
}

func TestOTelCollectorScrapeSettingsAndResourceOverrides(t *testing.T) {
	c := loadConfigCase(t, "public-routing")
	c.Observability.Metrics.ScrapeInterval = duration(1500 * time.Millisecond)
	c.Observability.Metrics.ScrapeTimeout = duration(250 * time.Millisecond)
	c.Kubernetes.Metrics = KubernetesMetrics{Resources: KubernetesResourceRequirements{Requests: map[string]string{"cpu": "30m"}, Limits: map[string]string{}}}
	r, err := GenerateKubernetes(c)
	if err != nil {
		t.Fatal(err)
	}
	var collector struct {
		Receivers struct {
			Prometheus struct {
				Config struct {
					Scrapes []struct {
						Interval string `yaml:"scrape_interval"`
						Timeout  string `yaml:"scrape_timeout"`
					} `yaml:"scrape_configs"`
				} `yaml:"config"`
			} `yaml:"prometheus"`
		} `yaml:"receivers"`
	}
	if err := yaml.Unmarshal([]byte(r.OTelCollectorConfigMap.Data[collectorConfigFilename]), &collector); err != nil {
		t.Fatal(err)
	}
	scrapes := collector.Receivers.Prometheus.Config.Scrapes
	if len(scrapes) != 1 || scrapes[0].Interval != "1500ms" || scrapes[0].Timeout != "250ms" {
		t.Fatalf("scrape timing = %+v", scrapes)
	}
	resources := r.Deployment.Spec.Template.Spec.Containers[1].Resources
	if len(resources.Requests) != 1 || resources.Requests.Cpu().Cmp(resource.MustParse("30m")) != 0 || len(resources.Limits) != 0 {
		t.Fatalf("collector resource overrides = %v", resources)
	}
}

func TestOTelCollectorConfigMapUpdateLeavesPodTemplateUnchanged(t *testing.T) {
	c := loadConfigCase(t, "public-routing")
	before, err := GenerateKubernetes(c)
	if err != nil {
		t.Fatal(err)
	}
	if before.OTelCollectorConfigMap == nil {
		t.Fatal("metrics-enabled configuration did not generate a collector ConfigMap")
	}

	c.Observability.Metrics.ScrapeInterval = duration(45 * time.Second)
	after, err := GenerateKubernetes(c)
	if err != nil {
		t.Fatal(err)
	}
	if after.OTelCollectorConfigMap == nil {
		t.Fatal("updated metrics configuration did not generate a collector ConfigMap")
	}
	if before.OTelCollectorConfigMap.Name != after.OTelCollectorConfigMap.Name {
		t.Fatalf("collector ConfigMap name changed from %q to %q", before.OTelCollectorConfigMap.Name, after.OTelCollectorConfigMap.Name)
	}
	if before.OTelCollectorConfigMap.Data[collectorConfigFilename] == after.OTelCollectorConfigMap.Data[collectorConfigFilename] {
		t.Fatal("changing the scrape interval did not update the collector ConfigMap")
	}
	var collector struct {
		Receivers struct {
			Prometheus struct {
				Config struct {
					ScrapeConfigs []struct {
						ScrapeInterval string `yaml:"scrape_interval"`
					} `yaml:"scrape_configs"`
				} `yaml:"config"`
			} `yaml:"prometheus"`
		} `yaml:"receivers"`
	}
	if err := yaml.Unmarshal([]byte(after.OTelCollectorConfigMap.Data[collectorConfigFilename]), &collector); err != nil {
		t.Fatal(err)
	}
	scrapes := collector.Receivers.Prometheus.Config.ScrapeConfigs
	if len(scrapes) != 1 || scrapes[0].ScrapeInterval != "45s" {
		t.Fatalf("updated collector scrape interval = %+v, want 45s", scrapes)
	}
	if !reflect.DeepEqual(before.ConfigMap.Data, after.ConfigMap.Data) {
		t.Fatal("changing the scrape interval changed the Envoy ConfigMap")
	}
	if !reflect.DeepEqual(before.Deployment.Spec.Template, after.Deployment.Spec.Template) {
		t.Fatal("changing the scrape interval changed the Deployment Pod template")
	}
	if len(after.Deployment.Spec.Template.Annotations) != 0 {
		t.Fatalf("collector ConfigMap update unexpectedly has rollout annotations: %#v", after.Deployment.Spec.Template.Annotations)
	}

	var configVolumeMatches, configMountMatches bool
	containers := after.Deployment.Spec.Template.Spec.Containers
	if len(containers) != 2 {
		t.Fatalf("metrics-enabled deployment has %d containers, want Envoy and collector", len(containers))
	}
	for _, volume := range after.Deployment.Spec.Template.Spec.Volumes {
		if volume.Name == metricsConfigVolumeName {
			configVolumeMatches = volume.ConfigMap != nil && volume.ConfigMap.Name == after.OTelCollectorConfigMap.Name
		}
	}
	for _, mount := range containers[1].VolumeMounts {
		if mount.Name == metricsConfigVolumeName {
			configMountMatches = mount.MountPath == collectorConfigDirectory && mount.ReadOnly && mount.SubPath == "" && mount.SubPathExpr == ""
		}
	}
	if !configVolumeMatches || !configMountMatches {
		t.Fatalf("collector ConfigMap volume and mount = %t/%t, want a projected directory mount", configVolumeMatches, configMountMatches)
	}
}

func TestPlaygroundOTelCollectorConfiguration(t *testing.T) {
	inputPath := filepath.Join("..", "playground", "config.yaml")
	c := loadTestConfig(t, readTestFile(t, inputPath), inputPath)
	collectorConfig, err := GenerateOTelCollectorConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	checkReference(t, filepath.Join("..", "playground", "otel-collector.yaml.golden"), collectorConfig)
}

func TestObservabilityMetricsValidation(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
		field   string
		edit    func(*Config)
	}{
		{name: "zero interval", fixture: "public-routing", field: "observability.metrics.scrape_interval", edit: func(c *Config) { c.Observability.Metrics.ScrapeInterval = duration(0) }},
		{name: "zero timeout", fixture: "public-routing", field: "observability.metrics.scrape_timeout", edit: func(c *Config) { c.Observability.Metrics.ScrapeTimeout = duration(0) }},
		{name: "timeout exceeds interval", fixture: "public-routing", field: "observability.metrics.scrape_timeout", edit: func(c *Config) { c.Observability.Metrics.ScrapeInterval = duration(time.Second) }},
		{name: "fractional milliseconds", fixture: "public-routing", field: "observability.metrics.scrape_timeout", edit: func(c *Config) { c.Observability.Metrics.ScrapeTimeout = duration(time.Millisecond + time.Microsecond) }},
		{name: "collector request exceeds limit", fixture: "public-routing", field: "kubernetes.metrics.resources.requests.memory", edit: func(c *Config) { c.Kubernetes.Metrics.Resources.Requests["memory"] = "257Mi" }},
		{name: "invalid collector quantity", fixture: "public-routing", field: "kubernetes.metrics.resources.limits.memory", edit: func(c *Config) { c.Kubernetes.Metrics.Resources.Limits["memory"] = "invalid" }},
		{name: "negative collector quantity", fixture: "public-routing", field: "kubernetes.metrics.resources.requests.cpu", edit: func(c *Config) { c.Kubernetes.Metrics.Resources.Requests["cpu"] = "-1m" }},
		{name: "listener port conflicts with metrics collector", fixture: "public-routing", field: "listener.port must not conflict with admin port", edit: func(c *Config) { c.Listener.Port = new(uint32(defaultOTelMetricsPort)) }},
		{name: "HTTP Service port conflict", fixture: "public-routing", field: "kubernetes.service_port", edit: func(c *Config) { c.Kubernetes.ServicePort = new(int32(defaultOTelMetricsPort)) }},
		{name: "HTTPS Service port conflict", fixture: "server-tls", field: "kubernetes.https_service_port", edit: func(c *Config) { c.Kubernetes.HTTPSServicePort = new(int32(defaultOTelMetricsPort)) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := loadConfigCase(t, test.fixture)
			test.edit(&c)
			if err := c.Validate(); err == nil || !strings.Contains(err.Error(), test.field) {
				t.Fatalf("validation = %v, want %s", err, test.field)
			}
		})
	}
}

func TestMetricsCollectorPortAvailableWithoutKubernetes(t *testing.T) {
	c := loadConfigCase(t, "public-routing")
	c.Kubernetes = nil
	c.Listener.Port = new(uint32(defaultOTelMetricsPort))
	if err := c.Validate(); err != nil {
		t.Fatalf("file-only configuration rejected the metrics collector port: %v", err)
	}
}
