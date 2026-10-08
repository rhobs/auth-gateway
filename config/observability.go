package config

import (
	"fmt"
	"maps"
	"math"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	metrics "github.com/envoyproxy/go-control-plane/envoy/config/metrics/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	traceconfig "github.com/envoyproxy/go-control-plane/envoy/config/trace/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	upstreamhttp "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	envoytype "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	defaultOTelCollectorImage       = "otel/opentelemetry-collector-contrib:0.135.0"
	defaultOTelMetricsPort          = 8889
	defaultOTelTracePort            = 4317
	defaultTraceSamplingPercentage  = 100
	defaultOTelTraceReceiverAddress = "127.0.0.1"
	envoyTraceClusterName           = "otel-traces"
	envoyOTelTracerName             = "envoy.tracers.opentelemetry"
	collectorConfigFilename         = "config.yaml"
	collectorConfigDirectory        = "/etc/collector"
	metricsPortName                 = "metrics"
	tracesPortName                  = "traces"
	metricsConfigVolumeName         = "metrics-config"
	listenerPortConflictErrorFormat = "listener.port must not conflict with admin port %d or the metrics collector port %d"
	defaultRequestMetricCounterName = "auth_gateway_http_requests_total"
	requestMetricsFilterName        = "envoy.filters.http.lua"
	requestMetricStatusLabelName    = "http_status_code"
)

// ObservabilityConfig groups gateway-wide telemetry settings.
type ObservabilityConfig struct {
	Metrics ObservabilityMetrics `yaml:"metrics,omitempty"`
	Tracing ObservabilityTracing `yaml:"tracing,omitempty"`
}

// ObservabilityMetrics configures the scraping, exposure, and naming of Envoy metrics.
type ObservabilityMetrics struct {
	Enabled          *bool     `yaml:"enabled,omitempty"`
	ScrapeInterval   *Duration `yaml:"scrape_interval,omitempty"`
	ScrapeTimeout    *Duration `yaml:"scrape_timeout,omitempty"`
	CustomMetricName *string   `yaml:"custom_metric_name,omitempty"`
}

// ObservabilityTracing configures Envoy tracing and the collector's OTLP exporter.
type ObservabilityTracing struct {
	Enabled            *bool    `yaml:"enabled,omitempty"`
	Endpoint           string   `yaml:"endpoint,omitempty"`
	ServiceName        string   `yaml:"service_name,omitempty"`
	SamplingPercentage *float64 `yaml:"sampling_percentage,omitempty"`
	Insecure           *bool    `yaml:"insecure,omitempty"`
}

// APIMetrics enables one request counter and optionally binds labels to working attributes.
type APIMetrics struct {
	Labels map[string]string `yaml:"labels,omitempty"`
}

// KubernetesMetrics configures resources for the collector container.
type KubernetesMetrics struct {
	Resources KubernetesResourceRequirements `yaml:"resources,omitempty"`
}

const otelCollectorConfigTemplate = `receivers:
  prometheus:
    config:
      scrape_configs:
        - job_name: auth-gateway
          scrape_interval: %s
          scrape_timeout: %s
          metrics_path: /stats/prometheus
          static_configs:
            - targets:
                - 127.0.0.1:%d
processors:
  transform:
    metric_statements:
      - context: metric
        statements:
          - replace_pattern(name, "^envoy_http_lua_", "")
exporters:
  prometheus:
    endpoint: 0.0.0.0:%d
service:
  pipelines:
    metrics:
      receivers:
        - prometheus
      processors:
        - transform
      exporters:
        - prometheus
`

const otelCollectorTracingOnlyConfigTemplate = `receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 127.0.0.1:%d
processors:
  batch: {}
exporters:
  otlp:
    endpoint: %s
%sservice:
  pipelines:
    traces:
      receivers:
        - otlp
      processors:
        - batch
      exporters:
        - otlp
`

const otelCollectorTracingAndMetricsConfigTemplate = `receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 127.0.0.1:%d
  prometheus:
    config:
      scrape_configs:
        - job_name: auth-gateway
          scrape_interval: %s
          scrape_timeout: %s
          metrics_path: /stats/prometheus
          static_configs:
            - targets:
                - 127.0.0.1:%d
processors:
  batch: {}
  transform:
    metric_statements:
      - context: metric
        statements:
          - replace_pattern(name, "^envoy_http_lua_", "")
exporters:
  otlp:
    endpoint: %s
%s  prometheus:
    endpoint: 0.0.0.0:%d
service:
  pipelines:
    metrics:
      receivers:
        - prometheus
      processors:
        - transform
      exporters:
        - prometheus
    traces:
      receivers:
        - otlp
      processors:
        - batch
      exporters:
        - otlp
`

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

func generateOTelCollectorConfig(metrics ObservabilityMetrics, tracing ObservabilityTracing) []byte {
	metricsEnabled := metrics.enabled()
	if !tracing.enabled() {
		if !metricsEnabled {
			return nil
		}
		return []byte(fmt.Sprintf(otelCollectorConfigTemplate, prometheusDuration(*metrics.ScrapeInterval), prometheusDuration(*metrics.ScrapeTimeout), envoyAdminPort, defaultOTelMetricsPort))
	}
	traceExporterTLS := ""
	if *tracing.Insecure {
		traceExporterTLS = "    tls:\n      insecure: true\n"
	}
	if !metricsEnabled {
		return []byte(fmt.Sprintf(otelCollectorTracingOnlyConfigTemplate, defaultOTelTracePort, tracing.Endpoint, traceExporterTLS))
	}
	return []byte(fmt.Sprintf(otelCollectorTracingAndMetricsConfigTemplate, defaultOTelTracePort, prometheusDuration(*metrics.ScrapeInterval), prometheusDuration(*metrics.ScrapeTimeout), envoyAdminPort, tracing.Endpoint, traceExporterTLS, defaultOTelMetricsPort))
}

func prometheusDuration(d Duration) string {
	if time.Duration(d)%time.Second == 0 {
		return fmt.Sprintf("%ds", time.Duration(d)/time.Second)
	}
	return fmt.Sprintf("%dms", time.Duration(d)/time.Millisecond)
}

func metricsResourceName(name string) string {
	return resourceNameWithSuffix(name, "-metrics")
}

func (o ObservabilityConfig) clone() ObservabilityConfig {
	o.Metrics = o.Metrics.clone()
	o.Tracing = o.Tracing.clone()
	return o
}

func (o ObservabilityConfig) withDefaults(serviceName string) ObservabilityConfig {
	o.Metrics.Enabled = defaultValue(o.Metrics.Enabled, true)
	o.Metrics.ScrapeInterval = o.Metrics.ScrapeInterval.withDefault(30 * time.Second)
	o.Metrics.ScrapeTimeout = o.Metrics.ScrapeTimeout.withDefault(10 * time.Second)
	o.Tracing.Enabled = defaultValue(o.Tracing.Enabled, false)
	if o.Tracing.ServiceName == "" {
		o.Tracing.ServiceName = serviceName
	}
	o.Tracing.SamplingPercentage = defaultValue(o.Tracing.SamplingPercentage, defaultTraceSamplingPercentage)
	o.Tracing.Insecure = defaultValue(o.Tracing.Insecure, false)
	return o
}

func (m ObservabilityMetrics) clone() ObservabilityMetrics {
	m.Enabled = clonePointer(m.Enabled)
	m.ScrapeInterval = clonePointer(m.ScrapeInterval)
	m.ScrapeTimeout = clonePointer(m.ScrapeTimeout)
	m.CustomMetricName = clonePointer(m.CustomMetricName)
	return m
}

func (t ObservabilityTracing) clone() ObservabilityTracing {
	t.Enabled = clonePointer(t.Enabled)
	t.SamplingPercentage = clonePointer(t.SamplingPercentage)
	t.Insecure = clonePointer(t.Insecure)
	return t
}

func (m KubernetesMetrics) clone() KubernetesMetrics {
	m.Resources = m.Resources.clone()
	return m
}

func (m APIMetrics) clone() APIMetrics {
	m.Labels = maps.Clone(m.Labels)
	return m
}

func (m KubernetesMetrics) withDefaults() KubernetesMetrics {
	m.Resources.Requests = copyResourcesOrDefault(m.Resources.Requests, map[string]string{kubernetesCPUResourceName: "20m", kubernetesMemoryResourceName: "64Mi"})
	m.Resources.Limits = copyResourcesOrDefault(m.Resources.Limits, map[string]string{kubernetesMemoryResourceName: "256Mi"})
	return m
}

func (m ObservabilityMetrics) enabled() bool {
	return m.Enabled != nil && *m.Enabled
}

func (m ObservabilityMetrics) validate() error {
	if err := validateCustomMetricName(m.CustomMetricName); err != nil {
		return err
	}
	for _, field := range []struct {
		name  string
		value *Duration
	}{{"scrape_interval", m.ScrapeInterval}, {"scrape_timeout", m.ScrapeTimeout}} {
		name := "observability.metrics." + field.name
		if err := validateDuration(name, field.value, false); err != nil {
			return err
		}
		if time.Duration(*field.value)%time.Millisecond != 0 {
			return fmt.Errorf("%s must be a whole number of milliseconds", name)
		}
	}
	if *m.ScrapeTimeout > *m.ScrapeInterval {
		return fmt.Errorf("observability.metrics.scrape_timeout (%s) must not exceed observability.metrics.scrape_interval (%s)", m.ScrapeTimeout, m.ScrapeInterval)
	}
	return nil
}

func (t ObservabilityTracing) enabled() bool {
	return t.Enabled != nil && *t.Enabled
}

func (t ObservabilityTracing) validate() error {
	if t.enabled() && (strings.TrimSpace(t.ServiceName) == "" || strings.ContainsAny(t.ServiceName, invalidControlCharacters)) {
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
	if t.enabled() && t.Endpoint == "" {
		return fmt.Errorf("observability.tracing.endpoint is required when tracing is enabled")
	}
	return nil
}

func (m KubernetesMetrics) validate() error {
	return validateKubernetesResourceRequirements("kubernetes.metrics.resources", m.Resources)
}

func validateObservabilityListenerPort(port *uint32, metricsEnabled, tracingEnabled bool) error {
	if *port == envoyAdminPort {
		return fmt.Errorf(listenerPortConflictErrorFormat, envoyAdminPort, defaultOTelMetricsPort)
	}
	if metricsEnabled && *port == defaultOTelMetricsPort {
		return fmt.Errorf(listenerPortConflictErrorFormat, envoyAdminPort, defaultOTelMetricsPort)
	}
	if tracingEnabled && *port == defaultOTelTracePort {
		return fmt.Errorf("listener.port must not conflict with the OTLP trace collector port %d", defaultOTelTracePort)
	}
	return nil
}

func validateOTelCollectorImage(image string, collectorEnabled bool) error {
	if collectorEnabled && (strings.TrimSpace(image) == "" || strings.ContainsAny(image, imageWhitespaceCharacters)) {
		return fmt.Errorf("kubernetes.otel_collector_image must be an image reference")
	}
	return nil
}

func validateOTelMetricsServicePort(field string, port int32, metricsEnabled bool) error {
	if metricsEnabled && port == defaultOTelMetricsPort {
		return fmt.Errorf("kubernetes.%s must not conflict with the metrics port", field)
	}
	return nil
}

var prometheusNamePattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

func validateCustomMetricName(value *string) error {
	if value != nil && (!prometheusNamePattern.MatchString(*value) || strings.HasPrefix(*value, "__")) {
		return fmt.Errorf("observability.metrics.custom_metric_name must start with an ASCII letter or underscore, use only ASCII letters, numbers, and underscores, and not start with __")
	}
	return nil
}

func validateAPIMetrics(name string, value *APIMetrics) error {
	if value == nil {
		return nil
	}
	for _, label := range slices.Sorted(maps.Keys(value.Labels)) {
		if !prometheusNamePattern.MatchString(label) || strings.HasPrefix(label, "__") ||
			label == apiMetadataName || label == requestMetricStatusLabelName || label == "envoy_http_conn_manager_prefix" {
			return fmt.Errorf("%s.labels contains invalid or reserved Prometheus label name %q", name, label)
		}
		if !attributeNamePattern.MatchString(value.Labels[label]) {
			return fmt.Errorf("%s.labels.%s must reference a valid attribute name", name, label)
		}
	}
	return nil
}

func validateMetricAttributeReferences(apis []API, authenticators map[string]Authenticator) error {
	known := make(map[string]struct{})
	for _, authenticator := range authenticators {
		for attribute := range authenticator.Attributes {
			known[attribute] = struct{}{}
		}
	}
	for i, api := range apis {
		if api.Metrics == nil {
			continue
		}
		for _, label := range slices.Sorted(maps.Keys(api.Metrics.Labels)) {
			attribute := api.Metrics.Labels[label]
			if _, exists := known[attribute]; !exists {
				return fmt.Errorf("apis[%d].metrics.labels.%s references unknown authenticator attribute %q", i, label, attribute)
			}
		}
	}
	return nil
}

func hasRequestMetricLabels(apis []API) bool {
	for _, api := range apis {
		if api.Metrics != nil && len(api.Metrics.Labels) > 0 {
			return true
		}
	}
	return false
}

func requestMetricLabelNames(apis []API) []string {
	labels := make(map[string]struct{})
	for _, api := range apis {
		if api.Metrics == nil {
			continue
		}
		for label := range api.Metrics.Labels {
			labels[label] = struct{}{}
		}
	}
	return slices.Sorted(maps.Keys(labels))
}

func (api API) toRequestMetricsRouteMetadata() *structpb.Struct {
	labels := make(map[string]*structpb.Value, len(api.Metrics.Labels))
	for label, attribute := range api.Metrics.Labels {
		labels[label] = structpb.NewStringValue(attribute)
	}
	return &structpb.Struct{Fields: map[string]*structpb.Value{
		apiMetadataName: structpb.NewStringValue(api.Name),
		"labels":        structpb.NewStructValue(&structpb.Struct{Fields: labels}),
	}}
}

func requestMetricsStatsConfig(apis []API, counterName string) *metrics.StatsConfig {
	fields := append([]string{apiMetadataName, requestMetricStatusLabelName}, requestMetricLabelNames(apis)...)
	prefix := `^http\.` + regexp.QuoteMeta(httpManagerStatPrefix) + `\.lua\.` + regexp.QuoteMeta(counterName)
	tags := make([]*metrics.TagSpecifier, 0, len(fields))
	for _, field := range fields {
		escaped := regexp.QuoteMeta(field)
		tags = append(tags, &metrics.TagSpecifier{
			TagName:  field,
			TagValue: &metrics.TagSpecifier_Regex{Regex: prefix + `(\|` + escaped + `=([^|]+))`},
		})
		prefix += `\|` + escaped + `=[^|]+`
	}
	return &metrics.StatsConfig{StatsTags: tags}
}

func requestMetricsLuaScript(apis []API, counterName string) string {
	labels := requestMetricLabelNames(apis)
	quoted := make([]string, len(labels))
	for i, label := range labels {
		quoted[i] = strconv.Quote(label)
	}
	return "local labels = {" + strings.Join(quoted, ", ") + "}\n" +
		"local counter_name = " + strconv.Quote(counterName) + "\n\n" + requestMetricsLuaBody
}

const requestMetricsLuaBody = `local function safe_label(value)
  if type(value) ~= "string" or #value == 0 or #value > 128 then
    return "__unattributed__"
  end
  for i = 1, #value do
    local byte = string.byte(value, i)
    if byte < 32 or byte > 126 or byte == 124 then
      return "__unattributed__"
    end
  end
  return value
end

function envoy_on_response(response_handle)
  local metadata = response_handle:metadata()
  if metadata == nil then
    return
  end
  local api = metadata:get("api")
  if type(api) ~= "string" or api == "" then
    return
  end
  local status = response_handle:headers():get(":status")
  if type(status) ~= "string" or not string.match(status, "^%d%d%d$") then
    return
  end

  local bindings = metadata:get("labels") or {}
  local filter_state = response_handle:streamInfo():filterState()
  local name = counter_name .. "|api=" .. api .. "|http_status_code=" .. status
  for _, label in ipairs(labels) do
    local attribute = bindings[label]
    local value = nil
    if type(attribute) == "string" then
      value = filter_state:get("auth_gateway.attributes." .. attribute)
    end
    name = name .. "|" .. label .. "=" .. safe_label(value)
  end
  response_handle:stats():counter(name):inc()
end
`

func (c Config) hasRequestMetrics() bool {
	for _, api := range c.APIs {
		if api.Metrics != nil {
			return true
		}
	}
	return false
}

func (c Config) requestMetricName() string {
	if c.Observability.Metrics.CustomMetricName != nil {
		return *c.Observability.Metrics.CustomMetricName
	}
	return defaultRequestMetricCounterName
}

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

func hasRequestMetricRoutes(hosts []*route.VirtualHost) bool {
	for _, host := range hosts {
		for _, route := range host.Routes {
			if route.Metadata != nil && route.Metadata.FilterMetadata[requestMetricsFilterName] != nil {
				return true
			}
		}
	}
	return false
}

func otelTraceCluster() (*cluster.Cluster, error) {
	protocolOptions, err := packEnvoy(&upstreamhttp.HttpProtocolOptions{UpstreamProtocolOptions: &upstreamhttp.HttpProtocolOptions_ExplicitHttpConfig_{ExplicitHttpConfig: &upstreamhttp.HttpProtocolOptions_ExplicitHttpConfig{
		ProtocolConfig: &upstreamhttp.HttpProtocolOptions_ExplicitHttpConfig_Http2ProtocolOptions{Http2ProtocolOptions: &core.Http2ProtocolOptions{}},
	}}})
	if err != nil {
		return nil, fmt.Errorf("encode OTLP upstream HTTP/2 options: %w", err)
	}
	return &cluster.Cluster{
		Name:                          envoyTraceClusterName,
		ConnectTimeout:                durationpb.New(5 * time.Second),
		ClusterDiscoveryType:          &cluster.Cluster_Type{Type: cluster.Cluster_STATIC},
		TypedExtensionProtocolOptions: map[string]*anypb.Any{upstreamHTTPProtocolOptionsTypeURL: protocolOptions},
		LoadAssignment: &endpoint.ClusterLoadAssignment{
			ClusterName: envoyTraceClusterName,
			Endpoints: []*endpoint.LocalityLbEndpoints{{
				LbEndpoints: []*endpoint.LbEndpoint{{
					HostIdentifier: &endpoint.LbEndpoint_Endpoint{Endpoint: &endpoint.Endpoint{
						Address: socket(defaultOTelTraceReceiverAddress, defaultOTelTracePort),
					}},
				}},
			}},
		},
	}, nil
}
