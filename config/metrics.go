package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"time"
)

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

const (
	defaultOTelTracePort            = 4317
	defaultTraceSamplingPercentage  = 100
	defaultOTelTraceReceiverAddress = "127.0.0.1"
	envoyTraceClusterName           = "otel-traces"
	envoyOTelTracerName             = "envoy.tracers.opentelemetry"
)

// ObservabilityConfig groups gateway-wide telemetry settings.
type ObservabilityConfig struct {
	Metrics ObservabilityMetrics `yaml:"metrics,omitempty"`
	Tracing ObservabilityTracing `yaml:"tracing,omitempty"`
}

// ObservabilityMetrics configures scraping and exposure of Envoy metrics.
type ObservabilityMetrics struct {
	Enabled        *bool     `yaml:"enabled,omitempty"`
	ScrapeInterval *Duration `yaml:"scrape_interval,omitempty"`
	ScrapeTimeout  *Duration `yaml:"scrape_timeout,omitempty"`
}

// ObservabilityTracing configures Envoy tracing and the collector's OTLP exporter.
type ObservabilityTracing struct {
	Enabled            *bool    `yaml:"enabled,omitempty"`
	Endpoint           string   `yaml:"endpoint,omitempty"`
	ServiceName        string   `yaml:"service_name,omitempty"`
	SamplingPercentage *float64 `yaml:"sampling_percentage,omitempty"`
	Insecure           *bool    `yaml:"insecure,omitempty"`
}

func (o ObservabilityConfig) withDefaults(serviceName string) ObservabilityConfig {
	o.Metrics.Enabled = defaultValue(o.Metrics.Enabled, true)
	o.Metrics.ScrapeInterval = defaultDuration(o.Metrics.ScrapeInterval, 30*time.Second)
	o.Metrics.ScrapeTimeout = defaultDuration(o.Metrics.ScrapeTimeout, 10*time.Second)
	o.Tracing.Enabled = defaultValue(o.Tracing.Enabled, false)
	if o.Tracing.ServiceName == "" {
		o.Tracing.ServiceName = serviceName
	}
	o.Tracing.SamplingPercentage = defaultValue(o.Tracing.SamplingPercentage, defaultTraceSamplingPercentage)
	o.Tracing.Insecure = defaultValue(o.Tracing.Insecure, false)
	return o
}

func (m ObservabilityMetrics) validate() error {
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
	metricsEnabled := metrics.Enabled != nil && *metrics.Enabled
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

func processingResourceName(name string) string {
	return resourceNameWithSuffix(name, "-processing")
}

func resourceNameWithSuffix(name, suffix string) string {
	const maxDNSLabelLength = 63
	if len(name)+len(suffix) <= maxDNSLabelLength {
		return name + suffix
	}

	digest := sha256.Sum256([]byte(name))
	hash := hex.EncodeToString(digest[:5])
	prefixLength := maxDNSLabelLength - len(suffix) - len(hash) - 1
	return name[:prefixLength] + "-" + hash + suffix
}
