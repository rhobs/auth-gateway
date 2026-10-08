package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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
