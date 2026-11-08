package config

import (
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"time"

	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
)

const (
	DefaultTraceSamplingPercentage  = 100
	MetricsPortName                 = "metrics"
	TracesPortName                  = "traces"
	MetricsConfigVolumeName         = "metrics-config"
	ListenerPortConflictErrorFormat = "listener.port must not conflict with admin port %d or the metrics collector port %d"
)

const EnvoyOTelTracerName = "envoy.tracers.opentelemetry"

func validateOTelTraceEndpoint(endpoint string) error {
	host, portText, err := net.SplitHostPort(endpoint)
	if err != nil || !validHost(host) {
		return fmt.Errorf("observability.tracing.endpoint must be a host:port for an OTLP gRPC endpoint")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return fmt.Errorf("observability.tracing.endpoint port must be between 1 and 65535")
	}
	if strings.ContainsAny(endpoint, InvalidControlCharacters) {
		return fmt.Errorf("observability.tracing.endpoint must not contain control characters")
	}
	return nil
}

func MetricsResourceName(name string) string {
	return resourceNameWithSuffix(name, "-metrics")
}

func cloneObservabilityConfig(o gatewayapi.ObservabilityConfig) gatewayapi.ObservabilityConfig {
	o.Metrics = cloneObservabilityMetrics(o.Metrics)
	o.Tracing = cloneObservabilityTracing(o.Tracing)
	return o
}

func withDefaultsObservabilityConfig(o gatewayapi.ObservabilityConfig, serviceName string) gatewayapi.ObservabilityConfig {
	o.Metrics.Enabled = defaultValue(o.Metrics.Enabled, true)
	o.Metrics.ScrapeInterval = withDefaultDuration(o.Metrics.ScrapeInterval, 30*time.Second)
	o.Metrics.ScrapeTimeout = withDefaultDuration(o.Metrics.ScrapeTimeout, 10*time.Second)
	o.Tracing.Enabled = defaultValue(o.Tracing.Enabled, false)
	if o.Tracing.ServiceName == "" {
		o.Tracing.ServiceName = serviceName
	}
	o.Tracing.SamplingPercentage = defaultValue(o.Tracing.SamplingPercentage, DefaultTraceSamplingPercentage)
	o.Tracing.Insecure = defaultValue(o.Tracing.Insecure, false)
	return o
}

func cloneObservabilityMetrics(m gatewayapi.ObservabilityMetrics) gatewayapi.ObservabilityMetrics {
	m.Enabled = clonePointer(m.Enabled)
	m.ScrapeInterval = clonePointer(m.ScrapeInterval)
	m.ScrapeTimeout = clonePointer(m.ScrapeTimeout)
	m.CustomMetricName = clonePointer(m.CustomMetricName)
	return m
}

func cloneObservabilityTracing(t gatewayapi.ObservabilityTracing) gatewayapi.ObservabilityTracing {
	t.Enabled = clonePointer(t.Enabled)
	t.SamplingPercentage = clonePointer(t.SamplingPercentage)
	t.Insecure = clonePointer(t.Insecure)
	return t
}

func EnabledObservabilityMetrics(m gatewayapi.ObservabilityMetrics) bool {
	return m.Enabled != nil && *m.Enabled
}

func validateObservabilityMetrics(m gatewayapi.ObservabilityMetrics) error {
	if err := validateCustomMetricName(m.CustomMetricName); err != nil {
		return err
	}
	for _, field := range []struct {
		Name  string
		Value *gatewayapi.Duration
	}{{"scrape_interval", m.ScrapeInterval}, {"scrape_timeout", m.ScrapeTimeout}} {
		name := "observability.metrics." + field.Name
		if err := validateDuration(name, field.Value, false); err != nil {
			return err
		}
		if time.Duration(*field.Value)%time.Millisecond != 0 {
			return fmt.Errorf("%s must be a whole number of milliseconds", name)
		}
	}
	if *m.ScrapeTimeout > *m.ScrapeInterval {
		return fmt.Errorf("observability.metrics.scrape_timeout (%s) must not exceed observability.metrics.scrape_interval (%s)", m.ScrapeTimeout, m.ScrapeInterval)
	}
	return nil
}

func EnabledObservabilityTracing(t gatewayapi.ObservabilityTracing) bool {
	return t.Enabled != nil && *t.Enabled
}

func validateObservabilityTracing(t gatewayapi.ObservabilityTracing) error {
	if EnabledObservabilityTracing(t) && (strings.TrimSpace(t.ServiceName) == "" || strings.ContainsAny(t.ServiceName, InvalidControlCharacters)) {
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
	if EnabledObservabilityTracing(t) && t.Endpoint == "" {
		return fmt.Errorf("observability.tracing.endpoint is required when tracing is enabled")
	}
	return nil
}

func validateObservabilityListenerPort(port *uint32, metricsEnabled, tracingEnabled bool) error {
	if *port == EnvoyAdminPort {
		return fmt.Errorf(ListenerPortConflictErrorFormat, EnvoyAdminPort, DefaultOTelMetricsPort)
	}
	if metricsEnabled && *port == DefaultOTelMetricsPort {
		return fmt.Errorf(ListenerPortConflictErrorFormat, EnvoyAdminPort, DefaultOTelMetricsPort)
	}
	if tracingEnabled && *port == DefaultOTelTracePort {
		return fmt.Errorf("listener.port must not conflict with the OTLP trace collector port %d", DefaultOTelTracePort)
	}
	return nil
}

const (
	DefaultOTelMetricsPort          = 8889
	DefaultOTelTracePort            = 4317
	DefaultOTelTraceReceiverAddress = "127.0.0.1"
	CollectorConfigFilename         = "config.yaml"
	CollectorConfigDirectory        = "/etc/collector"
)
