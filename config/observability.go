package config

import (
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	defaultTraceSamplingPercentage  = 100
	metricsPortName                 = "metrics"
	tracesPortName                  = "traces"
	metricsConfigVolumeName         = "metrics-config"
	listenerPortConflictErrorFormat = "listener.port must not conflict with admin port %d or the metrics collector port %d"
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
