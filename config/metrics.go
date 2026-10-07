package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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

// ObservabilityConfig groups gateway-wide telemetry settings.
type ObservabilityConfig struct {
	Metrics ObservabilityMetrics `yaml:"metrics,omitempty"`
}

// ObservabilityMetrics configures scraping and exposure of Envoy metrics.
type ObservabilityMetrics struct {
	Enabled        *bool     `yaml:"enabled,omitempty"`
	ScrapeInterval *Duration `yaml:"scrape_interval,omitempty"`
	ScrapeTimeout  *Duration `yaml:"scrape_timeout,omitempty"`
}

func (o ObservabilityConfig) withDefaults() ObservabilityConfig {
	o.Metrics.Enabled = defaultValue(o.Metrics.Enabled, true)
	o.Metrics.ScrapeInterval = defaultDuration(o.Metrics.ScrapeInterval, 30*time.Second)
	o.Metrics.ScrapeTimeout = defaultDuration(o.Metrics.ScrapeTimeout, 10*time.Second)
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

func generateOTelCollectorConfig(metrics ObservabilityMetrics) []byte {
	return []byte(fmt.Sprintf(otelCollectorConfigTemplate, prometheusDuration(*metrics.ScrapeInterval), prometheusDuration(*metrics.ScrapeTimeout), envoyAdminPort, defaultOTelMetricsPort))
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
