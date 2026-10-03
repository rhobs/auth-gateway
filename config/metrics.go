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
exporters:
  prometheus:
    endpoint: 0.0.0.0:%d
service:
  pipelines:
    metrics:
      receivers:
        - prometheus
      exporters:
        - prometheus
`

func generateOTelCollectorConfig(metrics KubernetesMetrics) []byte {
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
