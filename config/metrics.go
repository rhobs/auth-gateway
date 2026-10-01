package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

const otelCollectorConfigTemplate = `receivers:
  prometheus:
    config:
      scrape_configs:
        - job_name: auth-gateway
          scrape_interval: 30s
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

func generateOTelCollectorConfig() []byte {
	return []byte(fmt.Sprintf(otelCollectorConfigTemplate, envoyAdminPort, defaultOTelMetricsPort))
}

func metricsResourceName(name string) string {
	const suffix = "-metrics"
	const maxDNSLabelLength = 63
	if len(name)+len(suffix) <= maxDNSLabelLength {
		return name + suffix
	}

	digest := sha256.Sum256([]byte(name))
	hash := hex.EncodeToString(digest[:5])
	prefixLength := maxDNSLabelLength - len(suffix) - len(hash) - 1
	return name[:prefixLength] + "-" + hash + suffix
}
