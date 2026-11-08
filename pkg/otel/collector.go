package otel

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	configuration "github.com/rhobs/auth-gateway/pkg/config"
	yaml "go.yaml.in/yaml/v3"
)

type otelCollectorConfig struct {
	Receivers  otelCollectorReceivers  `yaml:"receivers"`
	Processors otelCollectorProcessors `yaml:"processors"`
	Exporters  otelCollectorExporters  `yaml:"exporters"`
	Service    otelCollectorService    `yaml:"service"`
}

type otelCollectorReceivers struct {
	OTLP       *otelOTLPReceiver       `yaml:"otlp,omitempty"`
	Prometheus *otelPrometheusReceiver `yaml:"prometheus,omitempty"`
}

type otelOTLPReceiver struct {
	Protocols otelOTLPReceiverProtocols `yaml:"protocols"`
}

type otelOTLPReceiverProtocols struct {
	GRPC otelOTLPGRPCReceiver `yaml:"grpc"`
}

type otelOTLPGRPCReceiver struct {
	Endpoint string `yaml:"endpoint"`
}

type otelPrometheusReceiver struct {
	Config otelPrometheusReceiverConfig `yaml:"config"`
}

type otelPrometheusReceiverConfig struct {
	ScrapeConfigs []otelPrometheusScrapeConfig `yaml:"scrape_configs"`
}

type otelPrometheusScrapeConfig struct {
	JobName        string                       `yaml:"job_name"`
	ScrapeInterval string                       `yaml:"scrape_interval"`
	ScrapeTimeout  string                       `yaml:"scrape_timeout"`
	MetricsPath    string                       `yaml:"metrics_path"`
	StaticConfigs  []otelPrometheusStaticConfig `yaml:"static_configs"`
}

type otelPrometheusStaticConfig struct {
	Targets []string `yaml:"targets"`
}

type otelCollectorProcessors struct {
	Batch     *otelBatchProcessor     `yaml:"batch,omitempty"`
	Transform *otelTransformProcessor `yaml:"transform,omitempty"`
}

type otelBatchProcessor struct{}

type otelTransformProcessor struct {
	MetricStatements []otelTransformMetricStatements `yaml:"metric_statements"`
}

type otelTransformMetricStatements struct {
	Context    string   `yaml:"context"`
	Statements []string `yaml:"statements"`
}

type otelCollectorExporters struct {
	OTLP       *otelOTLPExporter       `yaml:"otlp,omitempty"`
	Prometheus *otelPrometheusExporter `yaml:"prometheus,omitempty"`
}

type otelOTLPExporter struct {
	Endpoint string         `yaml:"endpoint"`
	TLS      *otelTLSConfig `yaml:"tls,omitempty"`
}

type otelTLSConfig struct {
	Insecure bool `yaml:"insecure"`
}

type otelPrometheusExporter struct {
	Endpoint string `yaml:"endpoint"`
}

type otelCollectorService struct {
	Pipelines otelCollectorPipelines `yaml:"pipelines"`
}

type otelCollectorPipelines struct {
	Metrics *otelCollectorPipeline `yaml:"metrics,omitempty"`
	Traces  *otelCollectorPipeline `yaml:"traces,omitempty"`
}

type otelCollectorPipeline struct {
	Receivers  []string `yaml:"receivers"`
	Processors []string `yaml:"processors"`
	Exporters  []string `yaml:"exporters"`
}

// GenerateOTelCollectorConfig builds the OpenTelemetry Collector configuration
// for the gateway's metrics and tracing settings. It returns nil when both are
// disabled.
func Generate(c gatewayapi.Config) ([]byte, error) {
	effective, err := configuration.ResolveConfig(c)
	if err != nil {
		return nil, err
	}
	return generateOTelCollectorConfig(effective.Observability.Metrics, effective.Observability.Tracing)
}

func generateOTelCollectorConfig(metrics gatewayapi.ObservabilityMetrics, tracing gatewayapi.ObservabilityTracing) ([]byte, error) {
	metricsEnabled := configuration.EnabledObservabilityMetrics(metrics)
	tracingEnabled := configuration.EnabledObservabilityTracing(tracing)
	if !metricsEnabled && !tracingEnabled {
		return nil, nil
	}

	collectorConfig := otelCollectorConfig{}
	if metricsEnabled {
		collectorConfig.Receivers.Prometheus = &otelPrometheusReceiver{
			Config: otelPrometheusReceiverConfig{
				ScrapeConfigs: []otelPrometheusScrapeConfig{{
					JobName:        "auth-gateway",
					ScrapeInterval: prometheusDuration(*metrics.ScrapeInterval),
					ScrapeTimeout:  prometheusDuration(*metrics.ScrapeTimeout),
					MetricsPath:    "/stats/prometheus",
					StaticConfigs: []otelPrometheusStaticConfig{{
						Targets: []string{fmt.Sprintf("127.0.0.1:%d", configuration.EnvoyAdminPort)},
					}},
				}},
			},
		}
		collectorConfig.Processors.Transform = &otelTransformProcessor{
			MetricStatements: []otelTransformMetricStatements{{
				Context:    "metric",
				Statements: []string{`replace_pattern(name, "^envoy_http_lua_", "")`},
			}},
		}
		collectorConfig.Exporters.Prometheus = &otelPrometheusExporter{
			Endpoint: fmt.Sprintf("0.0.0.0:%d", configuration.DefaultOTelMetricsPort),
		}
		collectorConfig.Service.Pipelines.Metrics = &otelCollectorPipeline{
			Receivers:  []string{"prometheus"},
			Processors: []string{"transform"},
			Exporters:  []string{"prometheus"},
		}
	}
	if tracingEnabled {
		collectorConfig.Receivers.OTLP = &otelOTLPReceiver{
			Protocols: otelOTLPReceiverProtocols{
				GRPC: otelOTLPGRPCReceiver{Endpoint: fmt.Sprintf("%s:%d", configuration.DefaultOTelTraceReceiverAddress, configuration.DefaultOTelTracePort)},
			},
		}
		collectorConfig.Processors.Batch = &otelBatchProcessor{}
		collectorConfig.Exporters.OTLP = &otelOTLPExporter{Endpoint: tracing.Endpoint}
		if *tracing.Insecure {
			collectorConfig.Exporters.OTLP.TLS = &otelTLSConfig{Insecure: true}
		}
		collectorConfig.Service.Pipelines.Traces = &otelCollectorPipeline{
			Receivers:  []string{"otlp"},
			Processors: []string{"batch"},
			Exporters:  []string{"otlp"},
		}
	}

	var output bytes.Buffer
	encoder := yaml.NewEncoder(&output)
	encoder.SetIndent(2)
	encodeErr := encoder.Encode(collectorConfig)
	closeErr := encoder.Close()
	if err := errors.Join(encodeErr, closeErr); err != nil {
		return nil, fmt.Errorf("marshal OpenTelemetry Collector configuration: %w", err)
	}
	return output.Bytes(), nil
}

func prometheusDuration(d gatewayapi.Duration) string {
	if time.Duration(d)%time.Second == 0 {
		return fmt.Sprintf("%ds", time.Duration(d)/time.Second)
	}
	return fmt.Sprintf("%dms", time.Duration(d)/time.Millisecond)
}
