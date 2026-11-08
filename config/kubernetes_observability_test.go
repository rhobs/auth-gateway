package config

import (
	"reflect"
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v3"
)

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
