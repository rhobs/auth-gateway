package kubernetes

import (
	"reflect"
	"strings"
	"testing"
	"time"

	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	configuration "github.com/rhobs/auth-gateway/pkg/config"
	yaml "go.yaml.in/yaml/v3"
	"k8s.io/apimachinery/pkg/api/resource"
)

func TestGenerateKubernetesTracingWithoutMetrics(t *testing.T) {
	c := loadConfigCase(t, "public-routing")
	c.Observability.Metrics.Enabled = new(false)
	c.Observability.Tracing = gatewayapi.ObservabilityTracing{
		Enabled:            new(true),
		Endpoint:           "jaeger:4317",
		ServiceName:        "auth-gateway-test",
		SamplingPercentage: new(100.0),
		Insecure:           new(true),
	}

	resources, err := Generate(c)
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
	if len(collectorContainer.Ports) != 1 || collectorContainer.Ports[0].Name != configuration.TracesPortName || collectorContainer.Ports[0].ContainerPort != configuration.DefaultOTelTracePort {
		t.Fatalf("trace-only collector ports = %#v", collectorContainer.Ports)
	}
	for _, port := range resources.Service.Spec.Ports {
		if port.Name == configuration.MetricsPortName || port.Name == configuration.TracesPortName {
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
	if err := yaml.Unmarshal([]byte(resources.OTelCollectorConfigMap.Data[configuration.CollectorConfigFilename]), &collector); err != nil {
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
	config, err := configuration.Load(strings.NewReader(readFixture(t, "public-routing/config.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	resources, err := Generate(config)
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
	if got := ports["http"]; got.port != configuration.DefaultServicePort || got.targetPort != "http" {
		t.Fatalf("HTTP Service port = %#v, want port %d targeting Envoy HTTP", got, configuration.DefaultServicePort)
	}
	if got := ports["metrics"]; got.port != configuration.DefaultOTelMetricsPort || got.targetPort != "metrics" {
		t.Fatalf("metrics Service port = %#v, want port %d targeting the collector", got, configuration.DefaultOTelMetricsPort)
	}
}

func TestGenerateKubernetesOmitsCollectorWhenMetricsAreDisabled(t *testing.T) {
	c := loadConfigCase(t, "api-key-auth")
	enabled, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	c.Observability.Metrics.Enabled = new(false)
	// With no collector port reserved, the HTTP Service can use 8889.
	c.Kubernetes.ServicePort = new(int32(configuration.DefaultOTelMetricsPort))
	disabled, err := Generate(c)
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
		if volume.Name == configuration.MetricsConfigVolumeName {
			t.Fatal("disabled metrics generated a collector config volume")
		}
	}
	servicePorts := make(map[string]int32, len(disabled.Service.Spec.Ports))
	for _, port := range disabled.Service.Spec.Ports {
		servicePorts[port.Name] = port.Port
	}
	if servicePorts["http"] != configuration.DefaultOTelMetricsPort {
		t.Fatalf("disabled metrics HTTP Service port = %d, want %d", servicePorts["http"], configuration.DefaultOTelMetricsPort)
	}
	if _, exists := servicePorts[configuration.MetricsPortName]; exists {
		t.Fatalf("disabled metrics Service still exposes the collector port: %#v", servicePorts)
	}
	if !reflect.DeepEqual(enabled.ConfigMap.Data, disabled.ConfigMap.Data) {
		t.Fatal("disabling collector metrics changed the Envoy bootstrap")
	}
}

func TestRequestMetricBindingChangesBootstrapOnly(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-with-attributes")
	before, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	c.APIs[0].Metrics.Labels["tenant"] = "writer_id"
	after, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	if before.ConfigMap.Data[configuration.EnvoyConfigFilename] == after.ConfigMap.Data[configuration.EnvoyConfigFilename] {
		t.Fatal("changing a metric label binding did not change the static Envoy bootstrap")
	}
	if !reflect.DeepEqual(before.Deployment.Spec.Template, after.Deployment.Spec.Template) {
		t.Fatal("changing a metric label binding changed the Deployment template")
	}
}

func TestRequestMetricNameChangesBootstrapOnly(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-with-attributes")
	before, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	*c.Observability.Metrics.CustomMetricName = "renamed_gateway_requests_total"
	after, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	if before.ConfigMap.Data[configuration.EnvoyConfigFilename] == after.ConfigMap.Data[configuration.EnvoyConfigFilename] {
		t.Fatal("changing the request metric name did not change the static Envoy bootstrap")
	}
	if !reflect.DeepEqual(before.Deployment.Spec.Template, after.Deployment.Spec.Template) {
		t.Fatal("changing the request metric name changed the Deployment template")
	}
}

func TestOTelCollectorScrapeSettingsAndResourceOverrides(t *testing.T) {
	c := loadConfigCase(t, "public-routing")
	c.Observability.Metrics.ScrapeInterval = duration(1500 * time.Millisecond)
	c.Observability.Metrics.ScrapeTimeout = duration(250 * time.Millisecond)
	c.Kubernetes.Metrics = gatewayapi.KubernetesMetrics{Resources: gatewayapi.KubernetesResourceRequirements{Requests: map[string]string{"cpu": "30m"}, Limits: map[string]string{}}}
	r, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	var collector struct {
		Receivers struct {
			Prometheus struct {
				Config struct {
					Scrapes []struct {
						Interval string `yaml:"scrape_interval"`
						Timeout  string `yaml:"scrape_timeout"`
					} `yaml:"scrape_configs"`
				} `yaml:"config"`
			} `yaml:"prometheus"`
		} `yaml:"receivers"`
	}
	if err := yaml.Unmarshal([]byte(r.OTelCollectorConfigMap.Data[configuration.CollectorConfigFilename]), &collector); err != nil {
		t.Fatal(err)
	}
	scrapes := collector.Receivers.Prometheus.Config.Scrapes
	if len(scrapes) != 1 || scrapes[0].Interval != "1500ms" || scrapes[0].Timeout != "250ms" {
		t.Fatalf("scrape timing = %+v", scrapes)
	}
	resources := r.Deployment.Spec.Template.Spec.Containers[1].Resources
	if len(resources.Requests) != 1 || resources.Requests.Cpu().Cmp(resource.MustParse("30m")) != 0 || len(resources.Limits) != 0 {
		t.Fatalf("collector resource overrides = %v", resources)
	}
}

func TestOTelCollectorConfigMapUpdateLeavesPodTemplateUnchanged(t *testing.T) {
	c := loadConfigCase(t, "public-routing")
	before, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	if before.OTelCollectorConfigMap == nil {
		t.Fatal("metrics-enabled configuration did not generate a collector ConfigMap")
	}

	c.Observability.Metrics.ScrapeInterval = duration(45 * time.Second)
	after, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	if after.OTelCollectorConfigMap == nil {
		t.Fatal("updated metrics configuration did not generate a collector ConfigMap")
	}
	if before.OTelCollectorConfigMap.Name != after.OTelCollectorConfigMap.Name {
		t.Fatalf("collector ConfigMap name changed from %q to %q", before.OTelCollectorConfigMap.Name, after.OTelCollectorConfigMap.Name)
	}
	if before.OTelCollectorConfigMap.Data[configuration.CollectorConfigFilename] == after.OTelCollectorConfigMap.Data[configuration.CollectorConfigFilename] {
		t.Fatal("changing the scrape interval did not update the collector ConfigMap")
	}
	var collector struct {
		Receivers struct {
			Prometheus struct {
				Config struct {
					ScrapeConfigs []struct {
						ScrapeInterval string `yaml:"scrape_interval"`
					} `yaml:"scrape_configs"`
				} `yaml:"config"`
			} `yaml:"prometheus"`
		} `yaml:"receivers"`
	}
	if err := yaml.Unmarshal([]byte(after.OTelCollectorConfigMap.Data[configuration.CollectorConfigFilename]), &collector); err != nil {
		t.Fatal(err)
	}
	scrapes := collector.Receivers.Prometheus.Config.ScrapeConfigs
	if len(scrapes) != 1 || scrapes[0].ScrapeInterval != "45s" {
		t.Fatalf("updated collector scrape interval = %+v, want 45s", scrapes)
	}
	if !reflect.DeepEqual(before.ConfigMap.Data, after.ConfigMap.Data) {
		t.Fatal("changing the scrape interval changed the Envoy ConfigMap")
	}
	if !reflect.DeepEqual(before.Deployment.Spec.Template, after.Deployment.Spec.Template) {
		t.Fatal("changing the scrape interval changed the Deployment Pod template")
	}
	if len(after.Deployment.Spec.Template.Annotations) != 0 {
		t.Fatalf("collector ConfigMap update unexpectedly has rollout annotations: %#v", after.Deployment.Spec.Template.Annotations)
	}

	var configVolumeMatches, configMountMatches bool
	containers := after.Deployment.Spec.Template.Spec.Containers
	if len(containers) != 2 {
		t.Fatalf("metrics-enabled deployment has %d containers, want Envoy and collector", len(containers))
	}
	for _, volume := range after.Deployment.Spec.Template.Spec.Volumes {
		if volume.Name == configuration.MetricsConfigVolumeName {
			configVolumeMatches = volume.ConfigMap != nil && volume.ConfigMap.Name == after.OTelCollectorConfigMap.Name
		}
	}
	for _, mount := range containers[1].VolumeMounts {
		if mount.Name == configuration.MetricsConfigVolumeName {
			configMountMatches = mount.MountPath == configuration.CollectorConfigDirectory && mount.ReadOnly && mount.SubPath == "" && mount.SubPathExpr == ""
		}
	}
	if !configVolumeMatches || !configMountMatches {
		t.Fatalf("collector ConfigMap volume and mount = %t/%t, want a projected directory mount", configVolumeMatches, configMountMatches)
	}
}
