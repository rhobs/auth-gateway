package config

import (
	"path/filepath"
	"reflect"
	"testing"
	"time"

	yaml "go.yaml.in/yaml/v3"
	"k8s.io/apimachinery/pkg/api/resource"
)

func TestOTelCollectorScrapeSettingsAndResourceOverrides(t *testing.T) {
	c := loadConfigCase(t, "public-routing")
	c.Observability.Metrics.ScrapeInterval = duration(1500 * time.Millisecond)
	c.Observability.Metrics.ScrapeTimeout = duration(250 * time.Millisecond)
	c.Kubernetes.Metrics = KubernetesMetrics{Resources: KubernetesResourceRequirements{Requests: map[string]string{"cpu": "30m"}, Limits: map[string]string{}}}
	r, err := GenerateKubernetes(c)
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
	if err := yaml.Unmarshal([]byte(r.OTelCollectorConfigMap.Data[collectorConfigFilename]), &collector); err != nil {
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
	before, err := GenerateKubernetes(c)
	if err != nil {
		t.Fatal(err)
	}
	if before.OTelCollectorConfigMap == nil {
		t.Fatal("metrics-enabled configuration did not generate a collector ConfigMap")
	}

	c.Observability.Metrics.ScrapeInterval = duration(45 * time.Second)
	after, err := GenerateKubernetes(c)
	if err != nil {
		t.Fatal(err)
	}
	if after.OTelCollectorConfigMap == nil {
		t.Fatal("updated metrics configuration did not generate a collector ConfigMap")
	}
	if before.OTelCollectorConfigMap.Name != after.OTelCollectorConfigMap.Name {
		t.Fatalf("collector ConfigMap name changed from %q to %q", before.OTelCollectorConfigMap.Name, after.OTelCollectorConfigMap.Name)
	}
	if before.OTelCollectorConfigMap.Data[collectorConfigFilename] == after.OTelCollectorConfigMap.Data[collectorConfigFilename] {
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
	if err := yaml.Unmarshal([]byte(after.OTelCollectorConfigMap.Data[collectorConfigFilename]), &collector); err != nil {
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
		if volume.Name == metricsConfigVolumeName {
			configVolumeMatches = volume.ConfigMap != nil && volume.ConfigMap.Name == after.OTelCollectorConfigMap.Name
		}
	}
	for _, mount := range containers[1].VolumeMounts {
		if mount.Name == metricsConfigVolumeName {
			configMountMatches = mount.MountPath == collectorConfigDirectory && mount.ReadOnly && mount.SubPath == "" && mount.SubPathExpr == ""
		}
	}
	if !configVolumeMatches || !configMountMatches {
		t.Fatalf("collector ConfigMap volume and mount = %t/%t, want a projected directory mount", configVolumeMatches, configMountMatches)
	}
}

func TestPlaygroundOTelCollectorConfiguration(t *testing.T) {
	inputPath := filepath.Join("..", "playground", "config.yaml")
	c := loadTestConfig(t, readTestFile(t, inputPath), inputPath)
	collectorConfig, err := GenerateOTelCollectorConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	checkReference(t, filepath.Join("..", "playground", "otel-collector.yaml.golden"), collectorConfig)
}
