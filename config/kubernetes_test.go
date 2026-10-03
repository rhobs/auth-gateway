package config

import (
	"reflect"
	"strings"
	"testing"
)

func TestGenerateKubernetesKeepsProcessingConfigOutsidePodTemplate(t *testing.T) {
	config, err := Load(strings.NewReader(readFixture(t, "jwt-auth-with-mappings/config.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	resources, err := GenerateKubernetes(config)
	if err != nil {
		t.Fatal(err)
	}
	if resources.ConfigMap.Data["envoy.yaml"] == "" {
		t.Fatal("Envoy bootstrap is missing from the gateway ConfigMap")
	}
	if resources.ProcessingConfigMap == nil {
		t.Fatal("attribute mappings did not generate a processing ConfigMap")
	}
	if got := resources.ProcessingConfigMap.Name; got != "auth-gateway-processing" {
		t.Fatalf("processing ConfigMap name = %q", got)
	}
	if resources.ProcessingConfigMap.Data[processingConfigFilename] == "" {
		t.Fatal("processing ConfigMap is missing its ECDS resource")
	}
	if _, exists := resources.ConfigMap.Data[processingConfigFilename]; exists {
		t.Fatal("processing ECDS resource was included in the main Envoy ConfigMap")
	}
	var processingVolume, processingMount bool
	for _, volume := range resources.Deployment.Spec.Template.Spec.Volumes {
		if volume.Name == "processing-config" {
			processingVolume = volume.ConfigMap != nil && volume.ConfigMap.Name == resources.ProcessingConfigMap.Name
			if !processingVolume || len(volume.ConfigMap.Items) != 1 || volume.ConfigMap.Items[0].Key != processingConfigFilename || volume.ConfigMap.Items[0].Path != processingConfigFilename {
				t.Fatalf("processing config volume = %#v", volume)
			}
		}
	}
	for _, mount := range resources.Deployment.Spec.Template.Spec.Containers[0].VolumeMounts {
		if mount.Name == "processing-config" {
			processingMount = mount.MountPath == processingDirectory && mount.ReadOnly && mount.SubPath == "" && mount.SubPathExpr == ""
		}
	}
	if !processingVolume || !processingMount {
		t.Fatalf("processing config volume/mount = %t/%t", processingVolume, processingMount)
	}
	if len(resources.Deployment.Spec.Template.Annotations) != 0 {
		t.Fatalf("Deployment template unexpectedly has rollout annotations: %#v", resources.Deployment.Spec.Template.Annotations)
	}

	config.Processing[0].Attributes["tenant_id"].Mappings["client-123"] = "team-c"
	updated, err := GenerateKubernetes(config)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(resources.ConfigMap.Data, updated.ConfigMap.Data) {
		t.Fatal("mapping update changed the main Envoy ConfigMap")
	}
	if updated.ProcessingConfigMap == nil || resources.ProcessingConfigMap.Data[processingConfigFilename] == updated.ProcessingConfigMap.Data[processingConfigFilename] {
		t.Fatal("mapping update did not change the processing ECDS resource")
	}
	if !reflect.DeepEqual(resources.Deployment.Spec.Template, updated.Deployment.Spec.Template) {
		t.Fatal("mapping update changed the Deployment template")
	}
}

func TestGenerateKubernetesOmitsProcessingConfigWithoutMappings(t *testing.T) {
	config := loadConfigCase(t, "jwt-auth-with-headers")
	resources, err := GenerateKubernetes(config)
	if err != nil {
		t.Fatal(err)
	}
	if resources.ProcessingConfigMap != nil {
		t.Fatal("direct header attributes generated an unnecessary processing ConfigMap")
	}
	for _, volume := range resources.Deployment.Spec.Template.Spec.Volumes {
		if volume.Name == "processing-config" {
			t.Fatal("direct header attributes generated an unnecessary processing volume")
		}
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

func TestGenerateKubernetesMountsServerTLSSecretAndSharesListenerPort(t *testing.T) {
	config, err := Load(strings.NewReader(readFixture(t, "public-routing/config.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := &ServerTLS{
		Secret:      "auth-gateway-tls",
		Certificate: "/etc/gateway-certs/tls.crt",
		PrivateKey:  "/etc/gateway-certs/tls.key",
	}
	config.Servers = []Server{
		{Hostname: "auth.example.com", APIs: []string{"metrics"}},
		{Hostname: "mts.auth.example.com", TLSConfig: tlsConfig, APIs: []string{"metrics"}},
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
	if len(ports) != 3 {
		t.Fatalf("Service ports = %#v, want HTTP, HTTPS, and metrics", ports)
	}
	if got := ports["http"]; got.port != defaultServicePort || got.targetPort != "http" {
		t.Fatalf("HTTP Service port = %#v", got)
	}
	if got := ports["https"]; got.port != defaultHTTPSServicePort || got.targetPort != "http" {
		t.Fatalf("HTTPS Service port = %#v, want port 443 targeting the same Envoy listener", got)
	}
	if got := resources.ConfigMap.Data["server-certificate-1.yaml"]; got == "" {
		t.Fatalf("config Map does not contain the server TLS SDS resource")
	}

	var tlsVolumeFound bool
	for _, volume := range resources.Deployment.Spec.Template.Spec.Volumes {
		if volume.Name == "server-tls-1" && volume.Secret != nil {
			tlsVolumeFound = true
			if volume.Secret.SecretName != tlsConfig.Secret {
				t.Errorf("mounted Secret = %q, want %q", volume.Secret.SecretName, tlsConfig.Secret)
			}
			if got := volume.Secret.Items; len(got) != 2 || got[0].Key != "tls.crt" || got[0].Path != "tls.crt" || got[1].Key != "tls.key" || got[1].Path != "tls.key" {
				t.Errorf("mounted TLS Secret items = %#v", got)
			}
		}
	}
	if !tlsVolumeFound {
		t.Fatal("Deployment has no projected server TLS Secret volume")
	}
	var tlsMountFound bool
	for _, mount := range resources.Deployment.Spec.Template.Spec.Containers[0].VolumeMounts {
		if mount.Name == "server-tls-1" && mount.MountPath == "/etc/gateway-certs" && mount.ReadOnly {
			tlsMountFound = true
		}
	}
	if !tlsMountFound {
		t.Fatal("Envoy does not mount the server TLS Secret directory read-only")
	}
}

func TestGenerateKubernetesOmitsHTTPServicePortForHTTPSOnly(t *testing.T) {
	config, err := Load(strings.NewReader(readFixture(t, "public-routing/config.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	config.Servers = []Server{{
		Hostname:  "mts.auth.example.com",
		TLSConfig: &ServerTLS{Secret: "auth-gateway-tls"},
		APIs:      []string{"metrics"},
	}}
	resources, err := GenerateKubernetes(config)
	if err != nil {
		t.Fatal(err)
	}
	if len(resources.Service.Spec.Ports) != 2 {
		t.Fatalf("HTTPS-only Service ports = %#v, want HTTPS and metrics", resources.Service.Spec.Ports)
	}
	if resources.Service.Spec.Ports[0].Name != "https" || resources.Service.Spec.Ports[0].Port != defaultHTTPSServicePort {
		t.Fatalf("HTTPS-only Service port = %#v", resources.Service.Spec.Ports[0])
	}
}

func TestGenerateKubernetesRequiresSettings(t *testing.T) {
	config, err := Load(strings.NewReader(readFixture(t, "public-routing/config.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	config.Kubernetes = nil
	if _, err := GenerateKubernetes(config); err == nil {
		t.Fatal("GenerateKubernetes accepted missing Kubernetes settings")
	}
}

func TestGenerateKubernetesSharesTLSSecretMount(t *testing.T) {
	config, err := Load(strings.NewReader(readFixture(t, "server-tls/config.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	config.Servers[2].TLSConfig = config.Servers[1].TLSConfig
	resources, err := GenerateKubernetes(config)
	if err != nil {
		t.Fatal(err)
	}
	pod := resources.Deployment.Spec.Template.Spec
	secretVolumes := 0
	for _, volume := range pod.Volumes {
		if volume.Secret != nil {
			secretVolumes++
			if volume.Secret.SecretName != "auth-gateway-tls" || volume.Secret.DefaultMode == nil || *volume.Secret.DefaultMode != 0o444 {
				t.Fatalf("unexpected shared Secret volume: %#v", volume.Secret)
			}
		}
	}
	if secretVolumes != 1 {
		t.Fatalf("shared Secret volume count = %d, want 1", secretVolumes)
	}
	tlsMounts := 0
	for _, mount := range pod.Containers[0].VolumeMounts {
		if mount.Name == "server-tls-1" {
			tlsMounts++
			if mount.MountPath != "/etc/auth-gateway-tls" || !mount.ReadOnly || mount.SubPath != "" || mount.SubPathExpr != "" {
				t.Fatalf("shared Secret mount prevents directory projection: %#v", mount)
			}
		}
	}
	if tlsMounts != 1 {
		t.Fatalf("shared TLS mount count = %d, want 1", tlsMounts)
	}
	if len(resources.ConfigMap.Data) != 3 {
		t.Fatal("shared certificate servers did not get separate SDS files")
	}
	for _, volume := range pod.Volumes {
		if volume.ConfigMap == nil || volume.Name != "config" {
			continue
		}
		if len(volume.ConfigMap.Items) != len(resources.ConfigMap.Data) {
			t.Fatal("Deployment does not project every generated config file")
		}
		previous := ""
		for _, item := range volume.ConfigMap.Items {
			if _, exists := resources.ConfigMap.Data[item.Key]; !exists || item.Path != item.Key || item.Key <= previous {
				t.Fatalf("unexpected ConfigMap item: %#v", item)
			}
			previous = item.Key
		}
	}
}

func TestGenerateKubernetesMountsSharedSecretAtDifferentPaths(t *testing.T) {
	config, err := Load(strings.NewReader(readFixture(t, "server-tls/config.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	config.Servers[2].TLSConfig = &ServerTLS{
		Secret: "auth-gateway-tls", Certificate: "/etc/query-tls/server.pem", PrivateKey: "/etc/query-tls/key.pem",
	}
	resources, err := GenerateKubernetes(config)
	if err != nil {
		t.Fatal(err)
	}
	secretVolumes := 0
	for _, volume := range resources.Deployment.Spec.Template.Spec.Volumes {
		if volume.Secret != nil {
			secretVolumes++
			if volume.Secret.SecretName != "auth-gateway-tls" {
				t.Fatal("mounted a different Secret")
			}
			if volume.Name == "server-tls-2" {
				items := volume.Secret.Items
				if len(items) != 2 || items[0].Path != "server.pem" || items[1].Path != "key.pem" {
					t.Fatalf("custom certificate filenames = %#v", items)
				}
			}
		}
	}
	if secretVolumes != 2 {
		t.Fatalf("Secret volume count = %d, want 2 for distinct paths", secretVolumes)
	}
}

func TestGenerateKubernetesFitsConfigMapNameLimit(t *testing.T) {
	config, err := Load(strings.NewReader(readFixture(t, "public-routing/config.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	config.Kubernetes.Name = strings.Repeat("a", 56)
	resources, err := GenerateKubernetes(config)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(resources.ConfigMap.Name); got != 63 {
		t.Fatalf("ConfigMap name length = %d, want 63", got)
	}
}
