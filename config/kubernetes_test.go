package config

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var updateGolden = flag.Bool("update", false, "update Kubernetes manifest golden files")

func TestGenerateKubernetesMatchesGoldenManifest(t *testing.T) {
	config, err := Load(strings.NewReader(readFixture(t, "example.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	resources, err := GenerateKubernetes(config)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := resources.YAML()
	if err != nil {
		t.Fatal(err)
	}

	goldenFiles := []string{
		"kubernetes/configmap.yaml.golden",
		"kubernetes/otel-collector-configmap.yaml.golden",
		"kubernetes/service-account.yaml.golden",
		"kubernetes/deployment.yaml.golden",
		"kubernetes/service.yaml.golden",
	}
	documents := bytes.Split(manifest, []byte("\n---\n"))
	if len(documents) != len(goldenFiles) {
		t.Fatalf("generated %d Kubernetes documents, want %d", len(documents), len(goldenFiles))
	}
	for index := 0; index < len(documents)-1; index++ {
		documents[index] = append(documents[index], '\n')
	}

	want := bytes.Buffer{}
	for index, name := range goldenFiles {
		if *updateGolden {
			path := filepath.Join("testdata", name)
			if err := os.WriteFile(path, documents[index], 0o644); err != nil {
				t.Fatalf("update golden file %q: %v", path, err)
			}
		}
		if index > 0 {
			want.WriteString("---\n")
		}
		want.WriteString(readFixture(t, name))
	}
	if !bytes.Equal(manifest, want.Bytes()) {
		t.Fatal("generated Kubernetes manifest does not match the golden files")
	}
}

func TestGenerateKubernetesTLSConfigMapMatchesGolden(t *testing.T) {
	config, err := Load(strings.NewReader(readFixture(t, "tls.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	resources, err := GenerateKubernetes(config)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := resources.YAML()
	if err != nil {
		t.Fatal(err)
	}
	documents := bytes.SplitN(manifest, []byte("\n---\n"), 2)
	if len(documents) != 2 {
		t.Fatalf("generated %d Kubernetes documents, want ConfigMap followed by another resource", len(documents))
	}
	configMap := append(documents[0], '\n')
	const name = "kubernetes/configmap-tls.yaml.golden"
	if *updateGolden {
		path := filepath.Join("testdata", name)
		if err := os.WriteFile(path, configMap, 0o644); err != nil {
			t.Fatalf("update golden file %q: %v", path, err)
		}
	}
	if want := []byte(readFixture(t, name)); !bytes.Equal(configMap, want) {
		t.Fatal("generated TLS ConfigMap does not match the golden file")
	}
}

func TestGenerateKubernetesExposesMetricsWithoutAdminPort(t *testing.T) {
	config, err := Load(strings.NewReader(readFixture(t, "example.yaml")))
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
	config, err := Load(strings.NewReader(readFixture(t, "example.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	config.Listener.HTTPHosts = []string{"auth.example.com"}
	config.Listener.HTTPSHosts = []string{"mts.auth.example.com"}
	config.ServerTLS = &ServerTLS{
		Secret:      "auth-gateway-tls",
		Certificate: "/etc/gateway-certs/tls.crt",
		PrivateKey:  "/etc/gateway-certs/tls.key",
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
	if got := resources.ConfigMap.Data[serverTLSResourceFilename]; got == "" {
		t.Fatalf("config Map does not contain the server TLS SDS resource")
	}

	var tlsVolumeFound bool
	for _, volume := range resources.Deployment.Spec.Template.Spec.Volumes {
		if volume.Name == "server-tls" && volume.Secret != nil {
			tlsVolumeFound = true
			if volume.Secret.SecretName != config.ServerTLS.Secret {
				t.Errorf("mounted Secret = %q, want %q", volume.Secret.SecretName, config.ServerTLS.Secret)
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
		if mount.Name == "server-tls" && mount.MountPath == "/etc/gateway-certs" && mount.ReadOnly {
			tlsMountFound = true
		}
	}
	if !tlsMountFound {
		t.Fatal("Envoy does not mount the server TLS Secret directory read-only")
	}
}

func TestGenerateKubernetesOmitsHTTPServicePortForHTTPSOnly(t *testing.T) {
	config, err := Load(strings.NewReader(readFixture(t, "example.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	config.Listener.HTTPHosts = nil
	config.Listener.HTTPSHosts = []string{"mts.auth.example.com"}
	config.ServerTLS = &ServerTLS{Secret: "auth-gateway-tls"}
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
	config, err := Load(strings.NewReader(readFixture(t, "example.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	config.Kubernetes = nil
	if _, err := GenerateKubernetes(config); err == nil {
		t.Fatal("GenerateKubernetes accepted missing Kubernetes settings")
	}
}

func TestGenerateKubernetesFitsConfigMapNameLimit(t *testing.T) {
	config, err := Load(strings.NewReader(readFixture(t, "example.yaml")))
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
