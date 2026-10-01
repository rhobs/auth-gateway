package config

import (
	"bytes"
	"strings"
	"testing"
)

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

	want := bytes.Buffer{}
	for index, name := range []string{
		"kubernetes/configmap.yaml.golden",
		"kubernetes/service-account.yaml.golden",
		"kubernetes/deployment.yaml.golden",
		"kubernetes/service.yaml.golden",
	} {
		if index > 0 {
			want.WriteString("---\n")
		}
		want.WriteString(readFixture(t, name))
	}
	if !bytes.Equal(manifest, want.Bytes()) {
		t.Fatal("generated Kubernetes manifest does not match the golden files")
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
