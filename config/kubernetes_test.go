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
