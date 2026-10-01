package config

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
)

func TestGenerateKubernetesProducesValidManifestStream(t *testing.T) {
	config, err := Load(strings.NewReader(exampleConfig))
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

	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := appsv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	deserializer := serializer.NewCodecFactory(scheme).UniversalDeserializer()
	decoder := utilyaml.NewYAMLToJSONDecoder(bytes.NewReader(manifest))
	wantKinds := []string{"ConfigMap", "ServiceAccount", "Deployment", "Service"}
	for index, wantKind := range wantKinds {
		var document map[string]any
		if err := decoder.Decode(&document); err != nil {
			t.Fatalf("decode manifest %d: %v", index, err)
		}
		if got := document["kind"]; got != wantKind {
			t.Fatalf("manifest %d kind = %v, want %q", index, got, wantKind)
		}
		jsonData, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := deserializer.Decode(jsonData, nil, nil); err != nil {
			t.Fatalf("deserialize Kubernetes object %q: %v", wantKind, err)
		}
	}
	var extra map[string]any
	if err := decoder.Decode(&extra); err != io.EOF {
		t.Fatalf("manifest stream has extra content: %v", err)
	}

	generatedEnvoy, err := Generate(config)
	if err != nil {
		t.Fatal(err)
	}
	if got := resources.ConfigMap.Data["envoy.yaml"]; got != string(generatedEnvoy["envoy.yaml"]) {
		t.Fatal("ConfigMap does not contain the generated Envoy configuration")
	}
	if resources.ServiceAccount.AutomountServiceAccountToken == nil || *resources.ServiceAccount.AutomountServiceAccountToken {
		t.Fatal("ServiceAccount must not mount a Kubernetes API token")
	}
	if !reflect.DeepEqual(resources.Service.Spec.Selector, resources.Deployment.Spec.Template.Labels) {
		t.Fatal("Service selector does not match Deployment pod labels")
	}
	if !reflect.DeepEqual(resources.Deployment.Spec.Selector.MatchLabels, resources.Deployment.Spec.Template.Labels) {
		t.Fatal("Deployment selector does not match pod labels")
	}
	resources.Service.Spec.Selector["app.kubernetes.io/instance"] = "changed"
	if resources.Deployment.Spec.Template.Labels["app.kubernetes.io/instance"] == "changed" {
		t.Fatal("Service and Deployment selectors share mutable labels")
	}
	if got := resources.Service.Spec.Ports[0].TargetPort.String(); got != "http" {
		t.Fatalf("Service target port = %q", got)
	}
	if len(resources.Deployment.Spec.Template.Spec.Containers[0].VolumeMounts) != 1 ||
		!resources.Deployment.Spec.Template.Spec.Containers[0].VolumeMounts[0].ReadOnly {
		t.Fatal("Envoy configuration must be mounted read-only")
	}
	securityContext := resources.Deployment.Spec.Template.Spec.Containers[0].SecurityContext
	if securityContext == nil || securityContext.RunAsUser == nil || *securityContext.RunAsUser != 101 ||
		securityContext.RunAsGroup == nil || *securityContext.RunAsGroup != 101 ||
		securityContext.RunAsNonRoot == nil || !*securityContext.RunAsNonRoot {
		t.Fatal("Envoy must run as the non-root image user")
	}
}

func TestGenerateKubernetesRequiresSettings(t *testing.T) {
	config, err := Load(strings.NewReader(exampleConfig))
	if err != nil {
		t.Fatal(err)
	}
	config.Kubernetes = nil
	if _, err := GenerateKubernetes(config); err == nil {
		t.Fatal("GenerateKubernetes accepted missing Kubernetes settings")
	}
}

func TestGenerateKubernetesFitsConfigMapNameLimit(t *testing.T) {
	config, err := Load(strings.NewReader(exampleConfig))
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
