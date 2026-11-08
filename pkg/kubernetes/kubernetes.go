package kubernetes

import (
	"bytes"
	"fmt"
	"maps"
	"slices"

	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	configuration "github.com/rhobs/auth-gateway/pkg/config"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kjson "k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// KubernetesResources contains native objects generated for a gateway.
type Resources struct {
	// ConfigMap contains the Envoy bootstrap and static Envoy resources.
	ConfigMap corev1.ConfigMap
	// OTelCollectorConfigMap contains collector configuration. It is nil when
	// both metrics and tracing are disabled.
	OTelCollectorConfigMap *corev1.ConfigMap
	// ServiceAccount is assigned to the gateway Deployment.
	ServiceAccount corev1.ServiceAccount
	// Deployment runs Envoy and, when enabled, the OpenTelemetry Collector.
	Deployment appsv1.Deployment
	// Service exposes the configured gateway and metrics ports.
	Service corev1.Service
}

func newGatewayConfigMap(c gatewayapi.Config, name string, files map[string][]byte) corev1.ConfigMap {
	return corev1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: configuration.KubernetesConfigMapKind},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: c.Kubernetes.Namespace},
		Data:       stringFiles(files),
	}
}

func newGatewayServiceAccount(c gatewayapi.Config) corev1.ServiceAccount {
	k := c.Kubernetes
	return corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "ServiceAccount"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      k.Name,
			Namespace: k.Namespace,
			Labels:    kubernetesLabels(c),
		},
		AutomountServiceAccountToken: new(false),
	}
}

func newGatewayService(c gatewayapi.Config, metricsEnabled bool) corev1.Service {
	k := c.Kubernetes
	servicePorts := make([]corev1.ServicePort, 0, 3)
	if configuration.HasHTTPConfig(c) {
		servicePorts = append(servicePorts, corev1.ServicePort{
			Name: configuration.HttpPortName, Port: *k.ServicePort,
			TargetPort: intstr.FromString(configuration.HttpPortName), Protocol: corev1.ProtocolTCP,
		})
	}
	if configuration.HasHTTPSConfig(c) {
		servicePorts = append(servicePorts, corev1.ServicePort{
			Name: configuration.HttpsPortName, Port: *k.HTTPSServicePort,
			TargetPort: intstr.FromString(configuration.HttpPortName), Protocol: corev1.ProtocolTCP,
		})
	}
	if metricsEnabled {
		servicePorts = append(servicePorts, corev1.ServicePort{
			Name: configuration.MetricsPortName, Port: configuration.DefaultOTelMetricsPort,
			TargetPort: intstr.FromString(configuration.MetricsPortName), Protocol: corev1.ProtocolTCP,
		})
	}
	return corev1.Service{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Service"},
		ObjectMeta: metav1.ObjectMeta{
			Name: k.Name, Namespace: k.Namespace, Labels: kubernetesLabels(c),
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP, Selector: kubernetesLabels(c), Ports: servicePorts,
		},
	}
}

func kubernetesLabels(c gatewayapi.Config) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":     "auth-gateway",
		"app.kubernetes.io/instance": c.Kubernetes.Name,
	}
}

// Objects returns the resources in apply order.
func (r *Resources) Objects() []runtime.Object {
	objects := []runtime.Object{&r.ConfigMap}
	if r.OTelCollectorConfigMap != nil {
		objects = append(objects, r.OTelCollectorConfigMap)
	}
	return append(objects, &r.ServiceAccount, &r.Deployment, &r.Service)
}

// YAML serializes all resources as a Kubernetes manifest stream.
func (r *Resources) YAML() ([]byte, error) {
	serializer := kjson.NewSerializerWithOptions(kjson.DefaultMetaFactory, nil, nil, kjson.SerializerOptions{Yaml: true})
	var output bytes.Buffer
	for index, object := range r.Objects() {
		if index > 0 {
			output.WriteString("---\n")
		}
		if err := serializer.Encode(object, &output); err != nil {
			return nil, fmt.Errorf("encode Kubernetes %T: %w", object, err)
		}
	}
	return output.Bytes(), nil
}

func stringFiles(files map[string][]byte) map[string]string {
	data := make(map[string]string, len(files))
	for filename, contents := range files {
		data[filename] = string(contents)
	}
	return data
}

func configMapItems(files map[string][]byte) []corev1.KeyToPath {
	items := make([]corev1.KeyToPath, 0, len(files))
	for _, name := range slices.Sorted(maps.Keys(files)) {
		items = append(items, corev1.KeyToPath{Key: name, Path: name})
	}
	return items
}
