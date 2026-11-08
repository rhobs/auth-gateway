package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kjson "k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	kubernetesConfigMapKind             = "ConfigMap"
	kubernetesResourcesFieldPath        = "kubernetes.resources"
	kubernetesMetricsResourcesFieldPath = "kubernetes.metrics.resources"
	terminationGracePeriodSeconds       = int64(30)
	preStopDrainDelaySeconds            = 5
	httpPortName                        = "http"
	httpsPortName                       = "https"
	gatewayConfigVolumeName             = "config"
	apiKeySecretVolumeName              = "api-keys"
	configDirectory                     = EnvoyConfigDirectory
	apiKeyDirectory                     = APIKeyConfigDirectory
)

// KubernetesResources contains native objects generated for a gateway.
type KubernetesResources struct {
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

func resourceNameWithSuffix(name, suffix string) string {
	const maxDNSLabelLength = 63
	if len(name)+len(suffix) <= maxDNSLabelLength {
		return name + suffix
	}

	digest := sha256.Sum256([]byte(name))
	hash := hex.EncodeToString(digest[:5])
	prefixLength := maxDNSLabelLength - len(suffix) - len(hash) - 1
	return name[:prefixLength] + "-" + hash + suffix
}

// GenerateKubernetes builds Kubernetes resources for Envoy and optional observability collection.
// It does not contact a cluster, read credentials, or write files.
func GenerateKubernetes(c Config) (*KubernetesResources, error) {
	effective, err := resolveConfig(c)
	if err != nil {
		return nil, err
	}
	c = effective.Config
	if c.Kubernetes == nil {
		return nil, fmt.Errorf("kubernetes settings are required")
	}
	files, err := generate(effective)
	if err != nil {
		return nil, err
	}
	configName := c.Kubernetes.Name + "-config"
	metricsName := metricsResourceName(c.Kubernetes.Name)
	metricsEnabled := c.Observability.Metrics.enabled()
	collectorConfigMap, err := newOTelCollectorConfigMap(c, metricsName)
	if err != nil {
		return nil, err
	}
	deployment, err := newGatewayDeployment(effective, files, configName, metricsName)
	if err != nil {
		return nil, err
	}
	return &KubernetesResources{
		ConfigMap:              newGatewayConfigMap(c, configName, files),
		OTelCollectorConfigMap: collectorConfigMap,
		ServiceAccount:         newGatewayServiceAccount(c),
		Deployment:             deployment,
		Service:                newGatewayService(c, metricsEnabled),
	}, nil
}

func newGatewayConfigMap(c Config, name string, files map[string][]byte) corev1.ConfigMap {
	return corev1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: kubernetesConfigMapKind},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: c.Kubernetes.Namespace},
		Data:       stringFiles(files),
	}
}

func newOTelCollectorConfigMap(c Config, name string) (*corev1.ConfigMap, error) {
	if !c.Observability.Metrics.enabled() && !c.Observability.Tracing.enabled() {
		return nil, nil
	}
	otelConfig, err := generateOTelCollectorConfig(c.Observability.Metrics, c.Observability.Tracing)
	if err != nil {
		return nil, err
	}
	return &corev1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: kubernetesConfigMapKind},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: c.Kubernetes.Namespace},
		Data:       map[string]string{collectorConfigFilename: string(otelConfig)},
	}, nil
}

func newGatewayServiceAccount(c Config) corev1.ServiceAccount {
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

func newGatewayService(c Config, metricsEnabled bool) corev1.Service {
	k := c.Kubernetes
	servicePorts := make([]corev1.ServicePort, 0, 3)
	if c.hasHTTP() {
		servicePorts = append(servicePorts, corev1.ServicePort{
			Name: httpPortName, Port: *k.ServicePort,
			TargetPort: intstr.FromString(httpPortName), Protocol: corev1.ProtocolTCP,
		})
	}
	if c.hasHTTPS() {
		servicePorts = append(servicePorts, corev1.ServicePort{
			Name: httpsPortName, Port: *k.HTTPSServicePort,
			TargetPort: intstr.FromString(httpPortName), Protocol: corev1.ProtocolTCP,
		})
	}
	if metricsEnabled {
		servicePorts = append(servicePorts, corev1.ServicePort{
			Name: metricsPortName, Port: defaultOTelMetricsPort,
			TargetPort: intstr.FromString(metricsPortName), Protocol: corev1.ProtocolTCP,
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

func kubernetesLabels(c Config) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":     "auth-gateway",
		"app.kubernetes.io/instance": c.Kubernetes.Name,
	}
}

// Objects returns the resources in apply order.
func (r *KubernetesResources) Objects() []runtime.Object {
	objects := []runtime.Object{&r.ConfigMap}
	if r.OTelCollectorConfigMap != nil {
		objects = append(objects, r.OTelCollectorConfigMap)
	}
	return append(objects, &r.ServiceAccount, &r.Deployment, &r.Service)
}

// YAML serializes all resources as a Kubernetes manifest stream.
func (r *KubernetesResources) YAML() ([]byte, error) {
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
