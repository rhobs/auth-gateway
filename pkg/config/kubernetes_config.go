package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"strings"

	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	KubernetesConfigMapKind             = "ConfigMap"
	KubernetesResourcesFieldPath        = "kubernetes.resources"
	KubernetesMetricsResourcesFieldPath = "kubernetes.metrics.resources"
	TerminationGracePeriodSeconds       = int64(30)
	PreStopDrainDelaySeconds            = 5
	HttpPortName                        = "http"
	HttpsPortName                       = "https"
	GatewayConfigVolumeName             = "config"
	ApiKeySecretVolumeName              = "api-keys"
	ConfigDirectory                     = EnvoyConfigDirectory
	ApiKeyDirectory                     = APIKeyConfigDirectory
)

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

const (
	DefaultServicePort                   = 80
	DefaultHTTPSServicePort              = 443
	DefaultKubernetesCPURequest          = "50m"
	DefaultKubernetesMemoryRequest       = "64Mi"
	DefaultKubernetesCPULimit            = "1"
	DefaultKubernetesMemoryLimit         = "256Mi"
	ImageWhitespaceCharacters            = " \t\r\n"
	KubernetesCPUResourceName            = "cpu"
	KubernetesMemoryResourceName         = "memory"
	DefaultKubernetesReplicas      int32 = 2
	// DefaultEnvoyImage is the default image used for generated Kubernetes Envoy containers.
	DefaultEnvoyImage = "envoyproxy/envoy:v1.39.1"
	// DefaultOTelCollectorImage is the default image used for the telemetry sidecar.
	DefaultOTelCollectorImage = "otel/opentelemetry-collector-contrib:0.135.0"
)

func withDefaultsKubernetes(k gatewayapi.Kubernetes, hasHTTPS bool) gatewayapi.Kubernetes {
	if k.Image == "" {
		k.Image = DefaultEnvoyImage
	}
	k.Replicas = defaultValue(k.Replicas, DefaultKubernetesReplicas)
	k.ServicePort = defaultValue(k.ServicePort, int32(DefaultServicePort))
	if hasHTTPS {
		k.HTTPSServicePort = defaultValue(k.HTTPSServicePort, int32(DefaultHTTPSServicePort))
	}
	if k.OTelCollectorImage == "" {
		k.OTelCollectorImage = DefaultOTelCollectorImage
	}
	k.Metrics = withDefaultsKubernetesMetrics(k.Metrics)
	k.Resources.Requests = copyResourcesOrDefault(k.Resources.Requests, map[string]string{
		KubernetesCPUResourceName:    DefaultKubernetesCPURequest,
		KubernetesMemoryResourceName: DefaultKubernetesMemoryRequest,
	})
	k.Resources.Limits = copyResourcesOrDefault(k.Resources.Limits, map[string]string{
		KubernetesCPUResourceName:    DefaultKubernetesCPULimit,
		KubernetesMemoryResourceName: DefaultKubernetesMemoryLimit,
	})
	return k
}

func copyResourcesOrDefault(values, defaults map[string]string) map[string]string {
	if values == nil {
		values = defaults
	}
	c := make(map[string]string, len(values))
	maps.Copy(c, values)
	return c
}

func KubernetesResourceRequirements(prefix string, requirements gatewayapi.KubernetesResourceRequirements) (corev1.ResourceRequirements, error) {
	requests, err := kubernetesResourceList(prefix+".requests", requirements.Requests)
	if err != nil {
		return corev1.ResourceRequirements{}, err
	}
	limits, err := kubernetesResourceList(prefix+".limits", requirements.Limits)
	if err != nil {
		return corev1.ResourceRequirements{}, err
	}
	return corev1.ResourceRequirements{Requests: requests, Limits: limits}, nil
}

func kubernetesResourceList(prefix string, values map[string]string) (corev1.ResourceList, error) {
	if values == nil {
		return nil, nil
	}
	resources := make(corev1.ResourceList, len(values))
	for _, name := range slices.Sorted(maps.Keys(values)) {
		quantity, err := resource.ParseQuantity(values[name])
		if err != nil {
			return nil, fmt.Errorf("%s.%s must be a valid Kubernetes resource quantity: %w", prefix, name, err)
		}
		resources[corev1.ResourceName(name)] = quantity
	}
	return resources, nil
}

func validateKubernetesResourceRequirements(prefix string, requirements gatewayapi.KubernetesResourceRequirements) error {
	requestQuantities := make(map[string]resource.Quantity, len(requirements.Requests))
	limitQuantities := make(map[string]resource.Quantity, len(requirements.Limits))
	for _, list := range []struct {
		Name       string
		Values     map[string]string
		Quantities map[string]resource.Quantity
	}{
		{Name: "requests", Values: requirements.Requests, Quantities: requestQuantities},
		{Name: "limits", Values: requirements.Limits, Quantities: limitQuantities},
	} {
		for _, name := range slices.Sorted(maps.Keys(list.Values)) {
			if problems := validation.IsQualifiedName(name); len(problems) > 0 {
				return fmt.Errorf("%s.%s contains invalid resource name %q", prefix, list.Name, name)
			}
			quantity, err := resource.ParseQuantity(list.Values[name])
			if err != nil {
				return fmt.Errorf("%s.%s.%s must be a valid Kubernetes resource quantity: %w", prefix, list.Name, name, err)
			}
			if quantity.Sign() < 0 {
				return fmt.Errorf("%s.%s.%s must not be negative", prefix, list.Name, name)
			}
			list.Quantities[name] = quantity
		}
	}
	for _, name := range slices.Sorted(maps.Keys(requirements.Requests)) {
		if limit, ok := limitQuantities[name]; ok {
			request := requestQuantities[name]
			if request.Cmp(limit) > 0 {
				return fmt.Errorf("%s.requests.%s must not exceed %s.limits.%s", prefix, name, prefix, name)
			}
		}
	}
	return nil
}

func cloneKubernetesMetrics(m gatewayapi.KubernetesMetrics) gatewayapi.KubernetesMetrics {
	m.Resources = cloneKubernetesResourceRequirements(m.Resources)
	return m
}

func withDefaultsKubernetesMetrics(m gatewayapi.KubernetesMetrics) gatewayapi.KubernetesMetrics {
	m.Resources.Requests = copyResourcesOrDefault(m.Resources.Requests, map[string]string{KubernetesCPUResourceName: "20m", KubernetesMemoryResourceName: "64Mi"})
	m.Resources.Limits = copyResourcesOrDefault(m.Resources.Limits, map[string]string{KubernetesMemoryResourceName: "256Mi"})
	return m
}

func validateKubernetesMetrics(m gatewayapi.KubernetesMetrics) error {
	return validateKubernetesResourceRequirements(KubernetesMetricsResourcesFieldPath, m.Resources)
}

func validateOTelCollectorImage(image string, collectorEnabled bool) error {
	if collectorEnabled && (strings.TrimSpace(image) == "" || strings.ContainsAny(image, ImageWhitespaceCharacters)) {
		return fmt.Errorf("kubernetes.otel_collector_image must be an image reference")
	}
	return nil
}

func validateOTelMetricsServicePort(field string, port int32, metricsEnabled bool) error {
	if metricsEnabled && port == DefaultOTelMetricsPort {
		return fmt.Errorf("kubernetes.%s must not conflict with the metrics port", field)
	}
	return nil
}

func cloneKubernetes(k gatewayapi.Kubernetes) gatewayapi.Kubernetes {
	k.Replicas = clonePointer(k.Replicas)
	k.ServicePort = clonePointer(k.ServicePort)
	k.HTTPSServicePort = clonePointer(k.HTTPSServicePort)
	k.Resources = cloneKubernetesResourceRequirements(k.Resources)
	k.EnvoyConcurrency = clonePointer(k.EnvoyConcurrency)
	k.Metrics = cloneKubernetesMetrics(k.Metrics)
	return k
}

func cloneKubernetesResourceRequirements(r gatewayapi.KubernetesResourceRequirements) gatewayapi.KubernetesResourceRequirements {
	r.Requests = maps.Clone(r.Requests)
	r.Limits = maps.Clone(r.Limits)
	return r
}
