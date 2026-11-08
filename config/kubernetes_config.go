package config

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	defaultServicePort                   = 80
	defaultHTTPSServicePort              = 443
	defaultKubernetesCPURequest          = "50m"
	defaultKubernetesMemoryRequest       = "64Mi"
	defaultKubernetesCPULimit            = "1"
	defaultKubernetesMemoryLimit         = "256Mi"
	imageWhitespaceCharacters            = " \t\r\n"
	kubernetesCPUResourceName            = "cpu"
	kubernetesMemoryResourceName         = "memory"
	defaultKubernetesReplicas      int32 = 2
	// DefaultEnvoyImage is the default image used for generated Kubernetes Envoy containers.
	DefaultEnvoyImage = "envoyproxy/envoy:v1.39.1"
	// DefaultOTelCollectorImage is the default image used for the telemetry sidecar.
	DefaultOTelCollectorImage = "otel/opentelemetry-collector-contrib:0.135.0"
)

// KubernetesMetrics configures resources for the collector container.
type KubernetesMetrics struct {
	Resources KubernetesResourceRequirements `yaml:"resources,omitempty"`
}

// Kubernetes contains the settings needed to generate a Deployment and Service.
type Kubernetes struct {
	Name      string `yaml:"name"`
	Namespace string `yaml:"namespace"`
	// Image overrides the default Envoy image for generated Deployments.
	Image string `yaml:"image"`
	// OTelCollectorImage overrides the default OpenTelemetry Collector sidecar image.
	OTelCollectorImage string                         `yaml:"otel_collector_image,omitempty"`
	Replicas           *int32                         `yaml:"replicas,omitempty"`
	ServicePort        *int32                         `yaml:"service_port,omitempty"`
	HTTPSServicePort   *int32                         `yaml:"https_service_port,omitempty"`
	Resources          KubernetesResourceRequirements `yaml:"resources,omitempty"`
	EnvoyConcurrency   *uint32                        `yaml:"envoy_concurrency,omitempty"`
	Metrics            KubernetesMetrics              `yaml:"metrics,omitempty"`
}

// KubernetesResourceRequirements configures resources for a container.
// Values use Kubernetes resource quantity notation.
type KubernetesResourceRequirements struct {
	Requests map[string]string `yaml:"requests,omitempty"`
	Limits   map[string]string `yaml:"limits,omitempty"`
}

func (c Config) validateKubernetes(metricsEnabled, tracingEnabled bool) error {
	k := c.Kubernetes
	if strings.TrimSpace(k.Image) == "" || strings.ContainsAny(k.Image, imageWhitespaceCharacters) {
		return fmt.Errorf("kubernetes.image must be an image reference")
	}
	if err := validateOTelCollectorImage(k.OTelCollectorImage, metricsEnabled || tracingEnabled); err != nil {
		return err
	}
	if k.Replicas != nil && *k.Replicas < 0 {
		return fmt.Errorf("kubernetes.replicas must not be negative")
	}
	if err := c.validateKubernetesServicePorts(metricsEnabled); err != nil {
		return err
	}
	if k.EnvoyConcurrency != nil && *k.EnvoyConcurrency == 0 {
		return fmt.Errorf("kubernetes.envoy_concurrency must be positive")
	}
	if err := validateKubernetesResourceRequirements(kubernetesResourcesFieldPath, k.Resources); err != nil {
		return err
	}
	return k.Metrics.validate()
}

func (c Config) validateKubernetesServicePorts(metricsEnabled bool) error {
	k := c.Kubernetes
	if *k.ServicePort < 1 || *k.ServicePort > 65535 {
		if c.hasHTTP() {
			return fmt.Errorf("kubernetes.service_port must be between 1 and 65535")
		}
	}
	if c.hasHTTP() {
		if err := validateOTelMetricsServicePort("service_port", *k.ServicePort, metricsEnabled); err != nil {
			return err
		}
	}
	if c.hasHTTPS() {
		if err := c.validateTLSMounts(); err != nil {
			return err
		}
		if *k.HTTPSServicePort < 1 || *k.HTTPSServicePort > 65535 {
			return fmt.Errorf("kubernetes.https_service_port must be between 1 and 65535")
		}
		if err := validateOTelMetricsServicePort("https_service_port", *k.HTTPSServicePort, metricsEnabled); err != nil {
			return err
		}
		if c.hasHTTP() && *k.HTTPSServicePort == *k.ServicePort {
			return fmt.Errorf("kubernetes.service_port and kubernetes.https_service_port must differ")
		}
	} else if k.HTTPSServicePort != nil {
		return fmt.Errorf("kubernetes.https_service_port requires an HTTPS server")
	}
	return nil
}

func (k Kubernetes) withDefaults(hasHTTPS bool) Kubernetes {
	if k.Image == "" {
		k.Image = DefaultEnvoyImage
	}
	k.Replicas = defaultValue(k.Replicas, defaultKubernetesReplicas)
	k.ServicePort = defaultValue(k.ServicePort, int32(defaultServicePort))
	if hasHTTPS {
		k.HTTPSServicePort = defaultValue(k.HTTPSServicePort, int32(defaultHTTPSServicePort))
	}
	if k.OTelCollectorImage == "" {
		k.OTelCollectorImage = DefaultOTelCollectorImage
	}
	k.Metrics = k.Metrics.withDefaults()
	k.Resources.Requests = copyResourcesOrDefault(k.Resources.Requests, map[string]string{
		kubernetesCPUResourceName:    defaultKubernetesCPURequest,
		kubernetesMemoryResourceName: defaultKubernetesMemoryRequest,
	})
	k.Resources.Limits = copyResourcesOrDefault(k.Resources.Limits, map[string]string{
		kubernetesCPUResourceName:    defaultKubernetesCPULimit,
		kubernetesMemoryResourceName: defaultKubernetesMemoryLimit,
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

func kubernetesResourceRequirements(prefix string, requirements KubernetesResourceRequirements) (corev1.ResourceRequirements, error) {
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

func validateKubernetesResourceRequirements(prefix string, requirements KubernetesResourceRequirements) error {
	requestQuantities := make(map[string]resource.Quantity, len(requirements.Requests))
	limitQuantities := make(map[string]resource.Quantity, len(requirements.Limits))
	for _, list := range []struct {
		name       string
		values     map[string]string
		quantities map[string]resource.Quantity
	}{
		{name: "requests", values: requirements.Requests, quantities: requestQuantities},
		{name: "limits", values: requirements.Limits, quantities: limitQuantities},
	} {
		for _, name := range slices.Sorted(maps.Keys(list.values)) {
			if problems := validation.IsQualifiedName(name); len(problems) > 0 {
				return fmt.Errorf("%s.%s contains invalid resource name %q", prefix, list.name, name)
			}
			quantity, err := resource.ParseQuantity(list.values[name])
			if err != nil {
				return fmt.Errorf("%s.%s.%s must be a valid Kubernetes resource quantity: %w", prefix, list.name, name, err)
			}
			if quantity.Sign() < 0 {
				return fmt.Errorf("%s.%s.%s must not be negative", prefix, list.name, name)
			}
			list.quantities[name] = quantity
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

func (m KubernetesMetrics) clone() KubernetesMetrics {
	m.Resources = m.Resources.clone()
	return m
}

func (m KubernetesMetrics) withDefaults() KubernetesMetrics {
	m.Resources.Requests = copyResourcesOrDefault(m.Resources.Requests, map[string]string{kubernetesCPUResourceName: "20m", kubernetesMemoryResourceName: "64Mi"})
	m.Resources.Limits = copyResourcesOrDefault(m.Resources.Limits, map[string]string{kubernetesMemoryResourceName: "256Mi"})
	return m
}

func (m KubernetesMetrics) validate() error {
	return validateKubernetesResourceRequirements(kubernetesMetricsResourcesFieldPath, m.Resources)
}

func validateOTelCollectorImage(image string, collectorEnabled bool) error {
	if collectorEnabled && (strings.TrimSpace(image) == "" || strings.ContainsAny(image, imageWhitespaceCharacters)) {
		return fmt.Errorf("kubernetes.otel_collector_image must be an image reference")
	}
	return nil
}

func validateOTelMetricsServicePort(field string, port int32, metricsEnabled bool) error {
	if metricsEnabled && port == defaultOTelMetricsPort {
		return fmt.Errorf("kubernetes.%s must not conflict with the metrics port", field)
	}
	return nil
}

func (k Kubernetes) clone() Kubernetes {
	k.Replicas = clonePointer(k.Replicas)
	k.ServicePort = clonePointer(k.ServicePort)
	k.HTTPSServicePort = clonePointer(k.HTTPSServicePort)
	k.Resources = k.Resources.clone()
	k.EnvoyConcurrency = clonePointer(k.EnvoyConcurrency)
	k.Metrics = k.Metrics.clone()
	return k
}

func (r KubernetesResourceRequirements) clone() KubernetesResourceRequirements {
	r.Requests = maps.Clone(r.Requests)
	r.Limits = maps.Clone(r.Limits)
	return r
}
