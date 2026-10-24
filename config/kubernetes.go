package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"path"
	"slices"
	"strconv"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kjson "k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	kubernetesConfigMapKind             = "ConfigMap"
	kubernetesResourcesFieldPath        = "kubernetes.resources"
	kubernetesMetricsResourcesFieldPath = "kubernetes.metrics.resources"
	terminationGracePeriodSeconds       = int64(30)
	preStopDrainDelaySeconds            = 5
)

const (
	httpPortName            = "http"
	httpsPortName           = "https"
	gatewayConfigVolumeName = "config"
	apiKeySecretVolumeName  = "api-keys"
)

const (
	configDirectory = EnvoyConfigDirectory
	apiKeyDirectory = APIKeyConfigDirectory
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

func newGatewayDeployment(c effectiveConfig, configFiles map[string][]byte, configName, metricsName string) (appsv1.Deployment, error) {
	k := c.Kubernetes
	preStopDrainCommand := fmt.Sprintf("sleep %d", preStopDrainDelaySeconds)
	gatewayResources, err := kubernetesResourceRequirements(kubernetesResourcesFieldPath, k.Resources)
	if err != nil {
		return appsv1.Deployment{}, err
	}
	collectorResources, err := kubernetesResourceRequirements(kubernetesMetricsResourcesFieldPath, k.Metrics.Resources)
	if err != nil {
		return appsv1.Deployment{}, err
	}
	envoyArgs := []string{"-c", EnvoyBootstrapPath, "--log-level", "info"}
	if k.EnvoyConcurrency != nil {
		envoyArgs = append(envoyArgs, "--concurrency", strconv.FormatUint(uint64(*k.EnvoyConcurrency), 10))
	}
	deployment := appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      k.Name,
			Namespace: k.Namespace,
			Labels:    kubernetesLabels(c.Config),
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: k.Replicas,
			Selector: &metav1.LabelSelector{MatchLabels: kubernetesLabels(c.Config)},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: kubernetesLabels(c.Config)},
				Spec: corev1.PodSpec{
					ServiceAccountName:            k.Name,
					AutomountServiceAccountToken:  new(false),
					TerminationGracePeriodSeconds: new(terminationGracePeriodSeconds),
					SecurityContext: &corev1.PodSecurityContext{
						SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
					},
					Containers: []corev1.Container{{
						Name:            "envoy",
						Image:           k.Image,
						ImagePullPolicy: corev1.PullIfNotPresent,
						Args:            envoyArgs,
						Ports: []corev1.ContainerPort{
							{Name: httpPortName, ContainerPort: int32(*c.Listener.Port), Protocol: corev1.ProtocolTCP},
							{Name: "admin", ContainerPort: envoyAdminPort, Protocol: corev1.ProtocolTCP},
						},
						ReadinessProbe: &corev1.Probe{
							ProbeHandler:     corev1.ProbeHandler{TCPSocket: &corev1.TCPSocketAction{Port: intstr.FromString(httpPortName)}},
							PeriodSeconds:    5,
							FailureThreshold: 12,
						},
						Lifecycle: &corev1.Lifecycle{
							PreStop: &corev1.LifecycleHandler{
								Exec: &corev1.ExecAction{Command: []string{"/bin/sh", "-c", preStopDrainCommand}},
							},
						},
						Resources: gatewayResources,
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: new(false),
							ReadOnlyRootFilesystem:   new(true),
							RunAsNonRoot:             new(true),
							RunAsUser:                new(int64(101)),
							RunAsGroup:               new(int64(101)),
							Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
						},
						VolumeMounts: []corev1.VolumeMount{{
							Name:      gatewayConfigVolumeName,
							MountPath: configDirectory,
							ReadOnly:  true,
						}},
					}},
					Volumes: []corev1.Volume{{
						Name: gatewayConfigVolumeName,
						VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{Name: configName},
							Items:                configMapItems(configFiles),
						}},
					}},
				},
			},
		},
	}
	addCollectorContainer(&deployment, c.Config, metricsName, collectorResources)
	addAPIKeySecretVolume(&deployment, c)
	addServerTLSVolumes(&deployment, c.Config)
	addTrustedCAVolumes(&deployment, c)
	return deployment, nil
}

func addCollectorContainer(deployment *appsv1.Deployment, c Config, metricsName string, resources corev1.ResourceRequirements) {
	metricsEnabled := c.Observability.Metrics.enabled()
	tracingEnabled := c.Observability.Tracing.enabled()
	if !metricsEnabled && !tracingEnabled {
		return
	}
	collectorPorts := make([]corev1.ContainerPort, 0, 2)
	if metricsEnabled {
		collectorPorts = append(collectorPorts, corev1.ContainerPort{
			Name: metricsPortName, ContainerPort: defaultOTelMetricsPort, Protocol: corev1.ProtocolTCP,
		})
	}
	if tracingEnabled {
		collectorPorts = append(collectorPorts, corev1.ContainerPort{
			Name: tracesPortName, ContainerPort: defaultOTelTracePort, Protocol: corev1.ProtocolTCP,
		})
	}
	k := c.Kubernetes
	deployment.Spec.Template.Spec.Containers = append(deployment.Spec.Template.Spec.Containers, corev1.Container{
		Name:            metricsPortName,
		Image:           k.OTelCollectorImage,
		ImagePullPolicy: corev1.PullIfNotPresent,
		Args:            []string{"--config=" + path.Join(collectorConfigDirectory, collectorConfigFilename)},
		Ports:           collectorPorts,
		Resources:       resources,
		SecurityContext: &corev1.SecurityContext{
			AllowPrivilegeEscalation: new(false),
			ReadOnlyRootFilesystem:   new(true),
			RunAsNonRoot:             new(true),
			Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		},
		VolumeMounts: []corev1.VolumeMount{{
			Name:      metricsConfigVolumeName,
			MountPath: collectorConfigDirectory,
			ReadOnly:  true,
		}},
	})
	deployment.Spec.Template.Spec.Volumes = append(deployment.Spec.Template.Spec.Volumes, corev1.Volume{
		Name: metricsConfigVolumeName,
		VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
			LocalObjectReference: corev1.LocalObjectReference{Name: metricsName},
		}},
	})
}

func addAPIKeySecretVolume(deployment *appsv1.Deployment, c effectiveConfig) {
	authenticator, exists := c.apiKeyAuthenticator()
	if !exists || !c.usesAPIKeys() {
		return
	}
	deployment.Spec.Template.Spec.Volumes = append(deployment.Spec.Template.Spec.Volumes, corev1.Volume{
		Name: apiKeySecretVolumeName,
		VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{
			SecretName: authenticator.APIKey.Secret,
			Items:      []corev1.KeyToPath{{Key: apiKeySecretFilename, Path: apiKeySecretFilename}},
		}},
	})
	envoy := &deployment.Spec.Template.Spec.Containers[0]
	envoy.VolumeMounts = append(envoy.VolumeMounts, corev1.VolumeMount{
		Name: apiKeySecretVolumeName, MountPath: apiKeyDirectory, ReadOnly: true,
	})
}

func addServerTLSVolumes(deployment *appsv1.Deployment, c Config) {
	for _, mount := range c.tlsMounts() {
		tlsConfig := mount.config
		certificateFilename := path.Base(tlsConfig.Certificate)
		privateKeyFilename := path.Base(tlsConfig.PrivateKey)
		volumeName := fmt.Sprintf("server-tls-%d", mount.serverIndex)
		defaultMode := int32(0o444)
		deployment.Spec.Template.Spec.Volumes = append(deployment.Spec.Template.Spec.Volumes, corev1.Volume{
			Name: volumeName,
			VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{
				SecretName:  tlsConfig.Secret,
				DefaultMode: &defaultMode,
				Items: []corev1.KeyToPath{
					{Key: tlsCertificateSecretKey, Path: certificateFilename},
					{Key: tlsPrivateKeySecretKey, Path: privateKeyFilename},
				},
			}},
		})
		envoy := &deployment.Spec.Template.Spec.Containers[0]
		envoy.VolumeMounts = append(envoy.VolumeMounts, corev1.VolumeMount{
			Name: volumeName, MountPath: path.Dir(tlsConfig.Certificate), ReadOnly: true,
		})
	}
}

func addTrustedCAVolumes(deployment *appsv1.Deployment, c effectiveConfig) {
	for _, ref := range c.caMounts() {
		volumeName := "ca-" + ref.id()
		deployment.Spec.Template.Spec.Volumes = append(deployment.Spec.Template.Spec.Volumes, corev1.Volume{
			Name: volumeName,
			VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: ref.Name},
				DefaultMode:          new(int32(0o444)),
				Items:                []corev1.KeyToPath{{Key: ref.Key, Path: caCertificateFilename}},
			}},
		})
		envoy := &deployment.Spec.Template.Spec.Containers[0]
		envoy.VolumeMounts = append(envoy.VolumeMounts, corev1.VolumeMount{
			Name: volumeName, MountPath: path.Join(caDirectory, ref.id()), ReadOnly: true,
		})
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
