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

const kubernetesConfigMapKind = "ConfigMap"

const (
	httpPortName               = "http"
	httpsPortName              = "https"
	gatewayConfigVolumeName    = "config"
	processingConfigVolumeName = "processing-config"
	apiKeySecretVolumeName     = "api-keys"
)

const (
	configDirectory     = EnvoyConfigDirectory
	processingDirectory = ProcessingConfigDirectory
	apiKeyDirectory     = APIKeyConfigDirectory
)

func processingResourceName(name string) string {
	return resourceNameWithSuffix(name, "-processing")
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
	configFiles := files
	var processingConfigMap *corev1.ConfigMap
	if processingData, ok := files[processingConfigFilename]; ok {
		configFiles = make(map[string][]byte, len(files)-1)
		for name, contents := range files {
			if name != processingConfigFilename {
				configFiles[name] = contents
			}
		}
		processingConfigMap = &corev1.ConfigMap{
			TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: kubernetesConfigMapKind},
			ObjectMeta: metav1.ObjectMeta{
				Name:      processingResourceName(c.Kubernetes.Name),
				Namespace: c.Kubernetes.Namespace,
			},
			Data: map[string]string{processingConfigFilename: string(processingData)},
		}
	}
	metricsEnabled := c.Observability.Metrics.enabled()
	tracingEnabled := c.Observability.Tracing.enabled()
	collectorEnabled := metricsEnabled || tracingEnabled

	k := c.Kubernetes
	envoyArgs := []string{"-c", EnvoyBootstrapPath, "--log-level", "info"}
	if k.EnvoyConcurrency != nil {
		envoyArgs = append(envoyArgs, "--concurrency", strconv.FormatUint(uint64(*k.EnvoyConcurrency), 10))
	}
	configName := k.Name + "-config"
	metricsName := metricsResourceName(k.Name)
	labels := func() map[string]string {
		return map[string]string{
			"app.kubernetes.io/name":     "auth-gateway",
			"app.kubernetes.io/instance": c.Node.Cluster,
		}
	}
	configMap := corev1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: kubernetesConfigMapKind},
		ObjectMeta: metav1.ObjectMeta{Name: configName, Namespace: k.Namespace},
		Data:       stringFiles(configFiles),
	}
	var otelConfigMap *corev1.ConfigMap
	if collectorEnabled {
		otelConfig := generateOTelCollectorConfig(c.Observability.Metrics, c.Observability.Tracing)
		otelConfigMap = &corev1.ConfigMap{
			TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: kubernetesConfigMapKind},
			ObjectMeta: metav1.ObjectMeta{Name: metricsName, Namespace: k.Namespace},
			Data:       map[string]string{collectorConfigFilename: string(otelConfig)},
		}
	}
	serviceAccount := corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "ServiceAccount"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      k.Name,
			Namespace: k.Namespace,
			Labels:    labels(),
		},
		AutomountServiceAccountToken: new(false),
	}

	deployment := appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      k.Name,
			Namespace: k.Namespace,
			Labels:    labels(),
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: k.Replicas,
			Selector: &metav1.LabelSelector{MatchLabels: labels()},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels(),
				},
				Spec: corev1.PodSpec{
					ServiceAccountName:            k.Name,
					AutomountServiceAccountToken:  new(false),
					TerminationGracePeriodSeconds: new(int64(30)),
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
						Resources: corev1.ResourceRequirements{
							Requests: kubernetesResourceList(k.Resources.Requests),
							Limits:   kubernetesResourceList(k.Resources.Limits),
						},
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
	if collectorEnabled {
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
		deployment.Spec.Template.Spec.Containers = append(deployment.Spec.Template.Spec.Containers, corev1.Container{
			Name:            metricsPortName,
			Image:           k.OTelCollectorImage,
			ImagePullPolicy: corev1.PullIfNotPresent,
			Args:            []string{"--config=" + path.Join(collectorConfigDirectory, collectorConfigFilename)},
			Ports:           collectorPorts,
			Resources: corev1.ResourceRequirements{
				Requests: kubernetesResourceList(k.Metrics.Resources.Requests),
				Limits:   kubernetesResourceList(k.Metrics.Resources.Limits),
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
	if processingConfigMap != nil {
		deployment.Spec.Template.Spec.Volumes = append(deployment.Spec.Template.Spec.Volumes, corev1.Volume{
			Name: processingConfigVolumeName,
			VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: processingConfigMap.Name},
				Items:                []corev1.KeyToPath{{Key: processingConfigFilename, Path: processingConfigFilename}},
			}},
		})
		envoy := &deployment.Spec.Template.Spec.Containers[0]
		envoy.VolumeMounts = append(envoy.VolumeMounts, corev1.VolumeMount{
			Name:      "processing-config",
			MountPath: processingDirectory,
			ReadOnly:  true,
		})
	}
	if authenticator, exists := c.apiKeyAuthenticator(); exists && c.usesAPIKeys() {
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
			Name:      volumeName,
			MountPath: path.Dir(tlsConfig.Certificate),
			ReadOnly:  true,
		})
	}
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
	servicePorts := make([]corev1.ServicePort, 0, 3)
	if c.hasHTTP() {
		servicePorts = append(servicePorts, corev1.ServicePort{
			Name:       httpPortName,
			Port:       *k.ServicePort,
			TargetPort: intstr.FromString(httpPortName),
			Protocol:   corev1.ProtocolTCP,
		})
	}
	if c.hasHTTPS() {
		servicePorts = append(servicePorts, corev1.ServicePort{
			Name:       httpsPortName,
			Port:       *k.HTTPSServicePort,
			TargetPort: intstr.FromString(httpPortName),
			Protocol:   corev1.ProtocolTCP,
		})
	}
	if metricsEnabled {
		servicePorts = append(servicePorts, corev1.ServicePort{
			Name:       metricsPortName,
			Port:       defaultOTelMetricsPort,
			TargetPort: intstr.FromString(metricsPortName),
			Protocol:   corev1.ProtocolTCP,
		})
	}
	service := corev1.Service{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Service"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      k.Name,
			Namespace: k.Namespace,
			Labels:    labels(),
		},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeClusterIP,
			Selector: labels(),
			Ports:    servicePorts,
		},
	}

	return &KubernetesResources{
		ConfigMap:              configMap,
		ProcessingConfigMap:    processingConfigMap,
		OTelCollectorConfigMap: otelConfigMap,
		ServiceAccount:         serviceAccount,
		Deployment:             deployment,
		Service:                service,
	}, nil
}

// Objects returns the resources in apply order.
func (r *KubernetesResources) Objects() []runtime.Object {
	objects := []runtime.Object{&r.ConfigMap}
	if r.ProcessingConfigMap != nil {
		objects = append(objects, r.ProcessingConfigMap)
	}
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

func kubernetesResourceList(values map[string]string) corev1.ResourceList {
	if values == nil {
		return nil
	}
	resources := make(corev1.ResourceList, len(values))
	for name, value := range values {
		resources[corev1.ResourceName(name)] = resource.MustParse(value)
	}
	return resources
}

func validateKubernetesResourceRequirements(prefix string, requirements KubernetesResourceRequirements) error {
	for _, list := range []struct {
		name   string
		values map[string]string
	}{
		{name: "requests", values: requirements.Requests},
		{name: "limits", values: requirements.Limits},
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
		}
	}
	for _, name := range slices.Sorted(maps.Keys(requirements.Requests)) {
		if limit, ok := requirements.Limits[name]; ok {
			request := resource.MustParse(requirements.Requests[name])
			if request.Cmp(resource.MustParse(limit)) > 0 {
				return fmt.Errorf("%s.requests.%s must not exceed %s.limits.%s", prefix, name, prefix, name)
			}
		}
	}
	return nil
}
