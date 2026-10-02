package config

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"path"
	"sort"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kjson "k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	configDirectory          = "/etc/auth-gateway"
	collectorConfigDirectory = "/etc/collector"
	configChecksumAnnotation = "auth-gateway/config-sha256"
)

// KubernetesResources contains native objects generated for a gateway.
type KubernetesResources struct {
	ConfigMap              corev1.ConfigMap
	LuaConfigMap           *corev1.ConfigMap
	OTelCollectorConfigMap corev1.ConfigMap
	ServiceAccount         corev1.ServiceAccount
	Deployment             appsv1.Deployment
	Service                corev1.Service
}

// Objects returns the resources in apply order.
func (r *KubernetesResources) Objects() []runtime.Object {
	objects := []runtime.Object{&r.ConfigMap}
	if r.LuaConfigMap != nil {
		objects = append(objects, r.LuaConfigMap)
	}
	return append(objects, &r.OTelCollectorConfigMap, &r.ServiceAccount, &r.Deployment, &r.Service)
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

// GenerateKubernetes builds Kubernetes resources for Envoy and its metrics sidecar.
// It does not contact a cluster, read credentials, or write files.
func GenerateKubernetes(c Config) (*KubernetesResources, error) {
	c = c.withDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if c.Kubernetes == nil {
		return nil, fmt.Errorf("kubernetes settings are required")
	}
	files, err := Generate(c)
	if err != nil {
		return nil, err
	}
	configFiles, luaFiles := splitLuaFiles(files)
	otelConfig := generateOTelCollectorConfig()

	k := c.Kubernetes
	configName := k.Name + "-config"
	luaConfigName := k.Name + "-lua"
	metricsName := metricsResourceName(k.Name)
	labels := func() map[string]string {
		return map[string]string{
			"app.kubernetes.io/name":     "auth-gateway",
			"app.kubernetes.io/instance": c.Node.Cluster,
		}
	}
	configMap := corev1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"},
		ObjectMeta: metav1.ObjectMeta{Name: configName, Namespace: k.Namespace},
		Data:       stringFiles(configFiles),
	}
	var luaConfigMap *corev1.ConfigMap
	if len(luaFiles) > 0 {
		luaConfigMap = &corev1.ConfigMap{
			TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"},
			ObjectMeta: metav1.ObjectMeta{Name: luaConfigName, Namespace: k.Namespace},
			Data:       stringFiles(luaFiles),
		}
	}
	otelConfigMap := corev1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"},
		ObjectMeta: metav1.ObjectMeta{Name: metricsName, Namespace: k.Namespace},
		Data:       map[string]string{"config.yaml": string(otelConfig)},
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
					Labels:      labels(),
					Annotations: map[string]string{configChecksumAnnotation: configFilesChecksum(files)},
				},
				Spec: corev1.PodSpec{
					ServiceAccountName:            k.Name,
					AutomountServiceAccountToken:  new(false),
					TerminationGracePeriodSeconds: new(int64(30)),
					Containers: []corev1.Container{{
						Name:            "envoy",
						Image:           k.Image,
						ImagePullPolicy: corev1.PullIfNotPresent,
						Args: []string{
							"-c", path.Join(configDirectory, "envoy.yaml"),
							"--log-level", "info",
						},
						Ports: []corev1.ContainerPort{
							{Name: "http", ContainerPort: int32(c.Listener.Port), Protocol: corev1.ProtocolTCP},
							{Name: "admin", ContainerPort: envoyAdminPort, Protocol: corev1.ProtocolTCP},
						},
						ReadinessProbe: &corev1.Probe{
							ProbeHandler:     corev1.ProbeHandler{TCPSocket: &corev1.TCPSocketAction{Port: intstr.FromString("http")}},
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
							Name:      "config",
							MountPath: configDirectory,
							ReadOnly:  true,
						}},
					}, {
						Name:            "metrics",
						Image:           k.OTelCollectorImage,
						ImagePullPolicy: corev1.PullIfNotPresent,
						Args:            []string{"--config=" + path.Join(collectorConfigDirectory, "config.yaml")},
						Ports: []corev1.ContainerPort{{
							Name: "metrics", ContainerPort: defaultOTelMetricsPort, Protocol: corev1.ProtocolTCP,
						}},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("20m"),
								corev1.ResourceMemory: resource.MustParse("64Mi"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceMemory: resource.MustParse("256Mi"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{{
							Name:      "metrics-config",
							MountPath: collectorConfigDirectory,
							ReadOnly:  true,
						}},
					}},
					Volumes: []corev1.Volume{{
						Name: "config",
						VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{Name: configName},
							Items:                configMapItems(configFiles),
						}},
					}, {
						Name: "metrics-config",
						VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{Name: metricsName},
						}},
					}},
				},
			},
		},
	}
	if luaConfigMap != nil {
		deployment.Spec.Template.Spec.Volumes = append(deployment.Spec.Template.Spec.Volumes, corev1.Volume{
			Name: "lua-config",
			VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: luaConfigName},
				Items:                configMapItems(luaFiles),
			}},
		})
		envoy := &deployment.Spec.Template.Spec.Containers[0]
		envoy.VolumeMounts = append(envoy.VolumeMounts, corev1.VolumeMount{
			Name:      "lua-config",
			MountPath: path.Join(configDirectory, "lua"),
			ReadOnly:  true,
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
					{Key: "tls.crt", Path: certificateFilename},
					{Key: "tls.key", Path: privateKeyFilename},
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
	servicePorts := make([]corev1.ServicePort, 0, 3)
	if c.hasHTTP() {
		servicePorts = append(servicePorts, corev1.ServicePort{
			Name:       "http",
			Port:       k.ServicePort,
			TargetPort: intstr.FromString("http"),
			Protocol:   corev1.ProtocolTCP,
		})
	}
	if c.hasHTTPS() {
		servicePorts = append(servicePorts, corev1.ServicePort{
			Name:       "https",
			Port:       k.HTTPSServicePort,
			TargetPort: intstr.FromString("http"),
			Protocol:   corev1.ProtocolTCP,
		})
	}
	servicePorts = append(servicePorts, corev1.ServicePort{
		Name:       "metrics",
		Port:       defaultOTelMetricsPort,
		TargetPort: intstr.FromString("metrics"),
		Protocol:   corev1.ProtocolTCP,
	})
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
		LuaConfigMap:           luaConfigMap,
		OTelCollectorConfigMap: otelConfigMap,
		ServiceAccount:         serviceAccount,
		Deployment:             deployment,
		Service:                service,
	}, nil
}

func splitLuaFiles(files map[string][]byte) (map[string][]byte, map[string][]byte) {
	configFiles := make(map[string][]byte, len(files))
	luaFiles := make(map[string][]byte)
	for filename, contents := range files {
		if strings.HasPrefix(filename, "lua/") {
			luaFiles[path.Base(filename)] = contents
			continue
		}
		configFiles[filename] = contents
	}
	return configFiles, luaFiles
}

func configFilesChecksum(files map[string][]byte) string {
	hash := sha256.New()
	for _, filename := range sortedFileNames(files) {
		hash.Write([]byte(filename))
		hash.Write([]byte{0})
		hash.Write(files[filename])
		hash.Write([]byte{0})
	}
	return fmt.Sprintf("%x", hash.Sum(nil))
}

func sortedFileNames(files map[string][]byte) []string {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
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
	for _, name := range sortedFileNames(files) {
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
