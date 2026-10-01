package config

import (
	"bytes"
	"fmt"
	"path"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kjson "k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const configDirectory = "/etc/auth-gateway"

// KubernetesResources contains native objects generated for a gateway.
type KubernetesResources struct {
	ConfigMap      corev1.ConfigMap
	ServiceAccount corev1.ServiceAccount
	Deployment     appsv1.Deployment
	Service        corev1.Service
}

// Objects returns the resources in apply order.
func (r *KubernetesResources) Objects() []runtime.Object {
	return []runtime.Object{&r.ConfigMap, &r.ServiceAccount, &r.Deployment, &r.Service}
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

// GenerateKubernetes builds a Deployment, Service, ServiceAccount, and ConfigMap.
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

	k := c.Kubernetes
	configName := k.Name + "-config"
	labels := func() map[string]string {
		return map[string]string{
			"app.kubernetes.io/name":     "auth-gateway",
			"app.kubernetes.io/instance": c.Node.Cluster,
		}
	}
	configMap := corev1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"},
		ObjectMeta: metav1.ObjectMeta{Name: configName, Namespace: k.Namespace},
		Data:       map[string]string{"envoy.yaml": string(files["envoy.yaml"])},
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
				ObjectMeta: metav1.ObjectMeta{Labels: labels()},
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
							"--disable-hot-restart", // Kubernetes handles Pod lifecycle.
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
					}},
					Volumes: []corev1.Volume{{
						Name: "config",
						VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{Name: configName},
							Items:                []corev1.KeyToPath{{Key: "envoy.yaml", Path: "envoy.yaml"}},
						}},
					}},
				},
			},
		},
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
			Ports: []corev1.ServicePort{{
				Name:       "http",
				Port:       k.ServicePort,
				TargetPort: intstr.FromString("http"),
				Protocol:   corev1.ProtocolTCP,
			}},
		},
	}

	return &KubernetesResources{
		ConfigMap:      configMap,
		ServiceAccount: serviceAccount,
		Deployment:     deployment,
		Service:        service,
	}, nil
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
