package config

import (
	"fmt"
	"path"
	"strconv"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

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
