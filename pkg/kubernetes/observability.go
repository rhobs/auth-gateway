package kubernetes

import (
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	configuration "github.com/rhobs/auth-gateway/pkg/config"
	otel "github.com/rhobs/auth-gateway/pkg/otel"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func newOTelCollectorConfigMap(c gatewayapi.Config, name string) (*corev1.ConfigMap, error) {
	if !configuration.EnabledObservabilityMetrics(c.Observability.Metrics) && !configuration.EnabledObservabilityTracing(c.Observability.Tracing) {
		return nil, nil
	}
	otelConfig, err := otel.Generate(c)
	if err != nil {
		return nil, err
	}
	return &corev1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: configuration.KubernetesConfigMapKind},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: c.Kubernetes.Namespace},
		Data:       map[string]string{configuration.CollectorConfigFilename: string(otelConfig)},
	}, nil
}
