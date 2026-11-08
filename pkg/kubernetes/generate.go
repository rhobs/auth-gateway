package kubernetes

import (
	"fmt"
	"path"

	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	configuration "github.com/rhobs/auth-gateway/pkg/config"
	envoyimpl "github.com/rhobs/auth-gateway/pkg/envoy"
)

// GenerateKubernetes builds Kubernetes resources for Envoy and optional observability collection.
// It does not contact a cluster, read credentials, or write files.
func Generate(c gatewayapi.Config) (*Resources, error) {
	effective, err := configuration.ResolveConfig(c)
	if err != nil {
		return nil, err
	}
	c = effective.Config
	if c.Kubernetes == nil {
		return nil, fmt.Errorf("kubernetes settings are required")
	}
	generated, err := envoyimpl.Generate(c)
	if err != nil {
		return nil, err
	}
	files := make(map[string][]byte)
	for _, file := range generated.All() {
		files[path.Base(file.Path)] = file.Contents
	}
	configName := c.Kubernetes.Name + "-config"
	metricsName := configuration.MetricsResourceName(c.Kubernetes.Name)
	metricsEnabled := configuration.EnabledObservabilityMetrics(c.Observability.Metrics)
	collectorConfigMap, err := newOTelCollectorConfigMap(c, metricsName)
	if err != nil {
		return nil, err
	}
	deployment, err := newGatewayDeployment(effective, files, configName, metricsName)
	if err != nil {
		return nil, err
	}
	return &Resources{
		ConfigMap:              newGatewayConfigMap(c, configName, files),
		OTelCollectorConfigMap: collectorConfigMap,
		ServiceAccount:         newGatewayServiceAccount(c),
		Deployment:             deployment,
		Service:                newGatewayService(c, metricsEnabled),
	}, nil
}
