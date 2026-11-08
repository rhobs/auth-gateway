package envoy

import (
	"fmt"

	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	inspector "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/tls_inspector/v3"
	configuration "github.com/rhobs/auth-gateway/pkg/config"
)

const tlsInspectorFilterName = "envoy.filters.listener.tls_inspector"

func generateListenerFilters(c configuration.ResolvedConfig) ([]*listener.ListenerFilter, error) {
	if !configuration.HasHTTPSConfig(c.Config) {
		return nil, nil
	}
	inspectorConfig, err := packEnvoy(&inspector.TlsInspector{})
	if err != nil {
		return nil, fmt.Errorf("encode TLS inspector: %w", err)
	}
	return []*listener.ListenerFilter{{
		Name:       tlsInspectorFilterName,
		ConfigType: &listener.ListenerFilter_TypedConfig{TypedConfig: inspectorConfig},
	}}, nil
}
