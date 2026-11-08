package config

import (
	"fmt"

	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	inspector "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/tls_inspector/v3"
)

const tlsInspectorFilterName = "envoy.filters.listener.tls_inspector"

func generateListenerFilters(c effectiveConfig) ([]*listener.ListenerFilter, error) {
	if !c.hasHTTPS() {
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
