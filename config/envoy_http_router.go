package config

import (
	router "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
)

const routerFilterName = "envoy.filters.http.router"

func routerHTTPFilter() (*hcm.HttpFilter, error) {
	config, err := packEnvoy(&router.Router{})
	if err != nil {
		return nil, err
	}
	return &hcm.HttpFilter{Name: routerFilterName, ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: config}}, nil
}
