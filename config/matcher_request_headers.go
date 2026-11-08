package config

import (
	xdscore "github.com/cncf/xds/go/xds/core/v3"
	matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
)

func requestHeaderMatcherInput(header string) (*xdscore.TypedExtensionConfig, error) {
	config, err := packEnvoy(&matcher.HttpRequestHeaderMatchInput{HeaderName: header})
	if err != nil {
		return nil, err
	}
	return &xdscore.TypedExtensionConfig{Name: "envoy.matching.inputs.request_headers", TypedConfig: config}, nil
}
