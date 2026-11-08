package config

import (
	xdscore "github.com/cncf/xds/go/xds/core/v3"
	networkinput "github.com/envoyproxy/go-control-plane/envoy/extensions/matching/common_inputs/network/v3"
)

func filterStateMatcherInput(key string) (*xdscore.TypedExtensionConfig, error) {
	config, err := packEnvoy(&networkinput.FilterStateInput{Key: key})
	if err != nil {
		return nil, err
	}
	return &xdscore.TypedExtensionConfig{Name: "envoy.matching.inputs.filter_state", TypedConfig: config}, nil
}
