package envoy

import (
	"fmt"
	"path"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	configuration "github.com/rhobs/auth-gateway/pkg/config"
	yaml "go.yaml.in/yaml/v3"
	"google.golang.org/protobuf/proto"
)

func fileConfigSource(filename string) *core.ConfigSource {
	return &core.ConfigSource{
		ResourceApiVersion: core.ApiVersion_V3,
		ConfigSourceSpecifier: &core.ConfigSource_PathConfigSource{PathConfigSource: &core.PathConfigSource{
			Path:             filename,
			WatchedDirectory: &core.WatchedDirectory{Path: path.Dir(filename)},
		}},
	}
}

func fileDataSource(filename string) *core.DataSource {
	return &core.DataSource{Specifier: &core.DataSource_Filename{Filename: filename}}
}

func marshalEnvoyFileDiscoveryResponse(resource proto.Message) ([]byte, error) {
	packed, err := packEnvoy(resource)
	if err != nil {
		return nil, err
	}
	resourceData, err := marshalEnvoyYAML(packed)
	if err != nil {
		return nil, err
	}
	var document any
	if err := yaml.Unmarshal(resourceData, &document); err != nil {
		return nil, fmt.Errorf("decode packed discovery resource: %w", err)
	}
	data, err := yaml.Marshal(map[string]any{configuration.EnvoyResourcesFieldName: []any{document}})
	if err != nil {
		return nil, fmt.Errorf("encode file discovery response: %w", err)
	}
	return data, nil
}
