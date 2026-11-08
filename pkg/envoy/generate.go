package envoy

import (
	"fmt"
	"path"

	bootstrap "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	configuration "github.com/rhobs/auth-gateway/pkg/config"
)

// Generate builds Envoy files from the high-level gateway configuration. Each
// returned file includes its absolute path and contents.
func Generate(c gatewayapi.Config) (GeneratedFiles, error) {
	effective, err := configuration.ResolveConfig(c)
	if err != nil {
		return GeneratedFiles{}, err
	}
	contents, err := generate(effective)
	if err != nil {
		return GeneratedFiles{}, err
	}

	files := GeneratedFiles{
		EnvoyBootstrap: GeneratedFile{
			Path:     configuration.EnvoyBootstrapPath,
			Contents: contents[configuration.EnvoyConfigFilename],
		},
	}
	for index, server := range effective.ResolvedServers {
		if server.TLSConfig == nil {
			continue
		}
		filename := configuration.ServerTLSResourceFilename(index)
		files.ServerCertificateResources = append(files.ServerCertificateResources, GeneratedFile{
			Path:     path.Join(configuration.EnvoyConfigDirectory, filename),
			Contents: contents[filename],
		})
		if server.UsesMTLS() {
			caFilename := configuration.ClientCAResourceFilename(index)
			files.ClientCAResources = append(files.ClientCAResources, GeneratedFile{
				Path:     path.Join(configuration.EnvoyConfigDirectory, caFilename),
				Contents: contents[caFilename],
			})
		}
	}
	return files, nil
}

func generate(effective configuration.ResolvedConfig) (map[string][]byte, error) {
	bootstrapConfig, err := generateBootstrap(effective)
	if err != nil {
		return nil, err
	}
	return generateFiles(effective, bootstrapConfig)
}

func generateFiles(c configuration.ResolvedConfig, bootstrapConfig *bootstrap.Bootstrap) (map[string][]byte, error) {
	data, err := marshalEnvoyYAML(bootstrapConfig)
	if err != nil {
		return nil, fmt.Errorf("encode Envoy bootstrap: %w", err)
	}
	files := map[string][]byte{configuration.EnvoyConfigFilename: append([]byte(configuration.GeneratedFileHeader), data...)}
	if err := addServerCertificateFiles(c, files); err != nil {
		return nil, err
	}
	if err := addClientCAFiles(c, files); err != nil {
		return nil, err
	}
	return files, nil
}

func addServerCertificateFiles(c configuration.ResolvedConfig, files map[string][]byte) error {
	for i, server := range c.ResolvedServers {
		if server.TLSConfig == nil {
			continue
		}
		data, err := marshalEnvoyFileDiscoveryResponse(serverTLSSecret(*server.TLSConfig, i))
		if err != nil {
			return fmt.Errorf("servers[%d] certificate SDS resource: %w", i, err)
		}
		files[configuration.ServerTLSResourceFilename(i)] = append([]byte(configuration.GeneratedFileHeader), data...)
	}
	return nil
}

func addClientCAFiles(c configuration.ResolvedConfig, files map[string][]byte) error {
	for index, server := range c.ResolvedServers {
		if !server.UsesMTLS() {
			continue
		}
		data, err := marshalEnvoyFileDiscoveryResponse(clientCASecret(*server.Mtls.MTLS, index))
		if err != nil {
			return fmt.Errorf("servers[%d] client CA SDS resource: %w", index, err)
		}
		files[configuration.ClientCAResourceFilename(index)] = append([]byte(configuration.GeneratedFileHeader), data...)
	}
	return nil
}
