package config

// The Envoy file layout is fixed by paths embedded in the generated bootstrap.
const (
	// EnvoyConfigDirectory is `/etc/auth-gateway`, containing the bootstrap and server TLS resources.
	EnvoyConfigDirectory = "/etc/auth-gateway"
	// ProcessingConfigDirectory is `/etc/auth-gateway/processing`, watched for mapped attributes.
	ProcessingConfigDirectory = EnvoyConfigDirectory + "/processing"
	// APIKeyConfigDirectory is `/etc/auth-gateway/api-keys`, watched for API-key credentials.
	APIKeyConfigDirectory = EnvoyConfigDirectory + "/api-keys"
	// TrustedCADirectory is `/etc/auth-gateway-ca`, the root for CA ConfigMap files.
	TrustedCADirectory = "/etc/auth-gateway-ca"

	// EnvoyBootstrapPath is `/etc/auth-gateway/envoy.yaml`, the generated Envoy bootstrap path.
	EnvoyBootstrapPath = EnvoyConfigDirectory + "/" + envoyConfigFilename
	// ProcessingConfigPath is `/etc/auth-gateway/processing/processing.yaml`, the optional processing resource path.
	ProcessingConfigPath = ProcessingConfigDirectory + "/" + processingConfigFilename
	// APIKeyECDSPath is `/etc/auth-gateway/api-keys/api-keys.yaml`, the API-key ECDS resource path.
	APIKeyECDSPath = APIKeyConfigDirectory + "/" + apiKeySecretFilename
)

// GeneratedFile contains the bytes for one Envoy resource and the absolute path
// at which Envoy expects that resource to be available.
type GeneratedFile struct {
	// Path is the absolute location Envoy expects this resource to use.
	Path string
	// Contents is the serialized Envoy resource.
	Contents []byte
}

// GeneratedFiles names the files returned by Generate. ProcessingConfig is nil
// when the configuration has no attribute mappings. ServerCertificateResources
// contains one SDS resource per HTTPS server. ClientCAResources contains one
// validation-context SDS resource per server selecting mTLS.
type GeneratedFiles struct {
	// EnvoyBootstrap is always present when Generate succeeds.
	EnvoyBootstrap GeneratedFile
	// ProcessingConfig is present when attribute mappings are configured.
	ProcessingConfig *GeneratedFile
	// ServerCertificateResources contains one SDS resource for each HTTPS server.
	ServerCertificateResources []GeneratedFile
	// ClientCAResources contains one SDS resource for each mTLS server.
	ClientCAResources []GeneratedFile
}

// All returns the generated files in bootstrap, processing, server, and client CA order.
func (files GeneratedFiles) All() []GeneratedFile {
	result := make([]GeneratedFile, 0, 2+len(files.ServerCertificateResources)+len(files.ClientCAResources))
	if files.EnvoyBootstrap.Path != "" {
		result = append(result, files.EnvoyBootstrap)
	}
	if files.ProcessingConfig != nil {
		result = append(result, *files.ProcessingConfig)
	}
	result = append(result, files.ServerCertificateResources...)
	result = append(result, files.ClientCAResources...)
	return result
}
