package envoy

// GeneratedFile contains the bytes for one Envoy resource and the absolute path
// at which Envoy expects that resource to be available.
type GeneratedFile struct {
	// Path is the absolute location Envoy expects this resource to use.
	Path string
	// Contents is the serialized Envoy resource.
	Contents []byte
}

// GeneratedFiles names the files returned by Generate. ServerCertificateResources
// contains one SDS resource per HTTPS server. ClientCAResources contains one
// validation-context SDS resource per server selecting mTLS.
type GeneratedFiles struct {
	// EnvoyBootstrap is always present when Generate succeeds.
	EnvoyBootstrap GeneratedFile
	// ServerCertificateResources contains one SDS resource for each HTTPS server.
	ServerCertificateResources []GeneratedFile
	// ClientCAResources contains one SDS resource for each mTLS server.
	ClientCAResources []GeneratedFile
}

// All returns the generated files in bootstrap, server, and client CA order.
func (files GeneratedFiles) All() []GeneratedFile {
	result := make([]GeneratedFile, 0, 1+len(files.ServerCertificateResources)+len(files.ClientCAResources))
	if files.EnvoyBootstrap.Path != "" {
		result = append(result, files.EnvoyBootstrap)
	}
	result = append(result, files.ServerCertificateResources...)
	result = append(result, files.ClientCAResources...)
	return result
}
