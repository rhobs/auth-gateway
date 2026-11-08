package config

import (
	"path"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
)

const (
	mtlsMetadataNamespace      = "auth_gateway.mtls"
	mtlsFingerprintMetadataKey = "fingerprint"
	mtlsURIMetadataKey         = "uri_san"
	mtlsDNSMetadataKey         = "dns_san"
	mtlsFingerprintHeaderName  = "x-auth-gateway-mtls-fingerprint"
	mtlsURIHeaderName          = "x-auth-gateway-mtls-uri-san"
	mtlsDNSHeaderName          = "x-auth-gateway-mtls-dns-san"
	mtlsPendingHeaderName      = "x-auth-gateway-mtls-authentication-pending"
	// Request-control and peer filters remove client values and overwrite this
	// header from TLS state. Keep the matcher below Envoy's RE2 size limit.
	mtlsFingerprintPattern = "^[0-9A-Fa-f:]+$"
)

// MTLSAuthenticator validates client certificates against an explicit CA bundle.
type MTLSAuthenticator struct {
	TrustedCA *TrustedCA `yaml:"trusted_ca"`
}

func requiresClientCertificate(server Server) bool {
	return server.Authentication.AllOf != nil || len(server.Authentication.AnyOf) == 1
}

func (m MTLSAuthenticator) clone() MTLSAuthenticator {
	m.TrustedCA = cloneConfigPointer(m.TrustedCA)
	return m
}

func (m MTLSAuthenticator) toEnvoySecret(index int) *tls.Secret {
	filename := m.TrustedCA.filename()
	return &tls.Secret{
		Name: clientCASecretName(index),
		Type: &tls.Secret_ValidationContext{ValidationContext: &tls.CertificateValidationContext{
			TrustedCa:        fileDataSource(filename),
			WatchedDirectory: &core.WatchedDirectory{Path: path.Dir(filename)},
		}},
	}
}
