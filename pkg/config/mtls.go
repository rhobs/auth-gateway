package config

import (
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
)

const (
	MtlsMetadataNamespace      = "auth_gateway.mtls"
	MtlsFingerprintMetadataKey = "fingerprint"
	MtlsURIMetadataKey         = "uri_san"
	MtlsDNSMetadataKey         = "dns_san"
	MtlsFingerprintHeaderName  = "x-auth-gateway-mtls-fingerprint"
	MtlsURIHeaderName          = "x-auth-gateway-mtls-uri-san"
	MtlsDNSHeaderName          = "x-auth-gateway-mtls-dns-san"
	MtlsPendingHeaderName      = "x-auth-gateway-mtls-authentication-pending"
	// Request-control and peer filters remove client values and overwrite this
	// header from TLS state. Keep the matcher below Envoy's RE2 size limit.
	MtlsFingerprintPattern = "^[0-9A-Fa-f:]+$"
)

func RequiresClientCertificate(server gatewayapi.Server) bool {
	return server.Authentication.AllOf != nil || len(server.Authentication.AnyOf) == 1
}

func cloneMTLSAuthenticator(m gatewayapi.MTLSAuthenticator) gatewayapi.MTLSAuthenticator {
	m.TrustedCA = cloneConfigPointer(m.TrustedCA, cloneTrustedCA)
	return m
}
