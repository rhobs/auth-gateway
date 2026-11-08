package config

import (
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	rbac "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	mtlsauthenticated "github.com/envoyproxy/go-control-plane/envoy/extensions/rbac/principals/mtls_authenticated/v3"
)

const mtlsPrincipalName = "envoy.rbac.principals.mtls_authenticated"

func mtlsValidatedPrincipal() (*rbac.Principal, error) {
	packed, err := packEnvoy(&mtlsauthenticated.Config{AnyValidatedClientCertificate: true})
	if err != nil {
		return nil, err
	}
	return &rbac.Principal{Identifier: &rbac.Principal_Custom{Custom: &core.TypedExtensionConfig{
		Name: mtlsPrincipalName, TypedConfig: packed,
	}}}, nil
}
