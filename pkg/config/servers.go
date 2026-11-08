package config

import (
	"fmt"
	"path"
	"slices"
	"strings"

	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
)

const (
	DefaultServerTLSCertificate = "/etc/auth-gateway-tls/tls.crt"
	DefaultServerTLSPrivateKey  = "/etc/auth-gateway-tls/tls.key"
	ServerFieldPathFormat       = "servers[%d]"
	TlsCertificateSecretKey     = "tls.crt"
	TlsPrivateKeySecretKey      = "tls.key"
	ServerTLSSecretDirectory    = "/etc"
)

type ServerTLSMount struct {
	ServerIndex int
	Config      gatewayapi.ServerTLS
}

func withDefaultsServerTLS(s gatewayapi.ServerTLS) gatewayapi.ServerTLS {
	certificate, privateKey := DefaultServerTLSCertificate, DefaultServerTLSPrivateKey
	if s.Secret != "" {
		certificate = path.Join(ServerTLSSecretDirectory, s.Secret, TlsCertificateSecretKey)
		privateKey = path.Join(ServerTLSSecretDirectory, s.Secret, TlsPrivateKeySecretKey)
	}
	if s.Certificate == "" {
		s.Certificate = certificate
	}
	if s.PrivateKey == "" {
		s.PrivateKey = privateKey
	}
	return s
}

func boundAPIsServer(s gatewayapi.Server, apis map[string]gatewayapi.API) ([]gatewayapi.API, error) {
	bound := make([]gatewayapi.API, 0, len(s.APIs))
	seen := make(map[string]struct{}, len(s.APIs))
	for _, name := range s.APIs {
		api, ok := apis[name]
		if !ok {
			return nil, fmt.Errorf("unknown API %q", name)
		}
		if _, exists := seen[name]; exists {
			return nil, fmt.Errorf("duplicate API binding %q", name)
		}
		seen[name] = struct{}{}
		bound = append(bound, api)
	}
	return bound, nil
}

func validateServerTLS(name string, serverTLS gatewayapi.ServerTLS) error {
	for _, file := range []struct {
		Name  string
		Value string
	}{
		{Name: "certificate", Value: serverTLS.Certificate},
		{Name: "private_key", Value: serverTLS.PrivateKey},
	} {
		if !path.IsAbs(file.Value) || path.Clean(file.Value) != file.Value || file.Value == "/" || strings.ContainsAny(file.Value, InvalidControlCharacters) {
			return fmt.Errorf("%s.%s must be a clean absolute file path", name, file.Name)
		}
	}
	if path.Dir(serverTLS.Certificate) != path.Dir(serverTLS.PrivateKey) {
		return fmt.Errorf("%s.certificate and %s.private_key must be in the same directory", name, name)
	}
	if path.Base(serverTLS.Certificate) == path.Base(serverTLS.PrivateKey) {
		return fmt.Errorf("%s.certificate and %s.private_key must have different file names", name, name)
	}
	return nil
}

func directoriesOverlap(a, b string) bool {
	return a == b || a == "/" || b == "/" ||
		strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

func cloneServer(s gatewayapi.Server) gatewayapi.Server {
	s.TLSConfig = cloneConfigPointer(s.TLSConfig, cloneServerTLS)
	s.Authentication = cloneConfigPointer(s.Authentication, cloneAuthentication)
	s.Authorization = cloneConfigPointer(s.Authorization, cloneAuthorization)
	s.APIs = slices.Clone(s.APIs)
	return s
}

func cloneServerTLS(s gatewayapi.ServerTLS) gatewayapi.ServerTLS {
	return s
}
