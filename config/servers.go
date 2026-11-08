package config

import (
	"fmt"
	"path"
	"slices"
	"strings"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
)

const (
	defaultServerTLSCertificate = "/etc/auth-gateway-tls/tls.crt"
	defaultServerTLSPrivateKey  = "/etc/auth-gateway-tls/tls.key"
	serverFieldPathFormat       = "servers[%d]"
	tlsCertificateSecretKey     = "tls.crt"
	tlsPrivateKeySecretKey      = "tls.key"
	serverTLSSecretDirectory    = "/etc"
)

type serverTLSMount struct {
	serverIndex int
	config      ServerTLS
}

// Server binds an exact hostname and protocol to named APIs and optional access policies.
type Server struct {
	Hostname       string          `yaml:"hostname"`
	TLSConfig      *ServerTLS      `yaml:"tls_config,omitempty"`
	Authentication *Authentication `yaml:"authentication,omitempty"`
	Authorization  *Authorization  `yaml:"authorization,omitempty"`
	APIs           []string        `yaml:"apis,omitempty"`
}

// ServerTLS describes the certificate used by one HTTPS server.
type ServerTLS struct {
	Secret      string `yaml:"secret,omitempty"`
	Certificate string `yaml:"certificate,omitempty"`
	PrivateKey  string `yaml:"private_key,omitempty"`
}

func (s ServerTLS) withDefaults() ServerTLS {
	certificate, privateKey := defaultServerTLSCertificate, defaultServerTLSPrivateKey
	if s.Secret != "" {
		certificate = path.Join(serverTLSSecretDirectory, s.Secret, tlsCertificateSecretKey)
		privateKey = path.Join(serverTLSSecretDirectory, s.Secret, tlsPrivateKeySecretKey)
	}
	if s.Certificate == "" {
		s.Certificate = certificate
	}
	if s.PrivateKey == "" {
		s.PrivateKey = privateKey
	}
	return s
}

func (s Server) boundAPIs(apis map[string]API) ([]API, error) {
	bound := make([]API, 0, len(s.APIs))
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

func validateServerTLS(name string, serverTLS ServerTLS) error {
	for _, file := range []struct {
		name  string
		value string
	}{
		{name: "certificate", value: serverTLS.Certificate},
		{name: "private_key", value: serverTLS.PrivateKey},
	} {
		if !path.IsAbs(file.value) || path.Clean(file.value) != file.value || file.value == "/" || strings.ContainsAny(file.value, invalidControlCharacters) {
			return fmt.Errorf("%s.%s must be a clean absolute file path", name, file.name)
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

func (s Server) clone() Server {
	s.TLSConfig = cloneConfigPointer(s.TLSConfig)
	s.Authentication = cloneConfigPointer(s.Authentication)
	s.Authorization = cloneConfigPointer(s.Authorization)
	s.APIs = slices.Clone(s.APIs)
	return s
}

func (s ServerTLS) clone() ServerTLS {
	return s
}

func (config ServerTLS) toEnvoySecret(index int) *tls.Secret {
	return &tls.Secret{
		Name: serverTLSSecretName(index),
		Type: &tls.Secret_TlsCertificate{TlsCertificate: &tls.TlsCertificate{
			CertificateChain: fileDataSource(config.Certificate),
			PrivateKey:       fileDataSource(config.PrivateKey),
			WatchedDirectory: &core.WatchedDirectory{Path: path.Dir(config.Certificate)},
		}},
	}
}
