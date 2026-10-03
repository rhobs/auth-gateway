package config

import (
	"fmt"
	"path"
	"strings"
)

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
		certificate = path.Join("/etc", s.Secret, "tls.crt")
		privateKey = path.Join("/etc", s.Secret, "tls.key")
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
		if !path.IsAbs(file.value) || path.Clean(file.value) != file.value || file.value == "/" || strings.ContainsAny(file.value, "\r\n\x00") {
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

type serverTLSMount struct {
	serverIndex int
	config      ServerTLS
}

func directoriesOverlap(a, b string) bool {
	return a == b || a == "/" || b == "/" ||
		strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}
