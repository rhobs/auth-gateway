package config

import (
	"fmt"
	"path"
	"slices"
	"strings"
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

func (c Config) validateServers(apis map[string]API) ([]resolvedServer, error) {
	if len(c.Servers) == 0 {
		return nil, fmt.Errorf("servers must contain at least one server")
	}
	servers := make([]resolvedServer, len(c.Servers))
	hosts := make(map[string]int, len(c.Servers))
	for i, server := range c.Servers {
		name := fmt.Sprintf(serverFieldPathFormat, i)
		if !validDNSHost(server.Hostname) {
			return nil, fmt.Errorf("%s.hostname must be an exact DNS hostname", name)
		}
		if previous, exists := hosts[server.Hostname]; exists {
			return nil, fmt.Errorf("%s.hostname %q is already used by servers[%d]", name, server.Hostname, previous)
		}
		hosts[server.Hostname] = i
		if server.TLSConfig != nil {
			if err := validateServerTLS(name+".tls_config", *server.TLSConfig); err != nil {
				return nil, err
			}
		}
		bound, err := server.boundAPIs(apis)
		if err != nil {
			return nil, fmt.Errorf("%s.apis: %w", name, err)
		}
		routes := make(map[string]struct{})
		for _, api := range bound {
			for _, route := range api.Routes {
				for _, method := range route.Methods {
					if err := addRouteKey(routes, route.Path, method); err != nil {
						return nil, fmt.Errorf("%s.apis: %w", name, err)
					}
				}
			}
		}
		servers[i] = resolvedServer{Server: &c.Servers[i], apis: bound}
	}
	return servers, nil
}

func (c Config) tlsMounts() []serverTLSMount {
	var mounts []serverTLSMount
	seen := make(map[ServerTLS]struct{})
	for i, server := range c.Servers {
		if server.TLSConfig == nil {
			continue
		}
		binding := *server.TLSConfig
		if _, exists := seen[binding]; exists {
			continue
		}
		seen[binding] = struct{}{}
		mounts = append(mounts, serverTLSMount{serverIndex: i, config: binding})
	}
	return mounts
}

func (c Config) validateTLSMounts() error {
	mounts := c.tlsMounts()
	for i, mount := range mounts {
		name := fmt.Sprintf("servers[%d].tls_config", mount.serverIndex)
		if mount.config.Secret == "" {
			return fmt.Errorf("%s.secret is required when generating Kubernetes resources", name)
		}
		directory := path.Dir(mount.config.Certificate)
		for _, reserved := range []string{configDirectory, collectorConfigDirectory, caDirectory} {
			if directoriesOverlap(directory, reserved) {
				return fmt.Errorf("%s certificate directory %q overlaps configuration directory %q", name, directory, reserved)
			}
		}
		for _, previous := range mounts[:i] {
			if directoriesOverlap(directory, path.Dir(previous.config.Certificate)) {
				return fmt.Errorf("%s certificate directory overlaps servers[%d].tls_config", name, previous.serverIndex)
			}
		}
	}
	return nil
}

func (c Config) hasHTTP() bool {
	for _, server := range c.Servers {
		if server.TLSConfig == nil {
			return true
		}
	}
	return false
}

func (c Config) hasHTTPS() bool {
	for _, server := range c.Servers {
		if server.TLSConfig != nil {
			return true
		}
	}
	return false
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
