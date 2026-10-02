package config

import (
	"strings"
	"testing"
)

func TestLoadRequiresExplicitServers(t *testing.T) {
	input := `version: 1
apis:
  - name: metrics
    upstream:
      address: thanos-receive
      port: 19291
    routes:
      - methods: [POST]
        path:
          exact: /metrics/api/v1/receive
`
	if _, err := Load(strings.NewReader(input)); err == nil || !strings.Contains(err.Error(), "servers") {
		t.Fatalf("Load error = %v, want missing servers error", err)
	}
}

func TestServerRouteConflictsAreScopedToBindings(t *testing.T) {
	config, err := Load(strings.NewReader(readFixture(t, "example.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	other := config.APIs[0]
	other.Name = "other"
	other.Routes = append([]Route(nil), other.Routes...)
	config.APIs = append(config.APIs, other)
	if err := config.Validate(); err != nil {
		t.Fatalf("unbound API with the same path rejected: %v", err)
	}
	config.Servers = append(config.Servers, Server{Hostname: "other.example.com", APIs: []string{"other"}})
	if err := config.Validate(); err != nil {
		t.Fatalf("same path on separate servers rejected: %v", err)
	}
	config.Servers[0].APIs = append(config.Servers[0].APIs, "other")
	if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "servers[0].apis") {
		t.Fatalf("Validate error = %v, want route conflict on servers[0]", err)
	}
}

func TestValidateRejectsInvalidUnboundAPI(t *testing.T) {
	config, err := Load(strings.NewReader(readFixture(t, "example.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	api := config.APIs[0]
	api.Name = "unbound"
	api.Routes = append([]Route(nil), api.Routes...)
	api.Routes[0].Methods = nil
	config.APIs = append(config.APIs, api)

	if err := config.Validate(); err == nil || !strings.Contains(err.Error(), ".methods") {
		t.Fatalf("Validate error = %v, want missing route methods error for unbound API", err)
	}
}

func TestServerTLSDefaults(t *testing.T) {
	tests := []struct {
		name        string
		tls         ServerTLS
		certificate string
		privateKey  string
	}{
		{name: "file only", certificate: defaultServerTLSCertificate, privateKey: defaultServerTLSPrivateKey},
		{name: "named Secret", tls: ServerTLS{Secret: "other-tls"}, certificate: "/etc/other-tls/tls.crt", privateKey: "/etc/other-tls/tls.key"},
		{name: "explicit paths", tls: ServerTLS{Secret: "other-tls", Certificate: "/certs/server.pem", PrivateKey: "/certs/key.pem"}, certificate: "/certs/server.pem", privateKey: "/certs/key.pem"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config, err := Load(strings.NewReader(readFixture(t, "example.yaml")))
			if err != nil {
				t.Fatal(err)
			}
			config.Kubernetes = nil
			config.Servers[0].TLSConfig = &test.tls
			defaulted := config.withDefaults()
			if err := defaulted.Validate(); err != nil {
				t.Fatal(err)
			}
			tls := defaulted.Servers[0].TLSConfig
			if tls.Certificate != test.certificate || tls.PrivateKey != test.privateKey {
				t.Fatalf("TLS paths = %s, %s, want %s, %s", tls.Certificate, tls.PrivateKey, test.certificate, test.privateKey)
			}
		})
	}
}

func TestServerDefaultsDoNotMutateInput(t *testing.T) {
	config, err := Load(strings.NewReader(readFixture(t, "example.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	config.Servers[0].TLSConfig = &ServerTLS{Secret: "server-tls"}
	defaulted := config.withDefaults()
	if config.Servers[0].TLSConfig.Certificate != "" || config.Servers[0].TLSConfig.PrivateKey != "" || config.Kubernetes.HTTPSServicePort != 0 {
		t.Fatal("defaults changed the input TLS configuration")
	}
	if defaulted.Kubernetes.HTTPSServicePort != defaultHTTPSServicePort {
		t.Fatal("HTTPS Service port was not defaulted")
	}
	defaulted.Servers[0].APIs[0] = "other"
	defaulted.Servers[0].TLSConfig.Secret = "other-tls"
	if config.Servers[0].APIs[0] != "metrics" || config.Servers[0].TLSConfig.Secret != "server-tls" {
		t.Fatal("defaulted server aliases the input configuration")
	}
}

func TestValidateKubernetesTLSMounts(t *testing.T) {
	tests := map[string]func(*Config){
		"missing Secret": func(c *Config) { c.Servers[1].TLSConfig.Secret = "" },
		"same directory": func(c *Config) {
			c.Servers[1].TLSConfig.Certificate = "/etc/tls-one/tls.crt"
			c.Servers[1].TLSConfig.PrivateKey = "/etc/tls-one/tls.key"
		},
		"nested directory": func(c *Config) {
			c.Servers[1].TLSConfig.Certificate = "/etc/tls-one/nested/tls.crt"
			c.Servers[1].TLSConfig.PrivateKey = "/etc/tls-one/nested/tls.key"
		},
		"gateway configuration": func(c *Config) {
			c.Servers[1].TLSConfig.Certificate = "/etc/auth-gateway/tls.crt"
			c.Servers[1].TLSConfig.PrivateKey = "/etc/auth-gateway/tls.key"
		},
		"collector configuration": func(c *Config) {
			c.Servers[1].TLSConfig.Certificate = "/etc/collector/tls.crt"
			c.Servers[1].TLSConfig.PrivateKey = "/etc/collector/tls.key"
		},
		"parent of configuration": func(c *Config) {
			c.Servers[1].TLSConfig.Certificate = "/etc/tls.crt"
			c.Servers[1].TLSConfig.PrivateKey = "/etc/tls.key"
		},
		"filesystem root": func(c *Config) {
			c.Servers[1].TLSConfig.Certificate = "/tls.crt"
			c.Servers[1].TLSConfig.PrivateKey = "/tls.key"
		},
		"conflicting filenames for a shared Secret": func(c *Config) {
			c.Servers[1].TLSConfig = &ServerTLS{Secret: "tls-one", Certificate: "/etc/tls-one/server.pem", PrivateKey: "/etc/tls-one/key.pem"}
		},
		"metrics port conflict": func(c *Config) { c.Kubernetes.HTTPSServicePort = 8889 },
		"HTTP and HTTPS port conflict": func(c *Config) {
			c.Servers = append(c.Servers, Server{Hostname: "http.example.com", APIs: []string{"metrics"}})
			c.Kubernetes.HTTPSServicePort = 80
		},
		"HTTPS port without HTTPS": func(c *Config) {
			c.Servers[0].TLSConfig = nil
			c.Servers[1].TLSConfig = nil
			c.Kubernetes.HTTPSServicePort = 443
		},
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			config, err := Load(strings.NewReader(readFixture(t, "example.yaml")))
			if err != nil {
				t.Fatal(err)
			}
			config.Servers = []Server{
				{Hostname: "one.example.com", TLSConfig: &ServerTLS{Secret: "tls-one"}, APIs: []string{"metrics"}},
				{Hostname: "two.example.com", TLSConfig: &ServerTLS{Secret: "tls-two"}, APIs: []string{"metrics"}},
			}
			change(&config)
			if err := config.Validate(); err == nil {
				t.Fatal("invalid Kubernetes TLS configuration accepted")
			}
		})
	}
}
