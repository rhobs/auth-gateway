package config

import (
	"strings"
	"testing"

	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
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
	config, err := Load(strings.NewReader(readFixture(t, "public-routing/config.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	other := config.APIs[0]
	other.Name = "other"
	other.Routes = append([]gatewayapi.Route(nil), other.Routes...)
	config.APIs = append(config.APIs, other)
	if err := Validate(config); err != nil {
		t.Fatalf("unbound API with the same path rejected: %v", err)
	}
	config.Servers = append(config.Servers, gatewayapi.Server{Hostname: "other.example.com", APIs: []string{"other"}})
	if err := Validate(config); err != nil {
		t.Fatalf("same path on separate servers rejected: %v", err)
	}
	config.Servers[0].APIs = append(config.Servers[0].APIs, "other")
	if err := Validate(config); err == nil || !strings.Contains(err.Error(), "servers[0].apis") {
		t.Fatalf("Validate error = %v, want route conflict on servers[0]", err)
	}
}

func TestValidateServers(t *testing.T) {
	newConfig := func(t *testing.T) gatewayapi.Config {
		t.Helper()
		c := loadConfigCase(t, "public-routing")
		c.Kubernetes = nil
		c.Servers = []gatewayapi.Server{
			{Hostname: "auth.example.com", APIs: []string{"metrics"}},
			{Hostname: "tls.example.com", TLSConfig: &gatewayapi.ServerTLS{}, APIs: []string{"metrics"}},
		}
		return c
	}

	if err := Validate(newConfig(t)); err != nil {
		t.Fatalf("valid HTTP and HTTPS servers rejected: %v", err)
	}
	tests := []struct {
		name  string
		field string
		edit  func(*gatewayapi.Config)
	}{
		{name: "no servers", field: "servers", edit: func(c *gatewayapi.Config) { c.Servers = nil }},
		{name: "empty servers", field: "servers", edit: func(c *gatewayapi.Config) { c.Servers = []gatewayapi.Server{} }},
		{name: "missing hostname", field: "servers[0].hostname", edit: func(c *gatewayapi.Config) { c.Servers[0].Hostname = "" }},
		{name: "invalid hostname", field: "servers[0].hostname", edit: func(c *gatewayapi.Config) { c.Servers[0].Hostname = "https://auth.example.com" }},
		{name: "wildcard hostname", field: "servers[0].hostname", edit: func(c *gatewayapi.Config) { c.Servers[0].Hostname = "*.example.com" }},
		{name: "IP hostname", field: "servers[0].hostname", edit: func(c *gatewayapi.Config) { c.Servers[0].Hostname = "127.0.0.1" }},
		{name: "duplicate hostname", field: "servers[2].hostname", edit: func(c *gatewayapi.Config) { c.Servers = append(c.Servers, c.Servers[0]) }},
		{name: "host bound to both protocols", field: "servers[1].hostname", edit: func(c *gatewayapi.Config) { c.Servers[1].Hostname = c.Servers[0].Hostname }},
		{name: "unknown API", field: "servers[0].apis", edit: func(c *gatewayapi.Config) { c.Servers[0].APIs = []string{"unknown"} }},
		{name: "duplicate API binding", field: "servers[0].apis", edit: func(c *gatewayapi.Config) { c.Servers[0].APIs = []string{"metrics", "metrics"} }},
		{name: "certificate paths share a directory", field: "servers[1].tls_config.certificate", edit: func(c *gatewayapi.Config) {
			c.Servers[1].TLSConfig.Certificate = "/etc/certs/tls.crt"
			c.Servers[1].TLSConfig.PrivateKey = "/etc/keys/tls.key"
		}},
		{name: "relative certificate path", field: "servers[1].tls_config.certificate", edit: func(c *gatewayapi.Config) { c.Servers[1].TLSConfig.Certificate = "tls.crt" }},
		{name: "identical certificate and key", field: "servers[1].tls_config.certificate", edit: func(c *gatewayapi.Config) {
			c.Servers[1].TLSConfig.Certificate = "/etc/certs/tls.crt"
			c.Servers[1].TLSConfig.PrivateKey = "/etc/certs/tls.crt"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := newConfig(t)
			test.edit(&c)
			if err := Validate(c); err == nil || !strings.Contains(err.Error(), test.field) {
				t.Fatalf("validation error = %v, want field %q", err, test.field)
			}
		})
	}
}

func TestValidateRejectsInvalidUnboundAPI(t *testing.T) {
	config, err := Load(strings.NewReader(readFixture(t, "public-routing/config.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	api := config.APIs[0]
	api.Name = "unbound"
	api.Routes = append([]gatewayapi.Route(nil), api.Routes...)
	api.Routes[0].Methods = nil
	config.APIs = append(config.APIs, api)

	if err := Validate(config); err == nil || !strings.Contains(err.Error(), "apis[1].routes[0].methods") {
		t.Fatalf("Validate error = %v, want missing route methods error for unbound API", err)
	}
}

func TestValidateKubernetesTLSMounts(t *testing.T) {
	tests := []struct {
		name string
		want string
		edit func(*gatewayapi.Config)
	}{
		{name: "missing Secret", want: "servers[1].tls_config.secret", edit: func(c *gatewayapi.Config) { c.Servers[1].TLSConfig.Secret = "" }},
		{name: "same directory", want: "servers[1].tls_config", edit: func(c *gatewayapi.Config) {
			c.Servers[1].TLSConfig.Certificate = "/etc/tls-one/tls.crt"
			c.Servers[1].TLSConfig.PrivateKey = "/etc/tls-one/tls.key"
		}},
		{name: "nested directory", want: "servers[1].tls_config", edit: func(c *gatewayapi.Config) {
			c.Servers[1].TLSConfig.Certificate = "/etc/tls-one/nested/tls.crt"
			c.Servers[1].TLSConfig.PrivateKey = "/etc/tls-one/nested/tls.key"
		}},
		{name: "gateway configuration", want: "servers[1].tls_config", edit: func(c *gatewayapi.Config) {
			c.Servers[1].TLSConfig.Certificate = "/etc/auth-gateway/tls.crt"
			c.Servers[1].TLSConfig.PrivateKey = "/etc/auth-gateway/tls.key"
		}},
		{name: "collector configuration", want: "servers[1].tls_config", edit: func(c *gatewayapi.Config) {
			c.Servers[1].TLSConfig.Certificate = "/etc/collector/tls.crt"
			c.Servers[1].TLSConfig.PrivateKey = "/etc/collector/tls.key"
		}},
		{name: "parent of configuration", want: "servers[1].tls_config", edit: func(c *gatewayapi.Config) {
			c.Servers[1].TLSConfig.Certificate = "/etc/tls.crt"
			c.Servers[1].TLSConfig.PrivateKey = "/etc/tls.key"
		}},
		{name: "filesystem root", want: "servers[1].tls_config", edit: func(c *gatewayapi.Config) {
			c.Servers[1].TLSConfig.Certificate = "/tls.crt"
			c.Servers[1].TLSConfig.PrivateKey = "/tls.key"
		}},
		{name: "conflicting filenames for a shared Secret", want: "servers[1].tls_config", edit: func(c *gatewayapi.Config) {
			c.Servers[1].TLSConfig = &gatewayapi.ServerTLS{Secret: "tls-one", Certificate: "/etc/tls-one/server.pem", PrivateKey: "/etc/tls-one/key.pem"}
		}},
		{name: "HTTP and HTTPS port conflict", want: "kubernetes.service_port and kubernetes.https_service_port", edit: func(c *gatewayapi.Config) {
			c.Servers = append(c.Servers, gatewayapi.Server{Hostname: "http.example.com", APIs: []string{"metrics"}})
			c.Kubernetes.HTTPSServicePort = new(int32(80))
		}},
		{name: "HTTPS port without HTTPS", want: "kubernetes.https_service_port", edit: func(c *gatewayapi.Config) {
			c.Servers[0].TLSConfig = nil
			c.Servers[1].TLSConfig = nil
			c.Kubernetes.HTTPSServicePort = new(int32(443))
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config, err := Load(strings.NewReader(readFixture(t, "public-routing/config.yaml")))
			if err != nil {
				t.Fatal(err)
			}
			config.Servers = []gatewayapi.Server{
				{Hostname: "one.example.com", TLSConfig: &gatewayapi.ServerTLS{Secret: "tls-one"}, APIs: []string{"metrics"}},
				{Hostname: "two.example.com", TLSConfig: &gatewayapi.ServerTLS{Secret: "tls-two"}, APIs: []string{"metrics"}},
			}
			test.edit(&config)
			if err := Validate(config); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validation error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestServerTLSDefaults(t *testing.T) {
	tests := []struct {
		name        string
		tls         gatewayapi.ServerTLS
		certificate string
		privateKey  string
	}{
		{name: "file only", certificate: DefaultServerTLSCertificate, privateKey: DefaultServerTLSPrivateKey},
		{name: "named Secret", tls: gatewayapi.ServerTLS{Secret: "other-tls"}, certificate: "/etc/other-tls/tls.crt", privateKey: "/etc/other-tls/tls.key"},
		{name: "explicit paths", tls: gatewayapi.ServerTLS{Secret: "other-tls", Certificate: "/certs/server.pem", PrivateKey: "/certs/key.pem"}, certificate: "/certs/server.pem", privateKey: "/certs/key.pem"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := loadConfigCase(t, "public-routing")
			c.Kubernetes = nil
			c.Servers[0].TLSConfig = &test.tls
			defaulted := withDefaultsConfig(c)
			if err := Validate(defaulted); err != nil {
				t.Fatal(err)
			}
			got := defaulted.Servers[0].TLSConfig
			if got.Certificate != test.certificate || got.PrivateKey != test.privateKey {
				t.Fatalf("TLS paths = %s, %s, want %s, %s", got.Certificate, got.PrivateKey, test.certificate, test.privateKey)
			}
		})
	}
}
