package gateway

import (
	"strings"
	"testing"

	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
)

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
			c.Servers = append(c.Servers, gatewayapi.Server{Hostname: "http.example.com", APIs: []gatewayapi.APIBinding{{Name: "metrics", Public: true}}})
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
				{Hostname: "one.example.com", TLSConfig: &gatewayapi.ServerTLS{Secret: "tls-one"}, APIs: []gatewayapi.APIBinding{{Name: "metrics", Public: true}}},
				{Hostname: "two.example.com", TLSConfig: &gatewayapi.ServerTLS{Secret: "tls-two"}, APIs: []gatewayapi.APIBinding{{Name: "metrics", Public: true}}},
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
		{name: "file only", certificate: defaultServerTLSCertificate, privateKey: defaultServerTLSPrivateKey},
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

func TestKubernetesTrustedCAFilenameUsesContainerFileWithoutMount(t *testing.T) {
	const filename = "/etc/pki/tls/certs/ca-bundle.crt"
	c := loadConfigCase(t, "jwt-auth")
	c.Authenticators[0].JWT.JWKS.TrustedCA = &gatewayapi.TrustedCA{Filename: filename}

	resources, err := GenerateKubernetes(c)
	if err != nil {
		t.Fatal(err)
	}
	b := decodeBootstrap(t, []byte(resources.ConfigMap.Data["envoy.yaml"]))
	var gotFilename string
	for _, cluster := range b.StaticResources.Clusters {
		if cluster.Name != jwksClusterName(c.Authenticators[0].Name) {
			continue
		}
		var transport tls.UpstreamTlsContext
		if err := cluster.TransportSocket.GetTypedConfig().UnmarshalTo(&transport); err != nil {
			t.Fatal(err)
		}
		gotFilename = transport.CommonTlsContext.GetValidationContext().TrustedCa.GetFilename()
	}
	if gotFilename != filename {
		t.Fatalf("generated trusted CA filename = %q, want %q", gotFilename, filename)
	}

	configMapNames := map[string]bool{resources.ConfigMap.Name: true}
	if resources.OTelCollectorConfigMap != nil {
		configMapNames[resources.OTelCollectorConfigMap.Name] = true
	}
	configMapVolumeCount := 0
	for _, volume := range resources.Deployment.Spec.Template.Spec.Volumes {
		if volume.ConfigMap == nil {
			continue
		}
		configMapVolumeCount++
		if !configMapNames[volume.ConfigMap.Name] {
			t.Fatalf("unexpected ConfigMap volume for a trusted CA filename: %#v", volume)
		}
	}
	if configMapVolumeCount != len(configMapNames) {
		t.Fatalf("ConfigMap volume count = %d, want %d generated configuration volumes", configMapVolumeCount, len(configMapNames))
	}
}

func TestDedicatedMTLSRequiresCertificateForItsEntireAPISet(t *testing.T) {
	c := loadConfigCase(t, "access-control")
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := decodeBootstrap(t, files.EnvoyBootstrap.Contents)
	var found bool
	for _, chain := range bootstrap.GetStaticResources().GetListeners()[0].GetFilterChains() {
		if chain.GetTransportSocket() == nil {
			continue
		}
		found = true
		var transport tls.DownstreamTlsContext
		if err := chain.TransportSocket.GetTypedConfig().UnmarshalTo(&transport); err != nil {
			t.Fatal(err)
		}
		if !transport.GetRequireClientCertificate().GetValue() || transport.GetCommonTlsContext().GetValidationContextSdsSecretConfig() == nil {
			t.Fatal("mTLS must require a verified certificate during the handshake")
		}
		manager := decodeHTTPManager(t, chain)
		for _, name := range []string{jwtAuthnFilterName, apiKeyFilterName} {
			if hasHTTPFilter(manager, name) {
				t.Fatalf("dedicated mTLS manager enables %q", name)
			}
		}
		if hosts := manager.GetRouteConfig().GetVirtualHosts(); len(hosts) != 1 || hosts[0].Name != "cert.access.test" {
			t.Fatalf("mTLS host isolation = %v", hosts)
		}
	}
	if !found {
		t.Fatal("dedicated mTLS filter chain is missing")
	}
}
