package gateway

import (
	"path"
	"slices"
	"strings"
	"testing"

	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	httpRBAC "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rbac/v3"
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

func TestGenerateMTLSClientCAAndCertificateRequirements(t *testing.T) {
	c := loadConfigCase(t, "mtls-auth")
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(files.ClientCAResources), 4; got != want {
		t.Fatalf("client CA resource count = %d, want %d", got, want)
	}

	bootstrap := decodeBootstrap(t, files.EnvoyBootstrap.Contents)
	chains := bootstrap.GetStaticResources().GetListeners()[0].GetFilterChains()
	wantRequired := map[string]bool{
		"mtls.gateway.test":  true,
		"mixed.gateway.test": false,
		"all.gateway.test":   true,
		"trust.gateway.test": true,
	}
	effective := resolveTestConfig(t, c)
	for serverIndex, server := range effective.servers {
		if !server.usesMTLS() {
			continue
		}
		caPath := path.Join(EnvoyConfigDirectory, clientCAResourceFilename(serverIndex))
		resource := generatedContentsByPath(t, files, caPath)
		secret := decodeTLSSecret(t, resource)
		validation := secret.GetValidationContext()
		if validation == nil {
			t.Fatalf("client CA resource %q has no validation context", caPath)
		}
		if got, want := secret.GetName(), clientCASecretName(serverIndex); got != want {
			t.Errorf("client CA secret name = %q, want %q", got, want)
		}
		caFilename := filenameTrustedCA(*server.mtls.MTLS.TrustedCA)
		if got := validation.GetTrustedCa().GetFilename(); got != caFilename {
			t.Errorf("trusted CA filename = %q, want %q", got, caFilename)
		}
		if got := validation.GetWatchedDirectory().GetPath(); got != path.Dir(caFilename) {
			t.Errorf("trusted CA watched directory = %q, want %q", got, path.Dir(caFilename))
		}

		var chain *listener.FilterChain
		for _, candidate := range chains {
			for _, hostname := range candidate.GetFilterChainMatch().GetServerNames() {
				if hostname == server.Hostname {
					chain = candidate
				}
			}
		}
		if chain == nil {
			t.Fatalf("TLS filter chain for %q is missing", server.Hostname)
		}
		var downstream tls.DownstreamTlsContext
		if err := chain.GetTransportSocket().GetTypedConfig().UnmarshalTo(&downstream); err != nil {
			t.Fatal(err)
		}
		if got := downstream.GetRequireClientCertificate(); got == nil || got.GetValue() != wantRequired[server.Hostname] {
			t.Errorf("%s require_client_certificate = %v, want %t", server.Hostname, got, wantRequired[server.Hostname])
		}
		clientCA := downstream.GetCommonTlsContext().GetValidationContextSdsSecretConfig()
		if clientCA == nil {
			t.Fatalf("%s has no client CA SDS reference", server.Hostname)
		}
		if got, want := clientCA.GetName(), clientCASecretName(serverIndex); got != want {
			t.Errorf("%s client CA SDS name = %q, want %q", server.Hostname, got, want)
		}
		if got, want := clientCA.GetSdsConfig().GetPathConfigSource().GetPath(), caPath; got != want {
			t.Errorf("%s client CA SDS path = %q, want %q", server.Hostname, got, want)
		}
	}
}

func TestMTLSAllOfSharedAttributesAreCheckedAfterAuthentication(t *testing.T) {
	c := loadConfigCase(t, "mtls-auth")
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := decodeBootstrap(t, files.EnvoyBootstrap.Contents)
	var allChain *listener.FilterChain
	for _, chain := range bootstrap.GetStaticResources().GetListeners()[0].GetFilterChains() {
		if slices.Contains(chain.GetFilterChainMatch().GetServerNames(), "all.gateway.test") {
			allChain = chain
			break
		}
	}
	if allChain == nil {
		t.Fatal("all_of TLS filter chain is missing")
	}
	manager := decodeHTTPManager(t, allChain)

	names := httpFilterNames(manager)
	index := func(name string) int { return slices.Index(names, name) }
	if index(authenticationFilterName) < 0 ||
		index(mtlsPendingCleanupFilterName) <= index(authenticationFilterName) ||
		index(mtlsSANCardinalityFilterName) <= index(mtlsPendingCleanupFilterName) ||
		index(mtlsSharedAttributesFilterName) <= index(mtlsSANCardinalityFilterName) {
		t.Fatalf("mTLS filter order = %v", names)
	}

	var allHost *route.VirtualHost
	for _, host := range manager.GetRouteConfig().GetVirtualHosts() {
		if host.GetName() == "all.gateway.test" {
			allHost = host
			break
		}
	}
	if allHost == nil {
		t.Fatal("all_of virtual host is missing")
	}
	var authentication httpRBAC.RBACPerRoute
	authenticationConfig := allHost.GetTypedPerFilterConfig()[authenticationFilterName]
	if authenticationConfig == nil {
		t.Fatal("all_of authentication rules are missing")
	}
	if err := authenticationConfig.UnmarshalTo(&authentication); err != nil {
		t.Fatal(err)
	}
	if policy := authentication.GetRbac().GetRules().GetPolicies()["authenticated"]; policy == nil || policy.GetCondition() != nil {
		t.Fatalf("all_of authentication still checks shared attributes: %#v", policy)
	}

	var sharedAttributes httpRBAC.RBACPerRoute
	sharedAttributesConfig := allHost.GetTypedPerFilterConfig()[mtlsSharedAttributesFilterName]
	if sharedAttributesConfig == nil {
		t.Fatal("all_of shared-attribute rules are missing")
	}
	if err := sharedAttributesConfig.UnmarshalTo(&sharedAttributes); err != nil {
		t.Fatal(err)
	}
	policy := sharedAttributes.GetRbac().GetRules().GetPolicies()["shared-attributes"]
	if policy == nil || policy.GetCondition() == nil || len(policy.GetPrincipals()) == 0 {
		t.Fatalf("all_of shared-attribute policy = %#v", policy)
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
