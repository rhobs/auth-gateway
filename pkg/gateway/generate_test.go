package gateway

import (
	"bytes"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	jwt "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/jwt_authn/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"github.com/google/go-cmp/cmp"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	"go.yaml.in/yaml/v3"
)

func TestPlaygroundBootstrap(t *testing.T) {
	inputPath := filepath.Join("..", "..", "playground", "config.yaml")
	c := loadTestConfig(t, readTestFile(t, inputPath), inputPath)
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := files.EnvoyBootstrap.Contents
	if files.EnvoyBootstrap.Path != EnvoyBootstrapPath || len(bootstrap) == 0 {
		t.Fatal("playground bootstrap is missing")
	}
	if len(files.All()) != 1 {
		t.Fatalf("playground needs a file layout for %d generated files", len(files.All()))
	}
	checkReference(t, filepath.Join("..", "..", "playground", "envoy.yaml.golden"), bootstrap)

}

func checkReference(t *testing.T, path string, generated []byte) {
	t.Helper()
	if *updateGoldens {
		if err := os.WriteFile(path, generated, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	reference, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	referenceLines := strings.Split(string(reference), "\n")
	generatedLines := strings.Split(string(generated), "\n")
	if diff := cmp.Diff(referenceLines, generatedLines); diff != "" {
		t.Errorf("%s is out of date; run make update-golden (-reference +generated):\n%s", path, diff)
	}
}

func TestGenerateBuildsNamedAPIClustersAndRoutes(t *testing.T) {
	config, err := Load(strings.NewReader(readFixture(t, "public-routing/config.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	config.APIs = append(config.APIs, gatewayapi.API{
		Name: "logs",
		Upstream: gatewayapi.Upstream{
			Address: "loki",
			Port:    3100,
		},
		Routes: []gatewayapi.Route{{
			Methods: []string{"POST"},
			Path:    gatewayapi.PathMatch{Exact: "/logs/otlp/v1/logs"},
			Rewrite: &gatewayapi.PathRewrite{Path: "/otlp/v1/logs"},
		}},
	})
	config.Servers[0].APIs = append(config.Servers[0].APIs, "logs")

	files, err := Generate(config)
	if err != nil {
		t.Fatal(err)
	}
	if len(files.All()) != 1 || files.EnvoyBootstrap.Path != EnvoyBootstrapPath || len(files.EnvoyBootstrap.Contents) == 0 {
		t.Fatalf("generated files = %v", files)
	}
	bootstrapConfig := decodeBootstrap(t, files.EnvoyBootstrap.Contents)
	if got := bootstrapConfig.Node.GetId(); got != "auth-gateway" {
		t.Fatalf("node ID = %q", got)
	}
	static := bootstrapConfig.StaticResources
	if len(static.Listeners) != 1 || len(static.Clusters) != 2 {
		t.Fatalf("generated listener or cluster count is wrong: %d listeners, %d clusters", len(static.Listeners), len(static.Clusters))
	}
	clusters := map[string]*cluster.Cluster{}
	for _, resource := range static.Clusters {
		clusters[resource.Name] = resource
	}
	for name, wantAddress := range map[string]string{"api-metrics": "thanos-receive", "api-logs": "loki"} {
		resource, ok := clusters[name]
		if !ok {
			t.Fatalf("missing cluster %q", name)
		}
		if got := resource.GetLoadAssignment().Endpoints[0].LbEndpoints[0].GetEndpoint().Address.GetSocketAddress().Address; got != wantAddress {
			t.Errorf("cluster %q address = %q, want %q", name, got, wantAddress)
		}
	}

	listener := static.Listeners[0]
	if listener.Address.GetSocketAddress().GetPortValue() != defaultListenerPort {
		t.Fatalf("listener port = %d", listener.Address.GetSocketAddress().GetPortValue())
	}
	if len(listener.FilterChains) != 1 || len(listener.FilterChains[0].Filters) != 1 {
		t.Fatal("expected one HTTP connection manager filter chain")
	}
	var manager hcm.HttpConnectionManager
	if err := listener.FilterChains[0].Filters[0].GetTypedConfig().UnmarshalTo(&manager); err != nil {
		t.Fatal(err)
	}
	if !manager.GetRouteConfig().GetIgnorePortInHostMatching() {
		t.Fatal("route configuration does not ignore the listener port during virtual-host matching")
	}
	routes := manager.GetRouteConfig().GetVirtualHosts()[0].GetRoutes()
	if len(routes) != 5 {
		t.Fatalf("route count = %d, want 5", len(routes))
	}
	if got := routes[0].GetMatch().GetPath(); got != "/metrics/api/v1/receive" {
		t.Fatalf("metrics route path = %q", got)
	}
	if got := routes[0].GetMatch().GetHeaders()[0].GetStringMatch().GetExact(); got != "POST" {
		t.Fatalf("metrics method = %q", got)
	}
	if got := routes[0].GetRoute().GetCluster(); got != "api-metrics" {
		t.Fatalf("metrics cluster = %q", got)
	}
	if got := routes[0].GetRoute().GetPathRewrite(); got != "/api/v1/receive" {
		t.Fatalf("metrics upstream path = %q", got)
	}
	if status := routes[2].GetDirectResponse().GetStatus(); status != 405 {
		t.Fatalf("wrong method status = %d", status)
	}
	if status := routes[4].GetDirectResponse().GetStatus(); status != 404 {
		t.Fatalf("not found status = %d", status)
	}

}

func TestGenerateBuildsHTTPAndSNISelectedHTTPSChains(t *testing.T) {
	config, err := Load(strings.NewReader(readFixture(t, "route-lists/config.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	config.Kubernetes = nil
	tlsConfig := &gatewayapi.ServerTLS{
		Certificate: "/etc/gateway-certs/tls.crt",
		PrivateKey:  "/etc/gateway-certs/tls.key",
	}
	config.Servers = []gatewayapi.Server{
		{Hostname: "auth.example.com", APIs: []string{"metrics-query"}},
		{Hostname: "mts.auth.example.com", TLSConfig: tlsConfig, APIs: []string{"metrics-query"}},
	}

	files, err := Generate(config)
	if err != nil {
		t.Fatal(err)
	}
	if len(files.All()) != 2 {
		t.Fatalf("generated files = %v, want bootstrap and server certificate SDS resource", files)
	}
	bootstrapConfig := decodeBootstrap(t, files.EnvoyBootstrap.Contents)
	generatedListener := bootstrapConfig.StaticResources.Listeners[0]
	if len(generatedListener.ListenerFilters) != 1 || generatedListener.ListenerFilters[0].Name != "envoy.filters.listener.tls_inspector" {
		t.Fatalf("listener filters = %#v, want TLS inspector", generatedListener.ListenerFilters)
	}
	if len(generatedListener.FilterChains) != 2 {
		t.Fatalf("filter chain count = %d, want HTTP and HTTPS chains", len(generatedListener.FilterChains))
	}

	httpChain := generatedListener.FilterChains[0]
	if got := httpChain.GetFilterChainMatch().GetTransportProtocol(); got != "raw_buffer" {
		t.Fatalf("HTTP chain transport protocol = %q, want raw_buffer", got)
	}
	var httpManager hcm.HttpConnectionManager
	if err := httpChain.Filters[0].GetTypedConfig().UnmarshalTo(&httpManager); err != nil {
		t.Fatal(err)
	}
	if got := httpManager.GetRouteConfig().VirtualHosts[0].Domains; len(got) != 1 || got[0] != "auth.example.com" {
		t.Fatalf("HTTP domains = %v", got)
	}

	httpsChain := generatedListener.FilterChains[1]
	if match := httpsChain.GetFilterChainMatch(); match.GetTransportProtocol() != "tls" || len(match.ServerNames) != 1 || match.ServerNames[0] != "mts.auth.example.com" {
		t.Fatalf("HTTPS filter chain match = %#v", match)
	}
	var httpsManager hcm.HttpConnectionManager
	if err := httpsChain.Filters[0].GetTypedConfig().UnmarshalTo(&httpsManager); err != nil {
		t.Fatal(err)
	}
	if got := httpsManager.GetRouteConfig().VirtualHosts[0].Domains; len(got) != 1 || got[0] != "mts.auth.example.com" {
		t.Fatalf("HTTPS domains = %v", got)
	}
	var downstreamTLS tls.DownstreamTlsContext
	if err := httpsChain.TransportSocket.GetTypedConfig().UnmarshalTo(&downstreamTLS); err != nil {
		t.Fatal(err)
	}
	if required := downstreamTLS.GetRequireClientCertificate(); required != nil && required.GetValue() {
		t.Fatal("server TLS unexpectedly requires client certificates")
	}
	certificates := downstreamTLS.GetCommonTlsContext().GetTlsCertificateSdsSecretConfigs()
	if len(certificates) != 1 || certificates[0].GetName() != "gateway_server_1" {
		t.Fatalf("server certificate SDS config = %#v", certificates)
	}
	if got := certificates[0].GetSdsConfig().GetPathConfigSource().GetPath(); got != "/etc/auth-gateway/server-certificate-1.yaml" {
		t.Fatalf("certificate SDS resource path = %q", got)
	}

	secret := decodeTLSSecret(t, generatedContentsByPath(t, files, "/etc/auth-gateway/server-certificate-1.yaml"))
	certificate := secret.GetTlsCertificate()
	if secret.GetName() != "gateway_server_1" || certificate == nil {
		t.Fatalf("generated SDS resource = %#v", secret)
	}
	if got := certificate.GetCertificateChain().GetFilename(); got != tlsConfig.Certificate {
		t.Fatalf("certificate file = %q", got)
	}
	if got := certificate.GetPrivateKey().GetFilename(); got != tlsConfig.PrivateKey {
		t.Fatalf("private key file = %q", got)
	}
	if got := certificate.GetWatchedDirectory().GetPath(); got != "/etc/gateway-certs" {
		t.Fatalf("watched certificate directory = %q", got)
	}
}

func TestGenerateRejectsInvalidConfiguration(t *testing.T) {
	config, err := Load(strings.NewReader(readFixture(t, "public-routing/config.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	config.Version = 2
	if _, err := Generate(config); err == nil || !strings.Contains(err.Error(), "version must") {
		t.Fatalf("Generate error = %v, want unsupported config version", err)
	}
}

func TestGenerateReturnsNamedFilesWithRequiredPaths(t *testing.T) {
	files, err := Generate(loadConfigCase(t, "jwt-auth-with-attributes"))
	if err != nil {
		t.Fatal(err)
	}
	wantPaths := []string{
		EnvoyBootstrapPath,
		path.Join(EnvoyConfigDirectory, "server-certificate-1.yaml"),
	}
	generated := files.All()
	if len(generated) != len(wantPaths) {
		t.Fatalf("generated files = %#v, want paths %v", generated, wantPaths)
	}
	for i, file := range generated {
		if file.Path != wantPaths[i] || len(file.Contents) == 0 {
			t.Fatalf("generated file %d = %#v, want nonempty file at %q", i, file, wantPaths[i])
		}
	}
}

func TestGenerateScopesAPIExposureToServers(t *testing.T) {
	config, err := Load(strings.NewReader(readFixture(t, "public-routing/config.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	config.Kubernetes = nil
	config.APIs = append(config.APIs,
		gatewayapi.API{Name: "query", Upstream: config.APIs[0].Upstream, Routes: []gatewayapi.Route{{
			Methods: []string{"GET"}, Path: config.APIs[0].Routes[0].Path,
		}}},
		gatewayapi.API{Name: "hidden", Upstream: config.APIs[0].Upstream, Routes: []gatewayapi.Route{{
			Methods: []string{"GET"}, Path: gatewayapi.PathMatch{Exact: "/hidden"},
		}}},
	)
	config.Servers = []gatewayapi.Server{
		{Hostname: "write.example.com", APIs: []string{"metrics"}},
		{Hostname: "query.example.com", APIs: []string{"query"}},
		{Hostname: "empty.example.com"},
		{Hostname: "tls-write.example.com", TLSConfig: &gatewayapi.ServerTLS{Secret: "shared-tls"}, APIs: []string{"metrics"}},
		{Hostname: "tls-query.example.com", TLSConfig: &gatewayapi.ServerTLS{Secret: "shared-tls"}, APIs: []string{"query"}},
	}
	files, err := Generate(config)
	if err != nil {
		t.Fatal(err)
	}
	if len(files.All()) != 3 {
		t.Fatalf("file count = %d, want bootstrap and two SDS files", len(files.All()))
	}
	bootstrap := decodeBootstrap(t, files.EnvoyBootstrap.Contents)
	if len(bootstrap.StaticResources.Clusters) != 3 {
		t.Fatal("API bindings duplicated upstream clusters")
	}
	generatedListener := bootstrap.StaticResources.Listeners[0]
	if len(generatedListener.FilterChains) != 3 || generatedListener.DefaultFilterChain != nil {
		t.Fatal("expected an HTTP chain and two separate TLS chains without a default chain")
	}
	hosts := make(map[string]*route.VirtualHost)
	for _, chain := range generatedListener.FilterChains {
		manager := decodeHTTPManager(t, chain)
		if chain.GetFilterChainMatch().GetTransportProtocol() == "tls" {
			if len(manager.GetRouteConfig().VirtualHosts) != 1 {
				t.Fatal("TLS chain exposes more than one hostname")
			}
			domains := manager.GetRouteConfig().VirtualHosts[0].Domains
			sni := chain.FilterChainMatch.ServerNames
			if len(sni) != 1 || len(domains) != 1 || domains[0] != sni[0] {
				t.Fatalf("TLS authority domains %v do not match SNI %v", domains, sni)
			}
		}
		for _, host := range manager.GetRouteConfig().VirtualHosts {
			if len(host.Domains) != 1 || host.Domains[0] != host.Name {
				t.Fatalf("unexpected virtual host domains: %v", host.Domains)
			}
			hosts[host.Name] = host
		}
	}
	expected := map[string]struct{ cluster, method string }{
		"write.example.com":     {cluster: "api-metrics", method: "POST"},
		"query.example.com":     {cluster: "api-query", method: "GET"},
		"empty.example.com":     {},
		"tls-write.example.com": {cluster: "api-metrics", method: "POST"},
		"tls-query.example.com": {cluster: "api-query", method: "GET"},
	}
	if len(hosts) != len(expected) {
		t.Fatalf("virtual host count = %d, want %d", len(hosts), len(expected))
	}
	for hostname, want := range expected {
		host := hosts[hostname]
		if host == nil {
			t.Fatalf("missing virtual host %s", hostname)
		}
		routes := host.Routes
		if want.cluster == "" {
			if len(routes) != 1 || routes[0].GetDirectResponse().GetStatus() != 404 {
				t.Fatal("empty server exposes routes")
			}
			continue
		}
		if len(routes) != 3 || routes[0].GetRoute().GetCluster() != want.cluster ||
			routes[0].GetMatch().GetHeaders()[0].GetStringMatch().GetExact() != want.method {
			t.Fatalf("%s exposes routes from the wrong API", hostname)
		}
		if routes[1].GetDirectResponse().GetStatus() != 405 || routes[1].ResponseHeadersToAdd[0].Header.Value != want.method {
			t.Fatalf("%s has an Allow header from an unbound API", hostname)
		}
		if routes[2].GetDirectResponse().GetStatus() != 404 {
			t.Fatalf("%s has no final 404 response", hostname)
		}
	}
	for i, filename := range []string{"server-certificate-3.yaml", "server-certificate-4.yaml"} {
		secret := decodeTLSSecret(t, generatedContentsByPath(t, files, path.Join(EnvoyConfigDirectory, filename)))
		wantName := []string{"gateway_server_3", "gateway_server_4"}[i]
		if secret.Name != wantName || secret.GetTlsCertificate().GetWatchedDirectory().GetPath() != "/etc/shared-tls" {
			t.Fatalf("SDS file %s does not reference the shared certificate with a distinct name", filename)
		}
	}
}

func TestGenerateUsesAPIBindingOrder(t *testing.T) {
	config, err := Load(strings.NewReader(readFixture(t, "public-routing/config.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	config.APIs = append(config.APIs, gatewayapi.API{
		Name: "broad", Upstream: config.APIs[0].Upstream,
		Routes: []gatewayapi.Route{{Methods: []string{"POST"}, Path: gatewayapi.PathMatch{Prefix: "/metrics/"}}},
	})
	for _, order := range [][]string{{"broad", "metrics"}, {"metrics", "broad"}} {
		config.Servers[0].APIs = order
		files, err := Generate(config)
		if err != nil {
			t.Fatal(err)
		}
		bootstrap := decodeBootstrap(t, files.EnvoyBootstrap.Contents)
		manager := decodeHTTPManager(t, bootstrap.StaticResources.Listeners[0].FilterChains[0])
		routes := manager.GetRouteConfig().VirtualHosts[0].Routes
		for i, apiName := range order {
			if got := routes[i].GetRoute().GetCluster(); got != "api-"+apiName {
				t.Fatalf("route %d cluster = %s, want api-%s", i, got, apiName)
			}
		}
	}
}

func TestGeneratedReferenceFiles(t *testing.T) {
	cases, err := filepath.Glob(filepath.Join("testdata", "*", "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, inputPath := range cases {
		name := filepath.Base(filepath.Dir(inputPath))
		t.Run(name, func(t *testing.T) {
			input, err := os.Open(inputPath)
			if err != nil {
				t.Fatal(err)
			}
			gatewayConfig, err := Load(input)
			closeErr := input.Close()
			if err != nil {
				t.Fatal(err)
			}
			if closeErr != nil {
				t.Fatal(closeErr)
			}

			caseDir := filepath.Dir(inputPath)
			envoyFiles, err := Generate(gatewayConfig)
			if err != nil {
				t.Fatal(err)
			}
			checkReference(t, filepath.Join(caseDir, "envoy.yaml.golden"), envoyFiles.EnvoyBootstrap.Contents)
			for _, file := range envoyFiles.ClientCAResources {
				checkReference(t, filepath.Join(caseDir, filepath.Base(file.Path)+".golden"), file.Contents)
			}

		})
	}
}

func TestResolvedJWTRequirementsFollowSelectionOrder(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-multiple-issuers")
	c.Servers[0].Authentication.AnyOf = []string{"issuer-two", "issuer-one"}
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	manager := firstHTTPManager(t, files.EnvoyBootstrap.Contents)
	var authentication jwt.JwtAuthentication
	for _, filter := range manager.HttpFilters {
		if filter.Name == "envoy.filters.http.jwt_authn" {
			if err := filter.GetTypedConfig().UnmarshalTo(&authentication); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	requirements := authentication.RequirementMap["server-0"].GetRequiresAny().GetRequirements()
	if len(requirements) != 2 || requirements[0].GetProviderName() != "issuer-two" || requirements[1].GetProviderName() != "issuer-one" {
		t.Fatalf("JWT requirements = %v, want issuer-two followed by issuer-one", requirements)
	}
}

func TestResolvedReferencesDoNotAliasInput(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*gatewayapi.Config)
	}{
		{name: "API route", edit: func(c *gatewayapi.Config) { c.APIs[0].Routes[0].Path.Exact = "/changed" }},
		{name: "authenticator", edit: func(c *gatewayapi.Config) { c.Authenticators[0].JWT.Issuer = "https://changed.jwt.test" }},
		{name: "attribute source", edit: func(c *gatewayapi.Config) {
			c.Authenticators[0].Attributes["tenant_id"] = gatewayapi.AttributeSource{ClaimPath: []string{"changed"}}
		}},
		{name: "grant allowlist", edit: func(c *gatewayapi.Config) {
			c.AuthorizationPolicies[0].Grants[0].Attributes["tenant_id"][0] = "changed"
		}},
		{name: "server", edit: func(c *gatewayapi.Config) { c.Servers[2].Hostname = "changed.gateway.test" }},
		{name: "API binding", edit: func(c *gatewayapi.Config) { c.Servers[2].APIs[0] = "public" }},
		{name: "authenticator binding", edit: func(c *gatewayapi.Config) { slices.Reverse(c.Servers[2].Authentication.AnyOf) }},
		{name: "policy binding", edit: func(c *gatewayapi.Config) { slices.Reverse(c.Servers[2].Authorization.AnyOf) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := loadConfigCase(t, "api-key-auth")
			effective := resolveTestConfig(t, c)
			before, err := generate(effective)
			if err != nil {
				t.Fatal(err)
			}
			test.edit(&c)
			after, err := generate(effective)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, after) {
				t.Fatal("changing the caller's configuration changed resolved output")
			}
		})
	}
}

func TestGenerationCanReuseResolvedConfiguration(t *testing.T) {
	for _, fixture := range []string{"jwt-auth-with-attributes", "api-key-auth", "mtls-auth"} {
		t.Run(fixture, func(t *testing.T) {
			c := resolveTestConfig(t, loadConfigCase(t, fixture))
			before, err := yaml.Marshal(c.Config)
			if err != nil {
				t.Fatal(err)
			}
			first, err := generate(c)
			if err != nil {
				t.Fatal(err)
			}
			second, err := generate(c)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(first, second) {
				t.Fatal("reusing resolved configuration changed generated output")
			}
			after, err := yaml.Marshal(c.Config)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("generation changed the resolved configuration")
			}
		})
	}
}
