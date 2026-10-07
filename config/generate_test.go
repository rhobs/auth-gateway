package config

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	bootstrap "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"go.yaml.in/yaml/v3"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"
)

var updateGoldens = flag.Bool("update", false, "update generated reference files")

func TestGeneratedReferenceFiles(t *testing.T) {
	cases, err := filepath.Glob(filepath.Join("testdata", "*", "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, inputPath := range cases {
		inputPath := inputPath
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
			checkReference(t, filepath.Join(caseDir, "envoy.yaml.golden"), envoyFiles["envoy.yaml"])
			processingPath := filepath.Join(caseDir, "processing.yaml.golden")
			if data, ok := envoyFiles[processingConfigFilename]; ok {
				checkReference(t, processingPath, data)
			} else if *updateGoldens {
				if err := os.Remove(processingPath); err != nil && !os.IsNotExist(err) {
					t.Fatal(err)
				}
			} else if _, err := os.Stat(processingPath); !os.IsNotExist(err) {
				t.Errorf("unexpected processing reference %s", processingPath)
			}

			resources, err := GenerateKubernetes(gatewayConfig)
			if err != nil {
				t.Fatal(err)
			}
			manifest, err := resources.YAML()
			if err != nil {
				t.Fatal(err)
			}
			checkReference(t, filepath.Join(caseDir, "kubernetes.yaml.golden"), manifest)
		})
	}
}

func TestPlaygroundBootstrap(t *testing.T) {
	inputPath := filepath.Join("..", "playground", "config.yaml")
	c := loadTestConfig(t, readTestFile(t, inputPath), inputPath)
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, exists := files[envoyConfigFilename]
	if !exists {
		t.Fatal("playground bootstrap is missing")
	}
	if len(files) != 1 {
		t.Fatalf("playground needs a file layout for %d generated files", len(files))
	}
	checkReference(t, filepath.Join("..", "playground", "envoy.yaml.golden"), bootstrap)

	collectorConfig := generateOTelCollectorConfig(c.Observability.Metrics, c.Observability.Tracing)
	checkReference(t, filepath.Join("..", "playground", "otel-collector.yaml.golden"), collectorConfig)
}

func checkReference(t *testing.T, path string, want []byte) {
	t.Helper()
	if *updateGoldens {
		if err := os.WriteFile(path, want, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s is out of date; run make update-golden", path)
	}
}

func TestGenerateBuildsNamedAPIClustersAndRoutes(t *testing.T) {
	config, err := Load(strings.NewReader(readFixture(t, "public-routing/config.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	config.APIs = append(config.APIs, API{
		Name: "logs",
		Upstream: Upstream{
			Address: "loki",
			Port:    3100,
		},
		Routes: []Route{{
			Methods: []string{"POST"},
			Path:    PathMatch{Exact: "/logs/otlp/v1/logs"},
			Rewrite: &PathRewrite{Path: "/otlp/v1/logs"},
		}},
	})
	config.Servers[0].APIs = append(config.Servers[0].APIs, "logs")

	files, err := Generate(config)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || len(files["envoy.yaml"]) == 0 {
		t.Fatalf("generated files = %v", files)
	}
	bootstrapConfig := decodeBootstrap(t, files["envoy.yaml"])
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

func TestGenerateAllowsMethodsOnOnePath(t *testing.T) {
	config, err := Load(strings.NewReader(readFixture(t, "public-routing/config.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	secondRoute := config.APIs[0].Routes[0]
	config.APIs[0].Routes[0].Methods = []string{"GET"}
	secondRoute.Methods = []string{"POST"}
	config.APIs = append(config.APIs, API{
		Name:     "metrics-write",
		Upstream: config.APIs[0].Upstream,
		Routes:   []Route{secondRoute},
	})
	config.Servers[0].APIs = append(config.Servers[0].APIs, "metrics-write")
	files, err := Generate(config)
	if err != nil {
		t.Fatal(err)
	}
	bootstrapConfig := decodeBootstrap(t, files["envoy.yaml"])
	var manager hcm.HttpConnectionManager
	if err := bootstrapConfig.StaticResources.Listeners[0].FilterChains[0].Filters[0].GetTypedConfig().UnmarshalTo(&manager); err != nil {
		t.Fatal(err)
	}
	routes := manager.GetRouteConfig().GetVirtualHosts()[0].GetRoutes()
	if got := routes[2].GetResponseHeadersToAdd()[0].GetHeader().GetValue(); got != "GET, POST" {
		t.Fatalf("Allow header = %q", got)
	}
}

func TestGenerateBuildsRoutesFromRouteLists(t *testing.T) {
	config, err := Load(strings.NewReader(readFixture(t, "route-lists/config.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	files, err := Generate(config)
	if err != nil {
		t.Fatal(err)
	}
	bootstrapConfig := decodeBootstrap(t, files["envoy.yaml"])
	var manager hcm.HttpConnectionManager
	if err := bootstrapConfig.StaticResources.Listeners[0].FilterChains[0].Filters[0].GetTypedConfig().UnmarshalTo(&manager); err != nil {
		t.Fatal(err)
	}
	routes := manager.GetRouteConfig().GetVirtualHosts()[0].GetRoutes()
	if len(routes) != 8 {
		t.Fatalf("route count = %d, want 8", len(routes))
	}

	query := routes[0]
	if got := query.GetMatch().GetSafeRegex().GetRegex(); got != `^/metrics/api/v1/(query|query_range)$` {
		t.Fatalf("query regex = %q", got)
	}
	if got := query.GetMatch().GetHeaders()[0].GetStringMatch().GetExact(); got != "GET" {
		t.Fatalf("query method = %q, want GET", got)
	}
	if got := query.GetRoute().GetCluster(); got != "api-metrics-query" {
		t.Fatalf("query cluster = %q", got)
	}
	regexRewrite := query.GetRoute().GetRegexRewrite()
	if regexRewrite == nil || regexRewrite.GetPattern().GetRegex() != `^/metrics/(.*)$` || regexRewrite.GetSubstitution() != `/\1` {
		t.Fatalf("query rewrite = %#v", regexRewrite)
	}

	prefix := routes[2]
	if got := prefix.GetMatch().GetPrefix(); got != "/metrics/api/v1/label/" {
		t.Fatalf("label prefix = %q", got)
	}
	if got := prefix.GetRoute().GetPrefixRewrite(); got != "/api/v1/label/" {
		t.Fatalf("label prefix rewrite = %q", got)
	}

	exact := routes[3]
	if got := exact.GetMatch().GetPath(); got != "/metrics/api/v1/labels" {
		t.Fatalf("labels path = %q", got)
	}
	if got := exact.GetRoute().GetPathRewrite(); got != "/api/v1/labels" {
		t.Fatalf("labels path rewrite = %q", got)
	}
	if got := routes[4].GetDirectResponse().GetStatus(); got != 405 {
		t.Fatalf("query wrong method status = %d", got)
	}
	if got := routes[4].GetResponseHeadersToAdd()[0].GetHeader().GetValue(); got != "GET, POST" {
		t.Fatalf("query Allow header = %q", got)
	}
	if got := routes[7].GetDirectResponse().GetStatus(); got != 404 {
		t.Fatalf("not found status = %d", got)
	}
}

func TestGenerateBuildsHTTPAndSNISelectedHTTPSChains(t *testing.T) {
	config, err := Load(strings.NewReader(readFixture(t, "route-lists/config.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	config.Kubernetes = nil
	tlsConfig := &ServerTLS{
		Certificate: "/etc/gateway-certs/tls.crt",
		PrivateKey:  "/etc/gateway-certs/tls.key",
	}
	config.Servers = []Server{
		{Hostname: "auth.example.com", APIs: []string{"metrics-query"}},
		{Hostname: "mts.auth.example.com", TLSConfig: tlsConfig, APIs: []string{"metrics-query"}},
	}

	files, err := Generate(config)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("generated files = %v, want bootstrap and server certificate SDS resource", files)
	}
	bootstrapConfig := decodeBootstrap(t, files["envoy.yaml"])
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

	secret := decodeTLSSecret(t, files["server-certificate-1.yaml"])
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

func TestGenerateScopesAPIExposureToServers(t *testing.T) {
	config, err := Load(strings.NewReader(readFixture(t, "public-routing/config.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	config.Kubernetes = nil
	config.APIs = append(config.APIs,
		API{Name: "query", Upstream: config.APIs[0].Upstream, Routes: []Route{{
			Methods: []string{"GET"}, Path: config.APIs[0].Routes[0].Path,
		}}},
		API{Name: "hidden", Upstream: config.APIs[0].Upstream, Routes: []Route{{
			Methods: []string{"GET"}, Path: PathMatch{Exact: "/hidden"},
		}}},
	)
	config.Servers = []Server{
		{Hostname: "write.example.com", APIs: []string{"metrics"}},
		{Hostname: "query.example.com", APIs: []string{"query"}},
		{Hostname: "empty.example.com"},
		{Hostname: "tls-write.example.com", TLSConfig: &ServerTLS{Secret: "shared-tls"}, APIs: []string{"metrics"}},
		{Hostname: "tls-query.example.com", TLSConfig: &ServerTLS{Secret: "shared-tls"}, APIs: []string{"query"}},
	}
	files, err := Generate(config)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 3 {
		t.Fatalf("file count = %d, want bootstrap and two SDS files", len(files))
	}
	bootstrap := decodeBootstrap(t, files["envoy.yaml"])
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
		secret := decodeTLSSecret(t, files[filename])
		wantName := []string{"gateway_server_3", "gateway_server_4"}[i]
		if secret.Name != wantName || secret.GetTlsCertificate().GetWatchedDirectory().GetPath() != "/etc/shared-tls" {
			t.Fatalf("SDS file %s does not reference the shared certificate with a distinct name", filename)
		}
	}
}

func TestGenerationIsDeterministic(t *testing.T) {
	buildMapped := func(t *testing.T, reverse bool) Config {
		t.Helper()
		c := loadConfigCase(t, "jwt-auth-with-mappings")
		entries := []struct{ source, target string }{
			{source: "client-123", target: "team-a"},
			{source: "client-456", target: "team-b"},
			{source: "customer-456", target: "team-a"},
			{source: "customer-789", target: "team-b"},
		}
		mappings := make(map[string]string, len(entries))
		for i := range entries {
			index := i
			if reverse {
				index = len(entries) - i - 1
			}
			mappings[entries[index].source] = entries[index].target
		}
		attributes := c.Processing[0].Attributes
		attribute := attributes["tenant_id"]
		attribute.Mappings = mappings
		attributes["tenant_id"] = attribute
		return c
	}
	buildMultipleCAs := func(t *testing.T, reverse bool) Config {
		t.Helper()
		c := loadConfigCase(t, "jwt-auth-multiple-issuers")
		c.Authenticators[0].JWT.JWKS.TrustedCA = &TrustedCA{ConfigMap: &CAConfigMap{Name: "issuer-one-ca", Key: "ca.crt"}}
		c.Authenticators[1].JWT.JWKS.TrustedCA = &TrustedCA{ConfigMap: &CAConfigMap{Name: "issuer-two-ca", Key: "ca.crt"}}
		c.APIs[0].Upstream.TLSConfig = &UpstreamTLS{
			ServerName: "backend.example.test",
			TrustedCA:  &TrustedCA{ConfigMap: &CAConfigMap{Name: "backend-ca", Key: "ca.crt"}},
		}
		requests := []struct{ name, value string }{{name: "cpu", value: "50m"}, {name: "memory", value: "64Mi"}}
		limits := []struct{ name, value string }{{name: "cpu", value: "1"}, {name: "memory", value: "256Mi"}}
		c.Kubernetes.Resources.Requests = resourceMap(requests, reverse)
		c.Kubernetes.Resources.Limits = resourceMap(limits, reverse)
		return c
	}
	tests := []struct {
		name  string
		build func(*testing.T, bool) Config
	}{
		{name: "public routing", build: func(t *testing.T, _ bool) Config { return loadConfigCase(t, "public-routing") }},
		{name: "mapping insertion order", build: buildMapped},
		{name: "multiple CA mounts", build: buildMultipleCAs},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			firstConfig := test.build(t, false)
			secondConfig := test.build(t, true)
			firstFiles, err := Generate(firstConfig)
			if err != nil {
				t.Fatal(err)
			}
			secondFiles, err := Generate(secondConfig)
			if err != nil {
				t.Fatal(err)
			}
			assertGeneratedFilesEqual(t, firstFiles, secondFiles)

			firstResources, err := GenerateKubernetes(firstConfig)
			if err != nil {
				t.Fatal(err)
			}
			secondResources, err := GenerateKubernetes(secondConfig)
			if err != nil {
				t.Fatal(err)
			}
			firstManifest, err := firstResources.YAML()
			if err != nil {
				t.Fatal(err)
			}
			secondManifest, err := secondResources.YAML()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(firstManifest, secondManifest) {
				t.Fatal("Kubernetes manifest changed with map insertion order")
			}
		})
	}
}

func resourceMap(entries []struct{ name, value string }, reverse bool) map[string]string {
	values := make(map[string]string, len(entries))
	for i := range entries {
		index := i
		if reverse {
			index = len(entries) - i - 1
		}
		values[entries[index].name] = entries[index].value
	}
	return values
}

func assertGeneratedFilesEqual(t testing.TB, left, right map[string][]byte) {
	t.Helper()
	if len(left) != len(right) {
		t.Fatalf("generated file counts differ: %d and %d", len(left), len(right))
	}
	for name, contents := range left {
		other, ok := right[name]
		if !ok || !bytes.Equal(contents, other) {
			t.Fatalf("generated file %q differs", name)
		}
	}
}

func TestGenerateUsesAPIBindingOrder(t *testing.T) {
	config, err := Load(strings.NewReader(readFixture(t, "public-routing/config.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	config.APIs = append(config.APIs, API{
		Name: "broad", Upstream: config.APIs[0].Upstream,
		Routes: []Route{{Methods: []string{"POST"}, Path: PathMatch{Prefix: "/metrics/"}}},
	})
	for _, order := range [][]string{{"broad", "metrics"}, {"metrics", "broad"}} {
		config.Servers[0].APIs = order
		files, err := Generate(config)
		if err != nil {
			t.Fatal(err)
		}
		bootstrap := decodeBootstrap(t, files["envoy.yaml"])
		manager := decodeHTTPManager(t, bootstrap.StaticResources.Listeners[0].FilterChains[0])
		routes := manager.GetRouteConfig().VirtualHosts[0].Routes
		for i, apiName := range order {
			if got := routes[i].GetRoute().GetCluster(); got != "api-"+apiName {
				t.Fatalf("route %d cluster = %s, want api-%s", i, got, apiName)
			}
		}
	}
}

func decodeHTTPManager(t testing.TB, chain *listener.FilterChain) *hcm.HttpConnectionManager {
	t.Helper()
	var manager hcm.HttpConnectionManager
	if err := chain.Filters[0].GetTypedConfig().UnmarshalTo(&manager); err != nil {
		t.Fatal(err)
	}
	return &manager
}

func decodeBootstrap(t testing.TB, data []byte) *bootstrap.Bootstrap {
	t.Helper()
	var document map[string]any
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatalf("decode YAML: %v", err)
	}
	jsonData, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("encode JSON: %v", err)
	}
	var config bootstrap.Bootstrap
	if err := protojson.Unmarshal(jsonData, &config); err != nil {
		t.Fatalf("decode Envoy bootstrap: %v", err)
	}
	return &config
}

func decodeTLSSecret(t *testing.T, data []byte) *tls.Secret {
	t.Helper()
	var document map[string]any
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatalf("decode TLS secret YAML: %v", err)
	}
	resources, ok := document["resources"].([]any)
	if !ok || len(resources) != 1 {
		t.Fatalf("TLS SDS resources = %#v, want one resource", document["resources"])
	}
	resourceData, err := json.Marshal(resources[0])
	if err != nil {
		t.Fatalf("encode TLS SDS resource JSON: %v", err)
	}
	var resource anypb.Any
	if err := protojson.Unmarshal(resourceData, &resource); err != nil {
		t.Fatalf("decode packed TLS SDS resource: %v", err)
	}
	var secret tls.Secret
	if err := resource.UnmarshalTo(&secret); err != nil {
		t.Fatalf("decode TLS secret: %v", err)
	}
	return &secret
}
