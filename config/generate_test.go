package config

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	accesslog "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	bootstrap "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	rbac "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	stream "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/stream/v3"
	setfilterstatecommon "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/common/set_filter_state/v3"
	headermutation "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/header_mutation/v3"
	jwt "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/jwt_authn/v3"
	httpRBAC "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rbac/v3"
	router "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	setfilterstate "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"github.com/google/go-cmp/cmp"
	"go.yaml.in/yaml/v3"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"
)

var updateGoldens = flag.Bool("update", false, "update generated reference files")

func TestRequiredHeaderRBACRulesRejectsEmptyMappings(t *testing.T) {
	_, err := requiredHeaderRBACRules(nil)
	if err == nil || !strings.Contains(err.Error(), "at least one request header mapping") {
		t.Fatalf("required header rules error = %v, want empty mapping error", err)
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
	bootstrap := files.EnvoyBootstrap.Contents
	if files.EnvoyBootstrap.Path != EnvoyBootstrapPath || len(bootstrap) == 0 {
		t.Fatal("playground bootstrap is missing")
	}
	if len(files.All()) != 1 {
		t.Fatalf("playground needs a file layout for %d generated files", len(files.All()))
	}
	checkReference(t, filepath.Join("..", "playground", "envoy.yaml.golden"), bootstrap)

}

func TestGeneratedErrorAccessLogUsesQueryFreePath(t *testing.T) {
	c := loadConfigCase(t, "public-routing")
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	generated := decodeBootstrap(t, files.EnvoyBootstrap.Contents)
	manager := decodeHTTPManager(t, generated.StaticResources.Listeners[0].FilterChains[0])
	logs := manager.GetAccessLog()
	if len(logs) != 1 {
		t.Fatalf("access logs = %d, want one", len(logs))
	}
	comparison := logs[0].GetFilter().GetStatusCodeFilter().GetComparison()
	if comparison.GetOp() != accesslog.ComparisonFilter_GE || comparison.GetValue().GetDefaultValue() != 400 {
		t.Fatalf("error access log status filter = %v, want >= 400", comparison)
	}
	var stdout stream.StdoutAccessLog
	if err := logs[0].GetTypedConfig().UnmarshalTo(&stdout); err != nil {
		t.Fatal(err)
	}
	format := stdout.GetLogFormat().GetJsonFormat()
	if format == nil {
		t.Fatal("error access log has no JSON format")
	}
	if got := format.GetFields()["path"].GetStringValue(); got != "%PATH(NQ)%" {
		t.Fatalf("error access log path format = %q, want %%PATH(NQ)%%", got)
	}
}

func TestRewrittenRouteUsesEnvoyOriginalPathHeader(t *testing.T) {
	c := loadConfigCase(t, "public-routing")
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	generated := decodeBootstrap(t, files.EnvoyBootstrap.Contents)
	manager := decodeHTTPManager(t, generated.StaticResources.Listeners[0].FilterChains[0])
	route := manager.GetRouteConfig().GetVirtualHosts()[0].GetRoutes()[0]
	if got := route.GetRequestHeadersToAdd(); len(got) != 0 {
		t.Fatalf("rewritten route adds request headers: %v", got)
	}
	filters := manager.GetHttpFilters()
	var routerConfig router.Router
	if err := filters[len(filters)-1].GetTypedConfig().UnmarshalTo(&routerConfig); err != nil {
		t.Fatal(err)
	}
	if routerConfig.GetSuppressEnvoyHeaders() {
		t.Fatal("router suppresses Envoy headers")
	}

	var controls headermutation.HeaderMutation
	if err := filters[0].GetTypedConfig().UnmarshalTo(&controls); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range controls.GetMutations().GetRequestMutations() {
		if mutation.GetRemove() == "x-envoy-original-path" {
			return
		}
	}
	t.Fatal("request controls do not remove client-supplied x-envoy-original-path")
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
	bootstrapConfig := decodeBootstrap(t, files.EnvoyBootstrap.Contents)
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
	bootstrapConfig := decodeBootstrap(t, files.EnvoyBootstrap.Contents)
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

func TestGenerationIsDeterministic(t *testing.T) {
	buildAttributes := func(t *testing.T, reverse bool) Config {
		t.Helper()
		c := loadConfigCase(t, "jwt-auth-with-attributes")
		sources := c.Authenticators[0].Attributes
		names := []string{"tenant_id", "writer_id"}
		if reverse {
			slices.Reverse(names)
		}
		c.Authenticators[0].Attributes = make(map[string]AttributeSource, len(names))
		for _, name := range names {
			c.Authenticators[0].Attributes[name] = sources[name]
		}
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
		{name: "attribute insertion order", build: buildAttributes},
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

func assertGeneratedFilesEqual(t testing.TB, left, right GeneratedFiles) {
	t.Helper()
	leftFiles := left.All()
	rightFiles := right.All()
	if len(leftFiles) != len(rightFiles) {
		t.Fatalf("generated file counts differ: %d and %d", len(leftFiles), len(rightFiles))
	}
	for i, file := range leftFiles {
		other := rightFiles[i]
		if file.Path != other.Path || !bytes.Equal(file.Contents, other.Contents) {
			t.Fatalf("generated file %q differs from %q", file.Path, other.Path)
		}
	}
}

func generatedContentsByPath(t testing.TB, files GeneratedFiles, filePath string) []byte {
	t.Helper()
	for _, file := range files.All() {
		if file.Path == filePath {
			return file.Contents
		}
	}
	t.Fatalf("generated file %q is missing", filePath)
	return nil
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

func TestJWTHeaderOnlyGrantRequiresNamedVerifiedIssuer(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-multiple-issuers")
	c.Authenticators[0].Attributes["requested_tenant"] = AttributeSource{Header: new("X-Tenant")}
	c.AuthorizationPolicies[0].Grants[0].Attributes = map[string][]string{"requested_tenant": {"customer-a"}}
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	manager := firstHTTPManager(t, files.EnvoyBootstrap.Contents)
	names := httpFilterNames(manager)
	if slices.Index(names, "envoy.filters.http.header_to_metadata") < 0 ||
		slices.Index(names, "envoy.filters.http.set_filter_state") >= 0 {
		t.Fatalf("header-only grant needs capture but no working attributes: %v", names)
	}
	grant := resolveTestConfig(t, c).toGrantPrincipal(c.AuthorizationPolicies[0].Grants[0]).GetAndIds().GetIds()
	if len(grant) != 2 {
		t.Fatalf("header-only JWT grant principals = %#v", grant)
	}
	header := grant[0].GetSourcedMetadata().GetMetadataMatcher()
	issuer := grant[1].GetSourcedMetadata().GetMetadataMatcher()
	if header.GetFilter() != "auth_gateway.request_headers" ||
		!slices.Equal(metadataMatcherPath(header.GetPath()), []string{"x-tenant"}) ||
		header.GetValue().GetStringMatch().GetExact() != "customer-a" ||
		issuer.GetFilter() != "envoy.filters.http.jwt_authn" ||
		!slices.Equal(metadataMatcherPath(issuer.GetPath()), []string{"issuer-one", "iss"}) ||
		issuer.GetValue().GetStringMatch().GetExact() != "https://issuer-one.jwt.test" {
		t.Fatalf("header-only JWT grant does not bind the named issuer: %#v", grant)
	}
}

func TestJWTProviderClustersAndTrust(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-multiple-issuers")
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	generated := decodeBootstrap(t, files.EnvoyBootstrap.Contents)
	manager := decodeHTTPManager(t, generated.StaticResources.Listeners[0].FilterChains[0])

	var jwtConfig jwt.JwtAuthentication
	var jwtFilter *hcm.HttpFilter
	for _, filter := range manager.HttpFilters {
		if filter.Name == jwtAuthnFilterName {
			jwtFilter = filter
			break
		}
	}
	if jwtFilter == nil {
		t.Fatal("JWT filter is missing")
	}
	if err := jwtFilter.GetTypedConfig().UnmarshalTo(&jwtConfig); err != nil {
		t.Fatal(err)
	}
	if len(jwtConfig.Providers) != 2 || len(jwtConfig.RequirementMap) != 2 {
		t.Fatalf("JWT provider/requirement counts = %d/%d", len(jwtConfig.Providers), len(jwtConfig.RequirementMap))
	}
	for name, issuer := range map[string]string{
		"issuer-one": "https://issuer-one.jwt.test",
		"issuer-two": "https://issuer-two.jwt.test",
	} {
		provider := jwtConfig.Providers[name]
		if provider == nil || provider.Issuer != issuer || provider.PayloadInMetadata != name ||
			!provider.RequireExpiration || provider.Forward || len(provider.FromHeaders) != 1 ||
			provider.FromHeaders[0].Name != "Authorization" || provider.FromHeaders[0].ValuePrefix != "Bearer " {
			t.Fatalf("JWT provider %q = %#v", name, provider)
		}
		remote := provider.GetRemoteJwks()
		if remote == nil || remote.HttpUri == nil || remote.HttpUri.GetCluster() != jwksClusterName(name) {
			t.Fatalf("JWT provider %q has no dedicated JWKS cluster", name)
		}
		if remote.CacheDuration == nil {
			t.Fatalf("JWT provider %q has no JWKS cache duration", name)
		}
		if got, want := remote.CacheDuration.AsDuration(), 5*time.Minute; got != want {
			t.Fatalf("JWT provider %q cache duration = %s, want default %s", name, got, want)
		}
	}
	if jwtConfig.RequirementMap[serverJWTRequirementName(1)].GetProviderName() != "issuer-one" {
		t.Fatalf("issuer-restricted server JWT requirement = %#v", jwtConfig.RequirementMap[serverJWTRequirementName(1)])
	}

	clusters := make(map[string]*cluster.Cluster, len(generated.StaticResources.Clusters))
	for _, item := range generated.StaticResources.Clusters {
		clusters[item.Name] = item
	}
	for _, name := range []string{"issuer-one", "issuer-two"} {
		jwks := clusters[jwksClusterName(name)]
		if jwks == nil || jwks.TransportSocket == nil {
			t.Fatalf("missing TLS JWKS cluster for %q", name)
		}
		wantFamily := cluster.Cluster_V4_ONLY
		if name == "issuer-two" {
			wantFamily = cluster.Cluster_V6_ONLY
		}
		if got := jwks.GetDnsLookupFamily(); got != wantFamily {
			t.Fatalf("JWKS cluster %q DNS lookup family = %s, want %s", name, got, wantFamily)
		}
		var upstream tls.UpstreamTlsContext
		if err := jwks.TransportSocket.GetTypedConfig().UnmarshalTo(&upstream); err != nil {
			t.Fatal(err)
		}
		if upstream.GetSni() == "" || upstream.GetCommonTlsContext().GetValidationContext().GetTrustedCa().GetFilename() == "" {
			t.Fatalf("JWKS TLS validation is not enabled for %q", name)
		}
	}
	if got, want := len(generated.StaticResources.Clusters), len(c.APIs)+len(jwtConfig.Providers); got != want {
		t.Fatalf("upstream/JWKS cluster count = %d, want %d", got, want)
	}
}

func TestJWTAuthorizationReadsOriginalClaimsFromNamedProvider(t *testing.T) {
	c := resolveTestConfig(t, loadConfigCase(t, "jwt-auth-multiple-issuers"))
	rules := c.toServerRBACRules(c.servers[0])
	policy := rules.Policies["api-metrics"]
	if policy == nil || len(policy.Principals) != 1 {
		t.Fatalf("API authorization policy = %#v", policy)
	}
	grants := policy.Principals[0].GetOrIds().Ids
	if len(grants) != 2 {
		t.Fatalf("provider grant count = %d, want one for each issuer", len(grants))
	}
	gotValues := make(map[string]string, len(grants))
	for _, grant := range grants {
		claim := grant.GetSourcedMetadata()
		if claim == nil || claim.MetadataSource != rbac.MetadataSource_DYNAMIC || claim.GetMetadataMatcher().GetFilter() != "envoy.filters.http.jwt_authn" {
			t.Fatalf("grant does not use verified JWT metadata: %#v", grant)
		}
		var path []string
		for _, segment := range claim.GetMetadataMatcher().GetPath() {
			path = append(path, segment.GetKey())
		}
		if len(path) != 3 || path[1] != "organization" || path[2] != "id" {
			t.Fatalf("grant claim path = %v, want provider.organization.id", path)
		}
		valueMatcher := claim.GetMetadataMatcher().GetValue()
		branches := valueMatcher.GetOrMatch().GetValueMatchers()
		if len(branches) != 2 || branches[0].GetStringMatch() == nil || branches[1].GetListMatch() == nil {
			t.Fatalf("claim matcher = %#v, want scalar and list branches", valueMatcher)
		}
		listValueMatcher := branches[1].GetListMatch().GetOneOf()
		if listValueMatcher == nil || listValueMatcher.GetStringMatch() == nil {
			t.Fatalf("list matcher = %#v, want an exact string member matcher", branches[1].GetListMatch())
		}
		value := branches[0].GetStringMatch().GetExact()
		if listValueMatcher.GetStringMatch().GetExact() != value {
			t.Fatalf("scalar and list match values = %q and %q", value, listValueMatcher.GetStringMatch().GetExact())
		}
		gotValues[path[0]] = value
	}
	if !reflect.DeepEqual(gotValues, map[string]string{"issuer-one": "customer-a", "issuer-two": "customer-b"}) {
		t.Fatalf("raw provider grants = %v", gotValues)
	}

	config, err := c.toJWTFilterConfig()
	if err != nil {
		t.Fatal(err)
	}
	any := config.RequirementMap[serverJWTRequirementName(0)].GetRequiresAny().Requirements
	if len(any) != 2 || any[0].GetProviderName() != "issuer-one" || any[1].GetProviderName() != "issuer-two" {
		t.Fatalf("alternative issuer requirement = %#v", any)
	}
}

func TestJWTAuthorizationMatchesAnyAllowedListClaimValue(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth")
	c.Authenticators[0].Attributes["my_list"] = AttributeSource{ClaimPath: []string{"x", "my_list"}}
	grant := c.AuthorizationPolicies[0].Grants[0]
	grant.Attributes = map[string][]string{"my_list": {"y", "z"}}

	principal := resolveTestConfig(t, c).toGrantPrincipal(grant)
	claim := principal.GetSourcedMetadata()
	if claim == nil {
		t.Fatalf("grant principal = %#v, want a JWT metadata matcher", principal)
	}
	var gotPath []string
	for _, segment := range claim.GetMetadataMatcher().GetPath() {
		gotPath = append(gotPath, segment.GetKey())
	}
	if !slices.Equal(gotPath, []string{"internal-jwt", "x", "my_list"}) {
		t.Fatalf("claim path = %v, want internal-jwt.x.my_list", gotPath)
	}

	valueMatcher := claim.GetMetadataMatcher().GetValue()
	branches := valueMatcher.GetOrMatch().GetValueMatchers()
	if len(branches) != 2 || branches[0].GetOrMatch() == nil || branches[1].GetListMatch() == nil {
		t.Fatalf("claim matcher = %#v, want scalar allowlist and list-member branches", valueMatcher)
	}
	scalarValues := branches[0].GetOrMatch().GetValueMatchers()
	listMatcher := branches[1].GetListMatch().GetOneOf()
	if listMatcher == nil || listMatcher.GetOrMatch() == nil {
		t.Fatalf("list matcher = %#v, want an allowlist matcher for list members", branches[1].GetListMatch())
	}
	listValues := listMatcher.GetOrMatch().GetValueMatchers()
	if len(scalarValues) != 2 || len(listValues) != 2 {
		t.Fatalf("scalar/list allowlist lengths = %d/%d, want 2/2", len(scalarValues), len(listValues))
	}
	for i, want := range []string{"y", "z"} {
		if scalarValues[i].GetStringMatch() == nil || scalarValues[i].GetStringMatch().GetExact() != want {
			t.Fatalf("scalar allowlist value %d = %#v, want %q", i, scalarValues[i], want)
		}
		if listValues[i].GetStringMatch() == nil || listValues[i].GetStringMatch().GetExact() != want {
			t.Fatalf("list-member allowlist value %d = %#v, want %q", i, listValues[i], want)
		}
	}
}

func TestConditionalJWTFilterOrder(t *testing.T) {
	plainJWT := []string{requestControlsFilterName, jwtAuthnFilterName, authorizationFilterName, credentialCleanupFilterName, routerFilterName}
	attributesJWT := []string{
		requestControlsFilterName, jwtAuthnFilterName, attributeFilterName, authorizationFilterName,
		requiredHeaderFilterName, credentialCleanupFilterName, headerMutationFilterName, routerFilterName,
	}
	tests := []struct {
		name                  string
		fixture               string
		wantOrder             []string
		wantFiles             []string
		withoutRequestMetrics bool
	}{
		{name: "public", fixture: "public-routing", wantOrder: []string{requestControlsFilterName, routerFilterName}, wantFiles: []string{envoyConfigFilename}},
		{name: "plain JWT", fixture: "jwt-auth", wantOrder: plainJWT, wantFiles: []string{envoyConfigFilename}},
		{name: "direct headers", fixture: "jwt-auth-with-headers", wantOrder: attributesJWT, wantFiles: []string{envoyConfigFilename}},
		{name: "claim attributes", fixture: "jwt-auth-with-attributes", wantOrder: attributesJWT, wantFiles: []string{envoyConfigFilename, "server-certificate-1.yaml"}, withoutRequestMetrics: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := loadConfigCase(t, test.fixture)
			if test.withoutRequestMetrics {
				for i := range c.APIs {
					c.APIs[i].Metrics = nil
				}
			}
			files, err := Generate(c)
			if err != nil {
				t.Fatal(err)
			}
			bootstrap := decodeBootstrap(t, files.EnvoyBootstrap.Contents)
			manager := decodeHTTPManager(t, bootstrap.StaticResources.Listeners[0].FilterChains[0])
			if got := httpFilterNames(manager); !slices.Equal(got, test.wantOrder) {
				t.Fatalf("HTTP filter order = %v, want %v", got, test.wantOrder)
			}
			got := make([]string, 0, len(files.All()))
			for _, file := range files.All() {
				got = append(got, filepath.Base(file.Path))
			}
			slices.Sort(got)
			if !slices.Equal(got, test.wantFiles) {
				t.Fatalf("generated files = %v, want %v", got, test.wantFiles)
			}
		})
	}
}

func TestJWTRequiredHeadersAreRouteScopedAndManaged(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-with-headers")
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	manager := firstHTTPManager(t, files.EnvoyBootstrap.Contents)
	var globalMutation headermutation.HeaderMutation
	for _, filter := range manager.HttpFilters {
		if filter.Name == "envoy.filters.http.header_mutation" {
			if err := filter.GetTypedConfig().UnmarshalTo(&globalMutation); err != nil {
				t.Fatal(err)
			}
		}
	}
	removed := make(map[string]bool)
	for _, mutation := range globalMutation.GetMutations().GetRequestMutations() {
		removed[mutation.GetRemove()] = mutation.GetRemove() != ""
	}
	if len(removed) != 2 || !removed["x-scope-orgid"] || !removed["x-writer-id"] {
		t.Fatalf("managed headers removed = %v", removed)
	}
	var initialized setfilterstate.Config
	for _, filter := range manager.HttpFilters {
		if filter.Name == attributeFilterName {
			if err := filter.GetTypedConfig().UnmarshalTo(&initialized); err != nil {
				t.Fatal(err)
			}
		}
	}
	if len(initialized.OnRequestHeaders) != 2 {
		t.Fatalf("initialized attribute count = %d, want tenant_id and writer_id", len(initialized.OnRequestHeaders))
	}
	for i, name := range []string{"tenant_id", "writer_id"} {
		update := initialized.OnRequestHeaders[i]
		key, ok := update.GetKey().(*setfilterstatecommon.FilterStateValue_ObjectKey)
		value, valueOK := update.GetValue().(*setfilterstatecommon.FilterStateValue_FormatString)
		if !ok || key.ObjectKey != filterStateKey(name) || !valueOK || update.FactoryKey != "envoy.string" || !update.SkipIfEmpty || !value.FormatString.OmitEmptyValues {
			t.Fatalf("initialized attribute %q has unsafe or incomplete filter-state settings: %#v", name, update)
		}
	}

	host := manager.GetRouteConfig().GetVirtualHosts()[0]
	var protected, methodFallback, notFound bool
	for _, generatedRoute := range host.GetRoutes() {
		switch generatedRoute.Name {
		case "api-0-metrics-route-0-method-0":
			protected = true
			headerConfig := generatedRoute.TypedPerFilterConfig["envoy.filters.http.header_mutation"]
			if headerConfig == nil {
				t.Fatal("protected route has no per-route header values")
			}
			var perRoute headermutation.HeaderMutationPerRoute
			if err := headerConfig.UnmarshalTo(&perRoute); err != nil {
				t.Fatal(err)
			}
			values := make(map[string]string)
			for _, mutation := range perRoute.GetMutations().GetRequestMutations() {
				append := mutation.GetAppend()
				if append != nil && append.GetHeader() != nil {
					values[append.GetHeader().GetKey()] = append.GetHeader().GetValue()
				}
			}
			if !reflect.DeepEqual(values, map[string]string{
				"X-Scope-OrgID": "%FILTER_STATE(auth_gateway.attributes.tenant_id:PLAIN)%",
				"X-Writer-ID":   "%FILTER_STATE(auth_gateway.attributes.writer_id:PLAIN)%",
			}) {
				t.Fatalf("per-route header values = %v", values)
			}
			rbacConfig := generatedRoute.TypedPerFilterConfig[requiredHeaderFilterName]
			if rbacConfig == nil {
				t.Fatal("protected route has no required-attribute check")
			}
			var required httpRBAC.RBACPerRoute
			if err := rbacConfig.UnmarshalTo(&required); err != nil {
				t.Fatal(err)
			}
			policy := required.GetRbac().GetRules().GetPolicies()["required-attributes"]
			if policy == nil || len(policy.Principals) != 1 {
				t.Fatalf("required header policy = %#v", policy)
			}
			principals := policy.Principals[0].GetAndIds().Ids
			if len(principals) != 2 {
				t.Fatalf("required header attribute count = %d", len(principals))
			}
			keys := make([]string, 0, len(principals))
			for _, principal := range principals {
				filterState := principal.GetFilterState()
				if filterState.GetStringMatch().GetSafeRegex().GetRegex() != headerValuePattern {
					t.Fatalf("required attribute matcher = %#v", filterState.GetStringMatch())
				}
				keys = append(keys, filterState.GetKey())
			}
			if !reflect.DeepEqual(keys, []string{filterStateKey("tenant_id"), filterStateKey("writer_id")}) {
				t.Fatalf("required header filter-state keys = %v", keys)
			}
		case "method-not-allowed-0":
			methodFallback = true
			if generatedRoute.TypedPerFilterConfig[requiredHeaderFilterName] != nil {
				t.Fatal("method fallback incorrectly requires upstream header values")
			}
		case "not-found":
			notFound = true
			if generatedRoute.TypedPerFilterConfig[requiredHeaderFilterName] != nil {
				t.Fatal("not-found route incorrectly requires upstream header values")
			}
		}
	}
	if !protected || !methodFallback || !notFound {
		t.Fatalf("route cases protected/fallback/not-found = %t/%t/%t", protected, methodFallback, notFound)
	}
}

func TestJWTAuthorizationPolicyCombinationsAreAPIScoped(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-with-attributes")
	effective := resolveTestConfig(t, c)
	rules := effective.toServerRBACRules(effective.servers[0])
	if rules.Policies["api-metrics-write"] == nil || rules.Policies["api-logs"] == nil {
		t.Fatalf("any_of policies did not generate both granted API rules: %#v", rules.Policies)
	}
	metricsGrants := rules.Policies["api-metrics-write"].Principals[0].GetOrIds().Ids
	if len(metricsGrants) != 2 {
		t.Fatalf("metrics API grant principals = %d, want one grant from each issuer", len(metricsGrants))
	}

	c.Servers[0].Authorization = &Authorization{AllOf: []string{"metrics-writers", "logs-writers"}}
	effective = resolveTestConfig(t, c)
	rules = effective.toServerRBACRules(effective.servers[0])
	if rules.Policies["api-metrics-write"] != nil || rules.Policies["api-logs"] != nil {
		t.Fatalf("all_of policies for disjoint APIs granted access: %#v", rules.Policies)
	}
	if rules.Policies["local-responses"] == nil {
		t.Fatal("all_of denied APIs but removed local 404/405 responses")
	}
}

func firstHTTPManager(t testing.TB, data []byte) *hcm.HttpConnectionManager {
	t.Helper()
	generated := decodeBootstrap(t, data)
	for _, chain := range generated.StaticResources.Listeners[0].FilterChains {
		manager := decodeHTTPManager(t, chain)
		if containsFilter(manager, "envoy.filters.http.jwt_authn") {
			return manager
		}
	}
	t.Fatal("no protected HTTP manager was generated")
	return nil
}

func httpFilterNames(manager *hcm.HttpConnectionManager) []string {
	names := make([]string, len(manager.HttpFilters))
	for i, filter := range manager.HttpFilters {
		names[i] = filter.Name
	}
	return names
}

func containsFilter(manager *hcm.HttpConnectionManager, name string) bool {
	for _, filter := range manager.HttpFilters {
		if filter.Name == name {
			return true
		}
	}
	return false
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
