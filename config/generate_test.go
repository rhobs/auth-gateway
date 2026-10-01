package config

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	bootstrap "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"go.yaml.in/yaml/v3"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestGenerateBuildsNamedAPIClustersAndRoutes(t *testing.T) {
	config, err := Load(strings.NewReader(readFixture(t, "example.yaml")))
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

	second, err := Generate(config)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(files["envoy.yaml"], second["envoy.yaml"]) {
		t.Fatal("generation is not deterministic")
	}
}

func TestGenerateAllowsMethodsOnOnePath(t *testing.T) {
	config, err := Load(strings.NewReader(readFixture(t, "example.yaml")))
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
	config, err := Load(strings.NewReader(readFixture(t, "route-list.yaml")))
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
	config, err := Load(strings.NewReader(readFixture(t, "route-list.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	config.Listener.HTTPHosts = []string{"auth.example.com"}
	config.Listener.HTTPSHosts = []string{"mts.auth.example.com"}
	config.ServerTLS = &ServerTLS{
		Certificate: "/etc/gateway-certs/tls.crt",
		PrivateKey:  "/etc/gateway-certs/tls.key",
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
	if len(certificates) != 1 || certificates[0].GetName() != serverTLSSecretName {
		t.Fatalf("server certificate SDS config = %#v", certificates)
	}
	if got := certificates[0].GetSdsConfig().GetPathConfigSource().GetPath(); got != "/etc/auth-gateway/"+serverTLSResourceFilename {
		t.Fatalf("certificate SDS resource path = %q", got)
	}

	secret := decodeTLSSecret(t, files[serverTLSResourceFilename])
	certificate := secret.GetTlsCertificate()
	if secret.GetName() != serverTLSSecretName || certificate == nil {
		t.Fatalf("generated SDS resource = %#v", secret)
	}
	if got := certificate.GetCertificateChain().GetFilename(); got != config.ServerTLS.Certificate {
		t.Fatalf("certificate file = %q", got)
	}
	if got := certificate.GetPrivateKey().GetFilename(); got != config.ServerTLS.PrivateKey {
		t.Fatalf("private key file = %q", got)
	}
	if got := certificate.GetWatchedDirectory().GetPath(); got != "/etc/gateway-certs" {
		t.Fatalf("watched certificate directory = %q", got)
	}
}

func TestGenerateRejectsInvalidConfiguration(t *testing.T) {
	config, err := Load(strings.NewReader(readFixture(t, "example.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	config.Version = 2
	if _, err := Generate(config); err == nil {
		t.Fatal("Generate accepted an unsupported config version")
	}
}

func decodeBootstrap(t *testing.T, data []byte) *bootstrap.Bootstrap {
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
