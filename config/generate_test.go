package config

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	bootstrap "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"go.yaml.in/yaml/v3"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestGenerateBuildsNamedAPIClustersAndRoutes(t *testing.T) {
	config, err := Load(strings.NewReader(exampleConfig))
	if err != nil {
		t.Fatal(err)
	}
	config.APIs = append(config.APIs, API{
		Name:   "logs",
		Method: "POST",
		Path:   "/logs/otlp/v1/logs",
		Upstream: Upstream{
			Address: "loki",
			Port:    3100,
			Path:    "/otlp/v1/logs",
		},
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
	if got := routes[0].GetRoute().GetPrefixRewrite(); got != "/api/v1/receive" {
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
	config, err := Load(strings.NewReader(exampleConfig))
	if err != nil {
		t.Fatal(err)
	}
	config.APIs[0].Method = "GET"
	config.APIs = append(config.APIs, API{
		Name:     "metrics-write",
		Method:   "POST",
		Path:     config.APIs[0].Path,
		Upstream: config.APIs[0].Upstream,
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

func TestGenerateRejectsInvalidConfiguration(t *testing.T) {
	config, err := Load(strings.NewReader(exampleConfig))
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
