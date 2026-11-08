package gateway

import (
	"strings"
	"testing"

	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
)

func TestLoadRejectsMissingRouteMethods(t *testing.T) {
	input := `version: 1
servers:
  - hostname: auth.example.com
    apis: [metrics]
apis:
  - name: metrics
    upstream:
      address: thanos-receive
      port: 19291
    routes:
      - path:
          exact: /metrics/api/v1/receive
`
	if _, err := Load(strings.NewReader(input)); err == nil || !strings.Contains(err.Error(), ".methods") {
		t.Fatalf("Load error = %v, want a missing route methods error", err)
	}
}

func TestValidateRejectsInvalidRouteConfiguration(t *testing.T) {
	routeListConfig := readFixture(t, "route-lists/config.yaml")
	tests := []struct {
		name string
		want string
		edit func(*gatewayapi.Config)
	}{
		{name: "multiple path matchers", want: "apis[0].routes[0].path", edit: func(c *gatewayapi.Config) { c.APIs[0].Routes[0].Path.Prefix = "/metrics/" }},
		{name: "invalid path regex", want: "apis[0].routes[0].path.regex", edit: func(c *gatewayapi.Config) { c.APIs[0].Routes[0].Path.Regex = "[" }},
		{name: "duplicate method", want: "apis[0].routes[0].methods", edit: func(c *gatewayapi.Config) { c.APIs[0].Routes[0].Methods = []string{"GET", "GET"} }},
		{name: "missing path matcher", want: "apis[0].routes[0].path", edit: func(c *gatewayapi.Config) { c.APIs[0].Routes[0].Path = gatewayapi.PathMatch{} }},
		{name: "multiple rewrite types", want: "apis[0].routes[0].rewrite", edit: func(c *gatewayapi.Config) {
			c.APIs[0].Routes[0].Rewrite = &gatewayapi.PathRewrite{Path: "/query", Prefix: "/api/"}
		}},
		{name: "duplicate route", want: "duplicate API route", edit: func(c *gatewayapi.Config) { c.APIs[0].Routes = append(c.APIs[0].Routes, c.APIs[0].Routes[0]) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := loadTestConfig(t, routeListConfig, "valid route baseline")
			test.edit(&config)
			if err := Validate(config); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validation error = %v, want %q", err, test.want)
			}
		})
	}
}

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

func TestGenerateAllowsMethodsOnOnePath(t *testing.T) {
	config, err := Load(strings.NewReader(readFixture(t, "public-routing/config.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	secondRoute := config.APIs[0].Routes[0]
	config.APIs[0].Routes[0].Methods = []string{"GET"}
	secondRoute.Methods = []string{"POST"}
	config.APIs = append(config.APIs, gatewayapi.API{
		Name:     "metrics-write",
		Upstream: config.APIs[0].Upstream,
		Routes:   []gatewayapi.Route{secondRoute},
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
