package gateway

import (
	"regexp"
	"strings"
	"testing"

	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
)

func TestGeneratedAccessListsShareRoute(t *testing.T) {
	c := loadConfigCase(t, "access-control")
	c.Servers[0].APIs[0].Access[0].Match.Headers = []gatewayapi.MatchExpression{
		{Name: "X-Tenant", Expression: "in", Value: &gatewayapi.MatchValue{IsList: true, Items: []string{"tenant.a", "tenant+b"}}},
		{Name: "X-Region", Expression: "in", Value: &gatewayapi.MatchValue{IsList: true, Items: []string{"eu", "us"}}},
		{Name: "X-Mode", Expression: "equals", Value: &gatewayapi.MatchValue{Text: "write"}},
		{Name: "X-Ready", Expression: "present"},
	}
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	host := firstHTTPManager(t, files.EnvoyBootstrap.Contents).GetRouteConfig().GetVirtualHosts()[0]
	count := 0
	for _, generated := range host.Routes {
		if strings.HasPrefix(generated.Name, "api-0-write-route-0-access-0-match-") {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("generated access routes = %d, want 1", count)
	}
	generated := namedRoute(host.Routes, "api-0-write-route-0-access-0-match-0")
	patterns := make(map[string]*regexp.Regexp)
	var exact, present bool
	for _, header := range generated.Match.Headers {
		switch header.Name {
		case "x-mode":
			exact = header.GetStringMatch().GetExact() == "write"
		case "x-ready":
			present = header.GetPresentMatch()
		case "x-tenant", "x-region":
			pattern := header.GetStringMatch().GetSafeRegex().GetRegex()
			if pattern == "" {
				t.Fatalf("header %q has no list matcher", header.Name)
			}
			patterns[header.Name] = regexp.MustCompile(pattern)
		}
	}
	if !exact || !present || len(patterns) != 2 {
		t.Fatal("route did not preserve all header conditions")
	}
	for _, test := range []struct {
		tenant, region string
		want           bool
	}{
		{"tenant.a", "eu", true}, {"tenant.a", "us", true},
		{"tenant+b", "eu", true}, {"tenant+b", "us", true},
		{"tenantXa", "eu", false}, {"tenantb", "eu", false},
		{"tenant.a", "europe", false}, {"tenant.a", "", false},
		{"prefix-tenant.a", "eu", false}, {"tenant.a-extra", "eu", false},
		{"Tenant.a", "eu", false}, {"", "eu", false},
	} {
		got := patterns["x-tenant"].MatchString(test.tenant) && patterns["x-region"].MatchString(test.region)
		if got != test.want {
			t.Errorf("tenant %q, region %q matched = %t, want %t", test.tenant, test.region, got, test.want)
		}
	}
}

func TestAccessHeaderListsUseBoundedMatchers(t *testing.T) {
	for _, test := range []struct {
		name      string
		values    []string
		wantCount int
		wantRegex bool
	}{
		{"one value", []string{"tenant-a"}, 1, false},
		{"literal metacharacters", []string{"a.*", "left|right", "(a)", `a\b`}, 1, true},
		{"Unicode literals", []string{"\u00e9", "\u754c"}, 1, true},
		{"at byte budget", []string{strings.Repeat("a", 28), strings.Repeat("b", 29)}, 1, true},
		{"over byte budget", []string{strings.Repeat("a", 28), strings.Repeat("b", 30)}, 2, false},
		{"long literals", []string{strings.Repeat("a", 200), strings.Repeat("b", 200)}, 2, false},
		{"quoted literals exceed budget", []string{strings.Repeat(".", 15), strings.Repeat("+", 15)}, 2, false},
		{"large list", []string{"tenant-a", "tenant-b", "tenant-c", "tenant-d", "tenant-e", "tenant-f", "tenant-g"}, 7, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			headers := accessHeaderMatchers(gatewayapi.MatchExpression{Name: "X-Tenant", Expression: "in", Value: &gatewayapi.MatchValue{IsList: true, Items: test.values}})
			if len(headers) != test.wantCount {
				t.Fatalf("header matchers = %d, want %d", len(headers), test.wantCount)
			}
			for _, value := range test.values {
				matches := 0
				for _, header := range headers {
					if header.Name != "x-tenant" {
						t.Fatalf("header name = %q", header.Name)
					}
					match := header.GetStringMatch()
					pattern := match.GetSafeRegex().GetRegex()
					if (pattern != "") != test.wantRegex {
						t.Fatalf("regex = %q, want regex = %t", pattern, test.wantRegex)
					}
					if match.GetExact() == value || pattern != "" && regexp.MustCompile(pattern).MatchString(value) {
						matches++
					}
				}
				if matches != 1 {
					t.Errorf("value %q matches %d routes, want 1", value, matches)
				}
			}
		})
	}
}

func TestAccessHeaderCombinationsCompactEachListIndependently(t *testing.T) {
	combinations := accessHeaderCombinations(gatewayapi.AccessMatch{Headers: []gatewayapi.MatchExpression{
		{Name: "X-Tenant", Expression: "in", Value: &gatewayapi.MatchValue{IsList: true, Items: []string{strings.Repeat("a", 100), strings.Repeat("b", 100)}}},
		{Name: "X-Region", Expression: "in", Value: &gatewayapi.MatchValue{IsList: true, Items: []string{"eu", "us"}}},
	}})
	if len(combinations) != 2 {
		t.Fatalf("header combinations = %d, want 2", len(combinations))
	}
	for index, headers := range combinations {
		if len(headers) != 2 || headers[0].Name != "x-region" || headers[0].GetStringMatch().GetSafeRegex().GetRegex() != "^(?:eu|us)$" {
			t.Fatalf("combination %d lost the compact region matcher", index)
		}
		if got := headers[1].GetStringMatch().GetExact(); got != strings.Repeat(string(rune('a'+index)), 100) {
			t.Fatalf("combination %d tenant = %q", index, got)
		}
	}
}

func TestGeneratedRouteMatchesWholeMethods(t *testing.T) {
	config := loadConfigCase(t, "route-lists")
	files, err := Generate(config)
	if err != nil {
		t.Fatal(err)
	}
	manager := firstGeneratedHTTPManager(t, files.EnvoyBootstrap.Contents)
	generated := manager.GetRouteConfig().GetVirtualHosts()[0].GetRoutes()[0]
	pattern := generated.GetMatch().GetHeaders()[0].GetStringMatch().GetSafeRegex().GetRegex()
	if pattern == "" {
		t.Fatal("route has no matcher for multiple methods")
	}
	methods, err := regexp.Compile(pattern)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		method string
		want   bool
	}{
		{"GET", true}, {"POST", true}, {"PUT", false}, {"HEAD", false},
		{"GETPOST", false}, {"XGET", false}, {"POSTX", false}, {"get", false},
	} {
		t.Run(test.method, func(t *testing.T) {
			if got := methods.MatchString(test.method); got != test.want {
				t.Fatalf("method %q matched = %t, want %t", test.method, got, test.want)
			}
		})
	}
}

func TestLoadRejectsMissingRouteMethods(t *testing.T) {
	input := `version: 1
servers:
- hostname: auth.example.com
  apis:
  - name: metrics
    public: true
apis:
- name: metrics
  upstream:
    address: thanos-receive
    port: 19291
  routes:
  - path:
      expression: equals
      value: "/metrics/api/v1/receive"
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
		{name: "multiple path matchers", want: "apis[0].routes[0].path", edit: func(c *gatewayapi.Config) {
			c.APIs[0].Routes[0].Path.ValueFrom = &gatewayapi.SourceReference{Attribute: new("tenant_id")}
		}},
		{name: "invalid path regex", want: "apis[0].routes[0].path.value", edit: func(c *gatewayapi.Config) {
			c.APIs[0].Routes[0].Path.Expression = gatewayapi.ExpressionRegex
			c.APIs[0].Routes[0].Path.Value.Text = "["
		}},
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
          expression: equals
          value: /metrics/api/v1/receive
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
	config.Servers = append(config.Servers, gatewayapi.Server{Hostname: "other.example.com", APIs: []gatewayapi.APIBinding{{Name: "other", Public: true}}})
	if err := Validate(config); err != nil {
		t.Fatalf("same path on separate servers rejected: %v", err)
	}
	config.Servers[0].APIs = append(config.Servers[0].APIs, gatewayapi.APIBinding{Name: "other", Public: true})
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
			{Hostname: "auth.example.com", APIs: []gatewayapi.APIBinding{{Name: "metrics", Public: true}}},
			{Hostname: "tls.example.com", TLSConfig: &gatewayapi.ServerTLS{}, APIs: []gatewayapi.APIBinding{{Name: "metrics", Public: true}}},
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
		{name: "unknown API", field: "servers[0].apis", edit: func(c *gatewayapi.Config) {
			c.Servers[0].APIs = []gatewayapi.APIBinding{{Name: "unknown", Public: true}}
		}},
		{name: "duplicate API binding", field: "servers[0].apis", edit: func(c *gatewayapi.Config) {
			c.Servers[0].APIs = []gatewayapi.APIBinding{{Name: "metrics", Public: true}, {Name: "metrics", Public: true}}
		}},
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
	config.Servers[0].APIs = append(config.Servers[0].APIs, gatewayapi.APIBinding{Name: "metrics-write", Public: true})
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
	if len(routes) != 7 {
		t.Fatalf("route count = %d, want 7", len(routes))
	}

	query := routes[0]
	if got := query.GetMatch().GetSafeRegex().GetRegex(); got != `^/metrics/api/v1/(query|query_range)$` {
		t.Fatalf("query regex = %q", got)
	}
	if got := query.GetMatch().GetHeaders()[0].GetStringMatch().GetSafeRegex().GetRegex(); got != "^(?:GET|POST)$" {
		t.Fatalf("query methods = %q, want GET and POST", got)
	}
	if got := query.GetRoute().GetCluster(); got != "api-metrics-query" {
		t.Fatalf("query cluster = %q", got)
	}
	regexRewrite := query.GetRoute().GetRegexRewrite()
	if regexRewrite == nil || regexRewrite.GetPattern().GetRegex() != `^/metrics/(.*)$` || regexRewrite.GetSubstitution() != `/\1` {
		t.Fatalf("query rewrite = %#v", regexRewrite)
	}

	prefix := routes[1]
	if got := prefix.GetMatch().GetHeaders()[0].GetStringMatch().GetExact(); got != "GET" {
		t.Fatalf("label method = %q, want exact GET", got)
	}
	if got := prefix.GetMatch().GetPrefix(); got != "/metrics/api/v1/label/" {
		t.Fatalf("label prefix = %q", got)
	}
	if got := prefix.GetRoute().GetPrefixRewrite(); got != "/api/v1/label/" {
		t.Fatalf("label prefix rewrite = %q", got)
	}

	exact := routes[2]
	if got := exact.GetMatch().GetPath(); got != "/metrics/api/v1/labels" {
		t.Fatalf("labels path = %q", got)
	}
	if got := exact.GetRoute().GetPathRewrite(); got != "/api/v1/labels" {
		t.Fatalf("labels path rewrite = %q", got)
	}
	if got := routes[3].GetDirectResponse().GetStatus(); got != 405 {
		t.Fatalf("query wrong method status = %d", got)
	}
	if got := routes[3].GetResponseHeadersToAdd()[0].GetHeader().GetValue(); got != "GET, POST" {
		t.Fatalf("query Allow header = %q", got)
	}
	if got := routes[6].GetDirectResponse().GetStatus(); got != 404 {
		t.Fatalf("not found status = %d", got)
	}
}

func TestPathConditionsRejectUnsupportedOperandsAndExpressions(t *testing.T) {
	for _, test := range []struct {
		name, want string
		path       gatewayapi.PathMatch
	}{
		{"named path", ".path.name", gatewayapi.PathMatch{Name: "path", Expression: "equals", Value: &gatewayapi.MatchValue{Text: "/status"}}},
		{"reference", ".path.value", gatewayapi.PathMatch{Expression: "equals", ValueFrom: &gatewayapi.SourceReference{Attribute: new("tenant_id")}}},
		{"list", ".path.value", gatewayapi.PathMatch{Expression: "equals", Value: &gatewayapi.MatchValue{IsList: true, Items: []string{"/status"}}}},
		{"header expression", ".path.expression", gatewayapi.PathMatch{Expression: "present", Value: &gatewayapi.MatchValue{Text: "/status"}}},
		{"scalar membership", ".path.expression", gatewayapi.PathMatch{Expression: "in", Value: &gatewayapi.MatchValue{Text: "/status"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := loadConfigCase(t, "public-routing")
			c.APIs[0].Routes[0].Path = test.path
			if err := Validate(c); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validation = %v, want %q", err, test.want)
			}
		})
	}
}
