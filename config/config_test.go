package config

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	headermutation "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/header_mutation/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	upstreamhttp "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	"go.yaml.in/yaml/v3"
)

func readTestFile(t testing.TB, name string) string {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read test file %q: %v", name, err)
	}
	return string(data)
}

func readFixture(t testing.TB, name string) string {
	t.Helper()
	return readTestFile(t, filepath.Join("testdata", name))
}

func loadTestConfig(t testing.TB, input, name string) Config {
	t.Helper()
	config, err := Load(strings.NewReader(input))
	if err != nil {
		t.Fatalf("load %s: %v", name, err)
	}
	return config
}

func loadConfigCase(t testing.TB, name string) Config {
	t.Helper()
	return loadTestConfig(t, readFixture(t, filepath.Join(name, "config.yaml")), name+" case")
}

func loadAuthExample(t testing.TB) Config {
	t.Helper()
	return loadTestConfig(t, readTestFile(t, filepath.Join("..", "config.auth.example.yaml")), "auth example")
}

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

func TestLoadRejectsInvalidYAML(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "unknown field", input: "version: 1\nunknown: true\n", want: "field unknown not found"},
		{name: "duplicate field", input: "version: 1\nversion: 1\n", want: "already defined"},
		{name: "multiple documents", input: "version: 1\n---\nversion: 1\n", want: "expected exactly one YAML document"},
		{name: "invalid syntax", input: "version: [\n", want: "did not find expected node content"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Load(strings.NewReader(test.input)); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Load error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestDurationYAMLContract(t *testing.T) {
	for _, value := range []string{"250ms", "5s", "5m", "1.5ms", "0s"} {
		var parsed Duration
		if err := yaml.Unmarshal([]byte(value), &parsed); err != nil {
			t.Fatalf("parse %q: %v", value, err)
		}
		encoded, err := yaml.Marshal(parsed)
		if err != nil {
			t.Fatal(err)
		}
		var roundtrip Duration
		if err := yaml.Unmarshal(encoded, &roundtrip); err != nil || parsed != roundtrip {
			t.Fatalf("duration roundtrip %q: %v, %v", value, roundtrip, err)
		}
	}

	for name, input := range map[string]string{
		"number":     "5",
		"empty":      `""`,
		"negative":   "-1s",
		"sub-ms":     "500us",
		"overflow":   "999999999999h",
		"non-scalar": "[5s]",
	} {
		t.Run(name, func(t *testing.T) {
			var parsed Duration
			if err := yaml.Unmarshal([]byte(input), &parsed); err == nil {
				t.Fatalf("duration %s was accepted", input)
			}
		})
	}

	if _, err := Load(strings.NewReader(readFixture(t, "jwks-duration-invalid.yaml"))); err == nil || !strings.Contains(err.Error(), "authenticators[0].jwt.jwks.fetch_timeout") {
		t.Fatalf("duration field error = %v, want the complete field path", err)
	}
}

func TestValidateRejectsInvalidConfiguration(t *testing.T) {
	exampleConfig := readFixture(t, "public-routing/config.yaml")
	tests := []struct {
		name string
		want string
		edit func(*Config)
	}{
		{name: "unsupported version", want: "version must", edit: func(c *Config) { c.Version = 2 }},
		{name: "invalid listener port", want: "listener.port", edit: func(c *Config) { c.Listener.Port = new(uint32(65536)) }},
		{name: "no APIs", want: "at least one API", edit: func(c *Config) { c.APIs = nil }},
		{name: "invalid API name", want: "apis[0].name", edit: func(c *Config) { c.APIs[0].Name = "Metrics" }},
		{name: "duplicate API name", want: "duplicate API name", edit: func(c *Config) { c.APIs = append(c.APIs, c.APIs[0]) }},
		{name: "duplicate route", want: "servers[0].apis: duplicate API route", edit: func(c *Config) {
			api := c.APIs[0]
			api.Name = "metrics-copy"
			c.APIs = append(c.APIs, api)
			c.Servers[0].APIs = append(c.Servers[0].APIs, api.Name)
		}},
		{name: "no routes", want: "apis[0].routes", edit: func(c *Config) { c.APIs[0].Routes = nil }},
		{name: "lowercase method", want: "apis[0].routes[0].methods", edit: func(c *Config) { c.APIs[0].Routes[0].Methods = []string{"post"} }},
		{name: "invalid method", want: "apis[0].routes[0].methods", edit: func(c *Config) { c.APIs[0].Routes[0].Methods = []string{"POST /metrics"} }},
		{name: "relative path", want: "apis[0].routes[0].path.exact", edit: func(c *Config) { c.APIs[0].Routes[0].Path.Exact = "metrics/write" }},
		{name: "path traversal", want: "apis[0].routes[0].path.exact", edit: func(c *Config) { c.APIs[0].Routes[0].Path.Exact = "/metrics/../admin" }},
		{name: "path query", want: "apis[0].routes[0].path.exact", edit: func(c *Config) { c.APIs[0].Routes[0].Path.Exact = "/metrics?tenant=one" }},
		{name: "invalid upstream", want: "apis[0].upstream.address", edit: func(c *Config) { c.APIs[0].Upstream.Address = "bad_host" }},
		{name: "invalid port", want: "apis[0].upstream.port", edit: func(c *Config) { c.APIs[0].Upstream.Port = 65536 }},
		{name: "invalid rewrite path", want: "apis[0].routes[0].rewrite.path", edit: func(c *Config) { c.APIs[0].Routes[0].Rewrite.Path = "/api/%invalid" }},
		{name: "empty image", want: "kubernetes.image", edit: func(c *Config) { c.Kubernetes.Image = " " }},
		{name: "negative replicas", want: "kubernetes.replicas", edit: func(c *Config) { c.Kubernetes.Replicas = new(int32(-1)) }},
		{name: "invalid service port", want: "kubernetes.service_port", edit: func(c *Config) { c.Kubernetes.ServicePort = new(int32(65536)) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := loadTestConfig(t, exampleConfig, "valid baseline")
			test.edit(&config)
			if err := config.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validation error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestValidateRejectsInvalidRouteConfiguration(t *testing.T) {
	routeListConfig := readFixture(t, "route-lists/config.yaml")
	tests := []struct {
		name string
		want string
		edit func(*Config)
	}{
		{name: "multiple path matchers", want: "apis[0].routes[0].path", edit: func(c *Config) { c.APIs[0].Routes[0].Path.Prefix = "/metrics/" }},
		{name: "invalid path regex", want: "apis[0].routes[0].path.regex", edit: func(c *Config) { c.APIs[0].Routes[0].Path.Regex = "[" }},
		{name: "duplicate method", want: "apis[0].routes[0].methods", edit: func(c *Config) { c.APIs[0].Routes[0].Methods = []string{"GET", "GET"} }},
		{name: "missing path matcher", want: "apis[0].routes[0].path", edit: func(c *Config) { c.APIs[0].Routes[0].Path = PathMatch{} }},
		{name: "multiple rewrite types", want: "apis[0].routes[0].rewrite", edit: func(c *Config) { c.APIs[0].Routes[0].Rewrite = &PathRewrite{Path: "/query", Prefix: "/api/"} }},
		{name: "duplicate route", want: "duplicate API route", edit: func(c *Config) { c.APIs[0].Routes = append(c.APIs[0].Routes, c.APIs[0].Routes[0]) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := loadTestConfig(t, routeListConfig, "valid route baseline")
			test.edit(&config)
			if err := config.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validation error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestSupportedExamplesGenerate(t *testing.T) {
	for _, name := range []string{"config.example.yaml", "config.auth.example.yaml", "config.production.example.yaml"} {
		t.Run(name, func(t *testing.T) {
			config := loadTestConfig(t, readTestFile(t, filepath.Join("..", name)), name)
			files, err := Generate(config)
			if err != nil {
				t.Fatalf("generate Envoy configuration: %v", err)
			}
			if len(files["envoy.yaml"]) == 0 {
				t.Fatal("Envoy output is empty")
			}
			resources, err := GenerateKubernetes(config)
			if err != nil {
				t.Fatalf("generate Kubernetes resources: %v", err)
			}
			if _, err := resources.YAML(); err != nil {
				t.Fatalf("serialize Kubernetes resources: %v", err)
			}
		})
	}
}

func TestListenerLimitsOnEveryChainAndFixedControls(t *testing.T) {
	c := loadConfigCase(t, "server-tls")
	c.Listener = Listener{
		Port: new(uint32(8088)), PerConnectionBufferLimitBytes: new(uint32(65536)),
		MaxRequestHeadersKB: new(uint32(16)), MaxRequestHeadersCount: new(uint32(20)),
		RequestHeadersTimeout: duration(250 * time.Millisecond), RequestTimeout: duration(2 * time.Second),
		ConnectionIdleTimeout: duration(12 * time.Second), StreamIdleTimeout: duration(9 * time.Second),
		MaxStreamDuration: duration(45 * time.Second), StreamFlushTimeout: duration(3 * time.Second),
		TLSHandshakeTimeout: duration(time.Second), HTTP2: &HTTP2Options{MaxConcurrentStreams: new(uint32(17))},
	}
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	b := decodeBootstrap(t, files["envoy.yaml"])
	l := b.StaticResources.Listeners[0]
	if l.Address.GetSocketAddress().GetPortValue() != 8088 || l.PerConnectionBufferLimitBytes.Value != 65536 {
		t.Fatalf("listener = %v", l)
	}
	for _, chain := range l.FilterChains {
		m := decodeHTTPManager(t, chain)
		if m.MaxRequestHeadersKb.Value != 16 || m.CommonHttpProtocolOptions.MaxHeadersCount.Value != 20 || m.RequestHeadersTimeout.AsDuration() != 250*time.Millisecond || m.RequestTimeout.AsDuration() != 2*time.Second || m.StreamIdleTimeout.AsDuration() != 9*time.Second || m.CommonHttpProtocolOptions.IdleTimeout.AsDuration() != 12*time.Second || m.CommonHttpProtocolOptions.MaxStreamDuration.AsDuration() != 45*time.Second || m.StreamFlushTimeout.AsDuration() != 3*time.Second {
			t.Fatalf("HCM settings = %v", m)
		}
		if m.Http2ProtocolOptions.MaxConcurrentStreams.Value != 17 || m.Http2ProtocolOptions.InitialStreamWindowSize != nil {
			t.Fatalf("partial HTTP/2 options = %v", m.Http2ProtocolOptions)
		}
		if m.CommonHttpProtocolOptions.HeadersWithUnderscoresAction != core.HttpProtocolOptions_REJECT_REQUEST || m.NormalizePath.Value {
			t.Fatal("fixed HTTP semantics changed")
		}
		if (chain.TransportSocket != nil && chain.TransportSocketConnectTimeout.AsDuration() != time.Second) || (chain.TransportSocket == nil && chain.TransportSocketConnectTimeout != nil) {
			t.Fatalf("TLS handshake timeout = %v", chain)
		}
		if m.HttpFilters[0].Name != requestControlsFilterName {
			t.Fatalf("public chain has no fixed prelude: %v", httpFilterNames(m))
		}
		var removal headermutation.HeaderMutation
		if err := m.HttpFilters[0].GetTypedConfig().UnmarshalTo(&removal); err != nil {
			t.Fatal(err)
		}
		got := []string{}
		for _, mutation := range removal.Mutations.RequestMutations {
			got = append(got, mutation.GetRemove())
		}
		if !reflect.DeepEqual(got, requestControlHeaders) {
			t.Fatalf("control removal = %v", got)
		}
	}
	for _, name := range requestControlHeaders {
		if !forbiddenIdentityHeader(name) {
			t.Errorf("request output could restore %s", name)
		}
	}
}

func TestResolvedRouteTimeoutsAndReuse(t *testing.T) {
	c := loadConfigCase(t, "public-routing")
	c.Listener.StreamIdleTimeout = duration(75 * time.Second)
	c.Listener.MaxStreamDuration = duration(45 * time.Second)
	c.APIs[0].Timeouts = &RouteTimeouts{ResponseTimeout: duration(60 * time.Second), MaxStreamDuration: duration(90 * time.Second)}
	c.APIs[0].Routes = []Route{
		{Methods: []string{"GET", "POST"}, Path: PathMatch{Exact: "/query"}},
		{Methods: []string{"GET"}, Path: PathMatch{Exact: "/range"}, Timeouts: &RouteTimeouts{ResponseTimeout: duration(80 * time.Second), IdleTimeout: duration(95 * time.Second), MaxStreamDuration: duration(120 * time.Second)}},
	}
	c.Servers = append(c.Servers, Server{Hostname: "second.example.test", APIs: slices.Clone(c.Servers[0].APIs)})
	before, _ := yaml.Marshal(c)
	effective, err := resolveConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	if *effective.APIs[0].Routes[0].Timeouts.IdleTimeout != Duration(75*time.Second) {
		t.Fatal("API overrides lost listener idle fallback")
	}
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	m := decodeHTTPManager(t, decodeBootstrap(t, files["envoy.yaml"]).StaticResources.Listeners[0].FilterChains[0])
	for _, host := range m.GetRouteConfig().VirtualHosts {
		for i, route := range host.Routes {
			if route.GetRoute() == nil {
				if route.StatPrefix != "" {
					t.Fatal("local responses should not get forwarding stats")
				}
				continue
			}
			want := []time.Duration{60 * time.Second, 75 * time.Second, 90 * time.Second}
			if i == 2 {
				want = []time.Duration{80 * time.Second, 95 * time.Second, 120 * time.Second}
			}
			a := route.GetRoute()
			got := []time.Duration{a.Timeout.AsDuration(), a.IdleTimeout.AsDuration(), a.MaxStreamDuration.MaxStreamDuration.AsDuration()}
			if !reflect.DeepEqual(got, want) || route.StatPrefix != route.Name || a.RetryPolicy != nil {
				t.Fatalf("route %s: %v", route.Name, a)
			}
		}
	}
	resources, err := GenerateKubernetes(c)
	if err != nil || resources.ConfigMap.Data["envoy.yaml"] != string(files["envoy.yaml"]) {
		t.Fatalf("generators resolved differently: %v", err)
	}
	after, _ := yaml.Marshal(c)
	if string(before) != string(after) || c.APIs[0].Routes[0].Timeouts != nil {
		t.Fatal("resolution mutated the public overrides")
	}
	*effective.APIs[0].Routes[0].Timeouts.ResponseTimeout = Duration(time.Second)
	if *c.APIs[0].Timeouts.ResponseTimeout != Duration(60*time.Second) {
		t.Fatal("resolved timeout aliases caller")
	}
	c.APIs[0].Timeouts.MaxStreamDuration = nil
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "1m0s") || !strings.Contains(err.Error(), "45s") || !strings.Contains(err.Error(), "apis[0].routes[0]") {
		t.Fatalf("incompatible effective timers: %v", err)
	}
}

func TestUpstreamTLSAndExplicitProtocols(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-multiple-issuers")
	ca := &TrustedCA{ConfigMap: &CAConfigMap{Name: "shared-ca", Key: "ca.pem"}}
	c.Authenticators[0].JWT.JWKS.TrustedCA = ca
	c.APIs[0].Upstream = Upstream{Address: "192.0.2.2", Port: 443, HTTPProtocol: "http2", HTTP2: &HTTP2Options{MaxConcurrentStreams: new(uint32(8)), InitialStreamWindowSize: new(uint32(65535))}, ConnectTimeout: duration(2 * time.Second), PerConnectionBufferLimitBytes: new(uint32(65536)), TLSConfig: &UpstreamTLS{ServerName: "backend.example.test", TrustedCA: ca}}
	second := c.APIs[0]
	second.Name = "ip-backend"
	second.Upstream = Upstream{Address: "2001:db8::1", Port: 443, TLSConfig: &UpstreamTLS{TrustedCA: ca}}
	c.APIs = append(c.APIs, second)
	r, err := GenerateKubernetes(c)
	if err != nil {
		t.Fatal(err)
	}
	b := decodeBootstrap(t, []byte(r.ConfigMap.Data["envoy.yaml"]))
	for i, cluster := range b.StaticResources.Clusters[:2] {
		var protocol upstreamhttp.HttpProtocolOptions
		if err := cluster.TypedExtensionProtocolOptions["envoy.extensions.upstreams.http.v3.HttpProtocolOptions"].UnmarshalTo(&protocol); err != nil {
			t.Fatal(err)
		}
		if protocol.RetryPolicy != nil {
			t.Fatal("retries emitted")
		}
		var transport tls.UpstreamTlsContext
		if err := cluster.TransportSocket.GetTypedConfig().UnmarshalTo(&transport); err != nil {
			t.Fatal(err)
		}
		validation := transport.CommonTlsContext.GetValidationContext()
		if validation.TrustedCa.GetFilename() != ca.filename() {
			t.Fatalf("CA path = %v", validation)
		}
		if i == 0 {
			if protocol.GetExplicitHttpConfig().GetHttp2ProtocolOptions().MaxConcurrentStreams.Value != 8 || transport.Sni != "backend.example.test" || transport.CommonTlsContext.AlpnProtocols[0] != "h2" || cluster.ConnectTimeout.AsDuration() != 2*time.Second || cluster.PerConnectionBufferLimitBytes.Value != 65536 {
				t.Fatalf("HTTP/2 TLS upstream = %v / %v", cluster, &transport)
			}
		} else if protocol.GetExplicitHttpConfig().GetHttpProtocolOptions() == nil || transport.Sni != "" || validation.MatchTypedSubjectAltNames[0].SanType != tls.SubjectAltNameMatcher_IP_ADDRESS || validation.MatchTypedSubjectAltNames[0].Matcher.GetExact() != "2001:db8::1" {
			t.Fatalf("HTTP/1 IP TLS upstream = %v / %v", cluster, &transport)
		}
	}
	count := 0
	for _, v := range r.Deployment.Spec.Template.Spec.Volumes {
		if v.ConfigMap != nil && v.ConfigMap.Name == "shared-ca" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("shared JWKS/backend CA mount count = %d", count)
	}
}

func TestTuningValidationAndOptionalZeros(t *testing.T) {
	tests := []struct {
		field string
		edit  func(*Config)
	}{
		{"listener.port", func(c *Config) { c.Listener.Port = new(uint32(0)) }},
		{"listener.port", func(c *Config) { c.Listener.Port = new(uint32(9901)) }},
		{"listener.port", func(c *Config) { c.Listener.Port = new(uint32(8889)) }},
		{"listener.max_request_headers_kb", func(c *Config) { c.Listener.MaxRequestHeadersKB = new(uint32(8193)) }},
		{"listener.max_request_headers_count", func(c *Config) { c.Listener.MaxRequestHeadersCount = new(uint32(0)) }},
		{"listener.request_headers_timeout", func(c *Config) { c.Listener.RequestTimeout = duration(time.Second) }},
		{"listener.http2.max_concurrent_streams", func(c *Config) { c.Listener.HTTP2 = &HTTP2Options{MaxConcurrentStreams: new(uint32(0))} }},
		{"listener.http2.initial_stream_window_size", func(c *Config) { c.Listener.HTTP2 = &HTTP2Options{InitialStreamWindowSize: new(uint32(65534))} }},
		{"listener.http2.initial_connection_window_size", func(c *Config) {
			c.Listener.HTTP2 = &HTTP2Options{InitialConnectionWindowSize: new(uint32(2147483648))}
		}},
		{"apis[0].upstream.connect_timeout", func(c *Config) { c.APIs[0].Upstream.ConnectTimeout = duration(0) }},
		{"apis[0].upstream.per_connection_buffer_limit_bytes", func(c *Config) { c.APIs[0].Upstream.PerConnectionBufferLimitBytes = new(uint32(0)) }},
		{"apis[0].upstream.http_protocol", func(c *Config) { c.APIs[0].Upstream.HTTPProtocol = "auto" }},
		{"apis[0].upstream.http2", func(c *Config) { c.APIs[0].Upstream.HTTP2 = &HTTP2Options{} }},
		{"apis[0].upstream.tls_config.server_name", func(c *Config) { c.APIs[0].Upstream.TLSConfig = &UpstreamTLS{ServerName: "*.example.test"} }},
		{"apis[0].timeouts.idle_timeout", func(c *Config) { c.APIs[0].Timeouts = &RouteTimeouts{IdleTimeout: duration(0)} }},
		{"apis[0].routes[0].timeouts.response_timeout", func(c *Config) {
			c.APIs[0].Routes[0].Timeouts = &RouteTimeouts{ResponseTimeout: duration(31 * time.Second)}
		}},
		{"kubernetes.service_port", func(c *Config) { c.Kubernetes.ServicePort = new(int32(0)) }},
	}
	for _, tt := range tests {
		c := loadConfigCase(t, "public-routing")
		tt.edit(&c)
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), tt.field) {
			t.Errorf("%s: %v", tt.field, err)
		}
	}
	input := readFixture(t, "public-routing/config.yaml")
	for _, value := range []string{"null", "8080"} {
		c, err := Load(strings.NewReader(input + "\nlistener: {port: " + value + ", http2: {}}\n"))
		if err != nil || *c.Listener.Port != 8080 || c.Listener.HTTP2 == nil {
			t.Fatalf("null/empty options: %v", err)
		}
	}
	c := loadConfigCase(t, "public-routing")
	c.Kubernetes = nil
	c.Listener.Port = new(uint32(8889))
	if err := c.Validate(); err != nil {
		t.Fatal("file-only mode has no metrics listener:", err)
	}
}
