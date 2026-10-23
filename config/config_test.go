package config

import (
	"math"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	headermutation "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/header_mutation/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	upstreamhttp "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	"github.com/google/go-cmp/cmp"
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

func loadAuthValidationFixture(t testing.TB) Config {
	t.Helper()
	return loadTestConfig(t, readFixture(t, filepath.Join("baselines", "auth-validation.yaml")), "auth validation fixture")
}

func assertConfigDiff(t testing.TB, name string, want, got any) {
	t.Helper()
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("%s mismatch (-want +got):\n%s", name, diff)
	}
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

func TestLoadKeepsTimeoutOverridesUnresolved(t *testing.T) {
	c := loadConfigCase(t, "production-tuning")
	if c.Listener.Port == nil || *c.Listener.Port != 8080 {
		t.Fatalf("listener port default = %v", c.Listener.Port)
	}
	if c.APIs[0].Routes[0].Timeouts != nil {
		t.Fatal("Load filled omitted route timeouts")
	}
	timeouts := c.APIs[0].Routes[1].Timeouts
	wantTimeouts := &RouteTimeouts{ResponseTimeout: duration(20 * time.Second), MaxStreamDuration: duration(30 * time.Second)}
	assertConfigDiff(t, "partial route timeout overrides", wantTimeouts, timeouts)
}

func TestLoadRejectsIncompatibleEffectiveRouteTimeouts(t *testing.T) {
	input := `version: 1
listener:
  max_stream_duration: 10s
servers:
  - hostname: auth.example.test
    apis: [metrics]
apis:
  - name: metrics
    upstream: {address: httpbin, port: 80}
    timeouts: {response_timeout: 20s}
    routes:
      - methods: [GET]
        path: {exact: /metrics}
`
	if _, err := Load(strings.NewReader(input)); err == nil ||
		!strings.Contains(err.Error(), "apis[0].routes[0].timeouts.response_timeout (20s)") ||
		!strings.Contains(err.Error(), "max_stream_duration (10s)") {
		t.Fatalf("Load error = %v, want effective route timeout conflict", err)
	}
}

func TestLoadRejectsInvalidYAML(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "unknown field", input: "version: 1\nunknown: true\n", want: "field unknown not found"},
		{name: "top-level processing", input: "version: 1\nprocessing: []\n", want: "field processing not found"},
		{name: "top-level admission control", input: "version: 1\nadmission_control: {}\n", want: "field admission_control not found"},
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

func TestValidateRejectsInvalidOverloadConfiguration(t *testing.T) {
	exampleConfig := readFixture(t, "public-routing/config.yaml")
	validOverload := func() *OverloadConfig {
		return &OverloadConfig{
			MaxHeapBytes:             128 << 20,
			MaxDownstreamConnections: 1024,
			HeapShrinkThreshold:      new(0.70),
			RequestRejectThreshold:   new(0.85),
		}
	}
	tests := []struct {
		name string
		want string
		edit func(*Config)
	}{
		{name: "zero max downstream connections", want: "overload.max_downstream_connections", edit: func(c *Config) {
			o := validOverload()
			o.MaxDownstreamConnections = 0
			c.Overload = o
		}},
		{name: "heap shrink threshold not finite", want: "overload.heap_shrink_threshold", edit: func(c *Config) {
			o := validOverload()
			o.HeapShrinkThreshold = new(math.NaN())
			c.Overload = o
		}},
		{name: "heap shrink threshold out of range", want: "overload.heap_shrink_threshold", edit: func(c *Config) {
			o := validOverload()
			o.HeapShrinkThreshold = new(0.0)
			c.Overload = o
		}},
		{name: "request reject threshold out of range", want: "overload.request_reject_threshold", edit: func(c *Config) {
			o := validOverload()
			o.RequestRejectThreshold = new(1.0)
			c.Overload = o
		}},
		{name: "shrink threshold not below reject threshold", want: "overload.heap_shrink_threshold must be less than overload.request_reject_threshold", edit: func(c *Config) {
			o := validOverload()
			o.HeapShrinkThreshold = new(0.90)
			o.RequestRejectThreshold = new(0.80)
			c.Overload = o
		}},
		{name: "missing kubernetes memory limit", want: "overload requires a positive kubernetes.resources.limits.memory", edit: func(c *Config) {
			c.Overload = validOverload()
			c.Kubernetes.Resources.Limits = map[string]string{}
		}},
		{name: "heap budget exceeds memory limit", want: "overload.max_heap_bytes", edit: func(c *Config) {
			o := validOverload()
			o.MaxHeapBytes = 512 << 20
			c.Overload = o
		}},
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
	b := decodeBootstrap(t, files.EnvoyBootstrap.Contents)
	l := b.StaticResources.Listeners[0]
	if got := l.Address.GetSocketAddress().GetPortValue(); got != 8088 {
		t.Errorf("listener port = %d, want 8088", got)
	}
	if got := l.PerConnectionBufferLimitBytes.Value; got != 65536 {
		t.Errorf("listener per-connection buffer limit = %d, want 65536", got)
	}
	for _, chain := range l.FilterChains {
		m := decodeHTTPManager(t, chain)
		type hcmSettings struct {
			MaxRequestHeadersKB    uint32
			MaxRequestHeadersCount uint32
			RequestHeadersTimeout  time.Duration
			RequestTimeout         time.Duration
			StreamIdleTimeout      time.Duration
			ConnectionIdleTimeout  time.Duration
			MaxStreamDuration      time.Duration
			StreamFlushTimeout     time.Duration
		}
		gotSettings := hcmSettings{
			MaxRequestHeadersKB:    m.MaxRequestHeadersKb.Value,
			MaxRequestHeadersCount: m.CommonHttpProtocolOptions.MaxHeadersCount.Value,
			RequestHeadersTimeout:  m.RequestHeadersTimeout.AsDuration(),
			RequestTimeout:         m.RequestTimeout.AsDuration(),
			StreamIdleTimeout:      m.StreamIdleTimeout.AsDuration(),
			ConnectionIdleTimeout:  m.CommonHttpProtocolOptions.IdleTimeout.AsDuration(),
			MaxStreamDuration:      m.CommonHttpProtocolOptions.MaxStreamDuration.AsDuration(),
			StreamFlushTimeout:     m.StreamFlushTimeout.AsDuration(),
		}
		wantSettings := hcmSettings{
			MaxRequestHeadersKB:    16,
			MaxRequestHeadersCount: 20,
			RequestHeadersTimeout:  250 * time.Millisecond,
			RequestTimeout:         2 * time.Second,
			StreamIdleTimeout:      9 * time.Second,
			ConnectionIdleTimeout:  12 * time.Second,
			MaxStreamDuration:      45 * time.Second,
			StreamFlushTimeout:     3 * time.Second,
		}
		assertConfigDiff(t, "HCM settings", wantSettings, gotSettings)
		if m.Http2ProtocolOptions.MaxConcurrentStreams.Value != 17 || m.Http2ProtocolOptions.InitialStreamWindowSize != nil {
			t.Errorf("HTTP/2 max concurrent streams = %d and initial stream window size = %v, want 17 and nil", m.Http2ProtocolOptions.MaxConcurrentStreams.Value, m.Http2ProtocolOptions.InitialStreamWindowSize)
		}
		if m.CommonHttpProtocolOptions.HeadersWithUnderscoresAction != core.HttpProtocolOptions_REJECT_REQUEST || !m.NormalizePath.Value {
			t.Errorf("headers with underscores action = %v and normalize path = %t, want REJECT_REQUEST and true", m.CommonHttpProtocolOptions.HeadersWithUnderscoresAction, m.NormalizePath.Value)
		}
		if m.PathWithEscapedSlashesAction != hcm.HttpConnectionManager_UNESCAPE_AND_FORWARD {
			t.Errorf("path with escaped slashes action = %v, want UNESCAPE_AND_FORWARD", m.PathWithEscapedSlashesAction)
		}
		if chain.TransportSocket != nil && chain.TransportSocketConnectTimeout.AsDuration() != time.Second {
			t.Errorf("TLS handshake timeout = %s, want 1s", chain.TransportSocketConnectTimeout.AsDuration())
		}
		if chain.TransportSocket == nil && chain.TransportSocketConnectTimeout != nil {
			t.Errorf("TLS handshake timeout without a TLS socket = %v, want nil", chain.TransportSocketConnectTimeout)
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
	m := decodeHTTPManager(t, decodeBootstrap(t, files.EnvoyBootstrap.Contents).StaticResources.Listeners[0].FilterChains[0])
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
			type routeSettings struct {
				ResponseTimeout   time.Duration
				IdleTimeout       time.Duration
				MaxStreamDuration time.Duration
				StatPrefix        string
				HasRetryPolicy    bool
			}
			got := routeSettings{
				ResponseTimeout:   a.Timeout.AsDuration(),
				IdleTimeout:       a.IdleTimeout.AsDuration(),
				MaxStreamDuration: a.MaxStreamDuration.MaxStreamDuration.AsDuration(),
				StatPrefix:        route.StatPrefix,
				HasRetryPolicy:    a.RetryPolicy != nil,
			}
			wantSettings := routeSettings{
				ResponseTimeout:   want[0],
				IdleTimeout:       want[1],
				MaxStreamDuration: want[2],
				StatPrefix:        route.Name,
			}
			assertConfigDiff(t, "route settings for "+route.Name, wantSettings, got)
		}
	}
	resources, err := GenerateKubernetes(c)
	if err != nil {
		t.Fatalf("generate Kubernetes resources: %v", err)
	}
	if got, want := resources.ConfigMap.Data["envoy.yaml"], string(files.EnvoyBootstrap.Contents); got != want {
		t.Fatal("Envoy and Kubernetes generators produced different bootstraps")
	}
	after, _ := yaml.Marshal(c)
	if string(before) != string(after) {
		t.Fatal("resolution changed the serialized configuration")
	}
	if c.APIs[0].Routes[0].Timeouts != nil {
		t.Fatal("resolution added a timeout override to the public configuration")
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
}

func TestConfigurationDefaults(t *testing.T) {
	c := loadTestConfig(t, readFixture(t, "defaults.yaml"), "defaults fixture")
	if c.Node != (EnvoyNode{ID: "auth-gateway", Cluster: "auth-gateway"}) {
		t.Fatalf("node defaults = %#v", c.Node)
	}
	wantListener := Listener{
		Port: new(uint32(8080)), PerConnectionBufferLimitBytes: new(uint32(1048576)),
		MaxRequestHeadersKB: new(uint32(32)), MaxRequestHeadersCount: new(uint32(100)),
		RequestHeadersTimeout: duration(5 * time.Second), RequestTimeout: duration(30 * time.Second),
		ConnectionIdleTimeout: duration(60 * time.Second), StreamIdleTimeout: duration(60 * time.Second),
		MaxStreamDuration: duration(30 * time.Second), StreamFlushTimeout: duration(5 * time.Second),
		TLSHandshakeTimeout: duration(5 * time.Second),
	}
	assertConfigDiff(t, "listener defaults", wantListener, c.Listener)
	if c.Overload != nil {
		t.Fatal("overload must be opt-in")
	}
	wantBreakers := &CircuitBreakerConfig{MaxConnections: new(uint32(1024)), MaxPendingRequests: new(uint32(1024)), MaxRequests: new(uint32(1024)), MaxRetries: new(uint32(0))}
	for _, a := range c.Authenticators {
		if a.JWT == nil {
			continue
		}
		want := JWKSConfig{URI: a.JWT.JWKS.URI, DNSLookupFamily: jwksDNSLookupFamilyV4Only, CacheDuration: duration(5 * time.Minute), FetchTimeout: duration(5 * time.Second), ConnectTimeout: duration(5 * time.Second), CircuitBreakers: wantBreakers}
		assertConfigDiff(t, a.Name+" JWKS defaults", want, a.JWT.JWKS)
	}
	for _, api := range c.APIs {
		want := Upstream{Address: api.Upstream.Address, Port: api.Upstream.Port, ConnectTimeout: duration(5 * time.Second), PerConnectionBufferLimitBytes: new(uint32(1048576)), HTTPProtocol: "http1"}
		assertConfigDiff(t, api.Name+" upstream defaults", want, api.Upstream)
		assertConfigDiff(t, api.Name+" circuit breaker defaults", wantBreakers, api.CircuitBreakers)
		if api.Timeouts != nil {
			t.Fatalf("default fixture API %s must inherit API timeouts", api.Name)
		}
		for _, r := range api.Routes {
			if r.Timeouts != nil {
				t.Fatal("default fixture must inherit route timeouts")
			}
		}
	}
	wantKubernetesResources := KubernetesResourceRequirements{
		Requests: map[string]string{"cpu": "50m", "memory": "64Mi"},
		Limits:   map[string]string{"cpu": "1", "memory": "256Mi"},
	}
	type kubernetesDefaults struct {
		Name             string
		Namespace        string
		Replicas         *int32
		ServicePort      *int32
		HTTPSServicePort *int32
		EnvoyConcurrency *uint32
		Resources        KubernetesResourceRequirements
	}
	gotKubernetes := kubernetesDefaults{
		Name:             c.Kubernetes.Name,
		Namespace:        c.Kubernetes.Namespace,
		Replicas:         c.Kubernetes.Replicas,
		ServicePort:      c.Kubernetes.ServicePort,
		HTTPSServicePort: c.Kubernetes.HTTPSServicePort,
		EnvoyConcurrency: c.Kubernetes.EnvoyConcurrency,
		Resources:        c.Kubernetes.Resources,
	}
	wantKubernetes := kubernetesDefaults{
		Name: "auth-gateway", Namespace: "observability",
		Replicas: new(int32(2)), ServicePort: new(int32(80)), HTTPSServicePort: new(int32(443)),
		Resources: wantKubernetesResources,
	}
	assertConfigDiff(t, "Kubernetes defaults", wantKubernetes, gotKubernetes)
	wantTLS := &ServerTLS{Secret: "gateway-tls", Certificate: "/etc/gateway-tls/tls.crt", PrivateKey: "/etc/gateway-tls/tls.key"}
	assertConfigDiff(t, "server TLS defaults", wantTLS, c.Servers[0].TLSConfig)
	resolved, err := resolveConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	wantTimers := &RouteTimeouts{ResponseTimeout: duration(30 * time.Second), IdleTimeout: duration(60 * time.Second), MaxStreamDuration: duration(30 * time.Second)}
	for _, api := range resolved.APIs {
		for _, r := range api.Routes {
			assertConfigDiff(t, api.Name+" effective timeouts", wantTimers, r.Timeouts)
		}
	}
	if _, err := GenerateKubernetes(c); err != nil {
		t.Fatalf("generate defaulted resources: %v", err)
	}
}

func TestCircuitBreakerConfigAppliesToJWKSCluster(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-multiple-issuers")
	c.Authenticators[0].JWT.JWKS.CircuitBreakers = &CircuitBreakerConfig{
		MaxConnections: new(uint32(3)), MaxRequests: new(uint32(0)), MaxRetries: new(uint32(7)),
	}
	resources, err := GenerateKubernetes(c)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := decodeBootstrap(t, []byte(resources.ConfigMap.Data[envoyConfigFilename]))
	name := jwksClusterName(c.Authenticators[0].Name)
	for _, cluster := range bootstrap.StaticResources.Clusters {
		if cluster.Name != name {
			continue
		}
		if len(cluster.CircuitBreakers.Thresholds) != 1 {
			t.Fatalf("JWKS circuit breaker thresholds = %v, want one threshold", cluster.CircuitBreakers.Thresholds)
		}
		limits := cluster.CircuitBreakers.Thresholds[0]
		if limits.MaxConnections.Value != 3 || limits.MaxPendingRequests.Value != 1024 ||
			limits.MaxRequests.Value != 0 || limits.MaxRetries.Value != 7 {
			t.Fatalf("JWKS circuit breaker limits = %v", limits)
		}
		return
	}
	t.Fatalf("JWKS cluster %q not found", name)
}

func TestOptInOverloadDefaults(t *testing.T) {
	c := loadConfigCase(t, "public-routing")
	c.Overload = &OverloadConfig{MaxHeapBytes: 201326592, MaxDownstreamConnections: 2048}
	resolved, err := resolveConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	want := &OverloadConfig{MaxHeapBytes: 201326592, MaxDownstreamConnections: 2048, HeapShrinkThreshold: new(0.90), RequestRejectThreshold: new(0.95)}
	assertConfigDiff(t, "overload defaults", want, resolved.Overload)
	if c.Overload.HeapShrinkThreshold != nil {
		t.Error("default resolution added heap_shrink_threshold to the caller's configuration")
	}
	if c.Overload.RequestRejectThreshold != nil {
		t.Error("default resolution added request_reject_threshold to the caller's configuration")
	}
}

func TestServerTLSDefaults(t *testing.T) {
	tests := []struct {
		name        string
		tls         ServerTLS
		certificate string
		privateKey  string
	}{
		{name: "file only", certificate: defaultServerTLSCertificate, privateKey: defaultServerTLSPrivateKey},
		{name: "named Secret", tls: ServerTLS{Secret: "other-tls"}, certificate: "/etc/other-tls/tls.crt", privateKey: "/etc/other-tls/tls.key"},
		{name: "explicit paths", tls: ServerTLS{Secret: "other-tls", Certificate: "/certs/server.pem", PrivateKey: "/certs/key.pem"}, certificate: "/certs/server.pem", privateKey: "/certs/key.pem"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := loadConfigCase(t, "public-routing")
			c.Kubernetes = nil
			c.Servers[0].TLSConfig = &test.tls
			defaulted := c.withDefaults()
			if err := defaulted.Validate(); err != nil {
				t.Fatal(err)
			}
			got := defaulted.Servers[0].TLSConfig
			if got.Certificate != test.certificate || got.PrivateKey != test.privateKey {
				t.Fatalf("TLS paths = %s, %s, want %s, %s", got.Certificate, got.PrivateKey, test.certificate, test.privateKey)
			}
		})
	}
}

func TestDefaultsCloneInputs(t *testing.T) {
	t.Run("route slices and pointers", func(t *testing.T) {
		c := loadConfigCase(t, "public-routing")
		methods := c.APIs[0].Routes[0].Methods[0]
		c.Kubernetes.Replicas = nil
		defaulted := c.withDefaults()
		defaulted.APIs[0].Routes[0].Methods[0] = "changed"
		*defaulted.Kubernetes.Replicas = 1
		if c.APIs[0].Routes[0].Methods[0] != methods || c.Kubernetes.Replicas != nil {
			t.Fatal("defaulting aliases route slices or pointers")
		}
	})

	t.Run("authentication maps and slices", func(t *testing.T) {
		c := loadAuthValidationFixture(t)
		defaulted := c.withDefaults()
		defaulted.Authenticators[0].JWT.Audiences[0] = "changed"
		defaulted.Authenticators[0].Attributes["tenant_id"].ClaimPath[0] = "changed"
		keySource := defaulted.Authenticators[2].Attributes["tenant_id"]
		*keySource.Credential = false
		headerSource := defaulted.Authenticators[2].Attributes["requested_tenant"]
		*headerSource.Header = "changed"
		defaulted.AuthorizationPolicies[0].Grants[0].APIs[0] = "changed"
		defaulted.AuthorizationPolicies[0].Grants[0].Attributes["tenant_id"][0] = "changed"
		defaulted.Servers[0].Authentication.AnyOf[0] = "changed"
		defaulted.Servers[0].Authorization.AnyOf[0] = "changed"
		defaulted.APIs[0].Routes[0].Processing.RequestHeaders[0].Name = "changed"

		if c.Authenticators[0].JWT.Audiences[0] == "changed" ||
			c.Authenticators[0].Attributes["tenant_id"].ClaimPath[0] == "changed" ||
			!*c.Authenticators[2].Attributes["tenant_id"].Credential ||
			*c.Authenticators[2].Attributes["requested_tenant"].Header == "changed" ||
			c.AuthorizationPolicies[0].Grants[0].APIs[0] == "changed" ||
			c.AuthorizationPolicies[0].Grants[0].Attributes["tenant_id"][0] == "changed" ||
			c.Servers[0].Authentication.AnyOf[0] == "changed" ||
			c.Servers[0].Authorization.AnyOf[0] == "changed" ||
			c.APIs[0].Routes[0].Processing.RequestHeaders[0].Name == "changed" {
			t.Fatal("defaulting aliases authentication configuration")
		}
	})

	t.Run("JWKS references and timeout pointers", func(t *testing.T) {
		c := loadConfigCase(t, "jwt-auth-multiple-issuers")
		c.Authenticators[0].JWT.JWKS.TrustedCA = &TrustedCA{ConfigMap: &CAConfigMap{Name: "issuer-ca", Key: "roots.pem"}}
		c.Authenticators[0].JWT.JWKS.CacheDuration = duration(15 * time.Second)
		c.Authenticators[0].JWT.JWKS.CircuitBreakers = &CircuitBreakerConfig{MaxConnections: new(uint32(3))}
		defaulted := c.withDefaults()
		defaulted.Authenticators[0].JWT.JWKS.TrustedCA.ConfigMap.Key = "changed"
		*defaulted.Authenticators[0].JWT.JWKS.CacheDuration = Duration(time.Minute)
		*defaulted.Authenticators[0].JWT.JWKS.CircuitBreakers.MaxConnections = 99
		jwks := c.Authenticators[0].JWT.JWKS
		if jwks.TrustedCA.ConfigMap.Key != "roots.pem" || *jwks.CacheDuration != Duration(15*time.Second) || *jwks.CircuitBreakers.MaxConnections != 3 {
			t.Fatal("defaulting aliases JWKS references or timeout pointers")
		}
	})

	t.Run("server fields", func(t *testing.T) {
		c := loadConfigCase(t, "public-routing")
		c.Servers[0].TLSConfig = &ServerTLS{Secret: "server-tls"}
		defaulted := c.withDefaults()
		if c.Servers[0].TLSConfig.Certificate != "" || c.Servers[0].TLSConfig.PrivateKey != "" || c.Kubernetes.HTTPSServicePort != nil {
			t.Fatal("defaulting changed the input TLS configuration")
		}
		if *defaulted.Kubernetes.HTTPSServicePort != defaultHTTPSServicePort {
			t.Fatal("HTTPS Service port was not defaulted")
		}
		defaulted.Servers[0].APIs[0] = "other"
		defaulted.Servers[0].TLSConfig.Secret = "other-tls"
		if c.Servers[0].APIs[0] != "metrics" || c.Servers[0].TLSConfig.Secret != "server-tls" {
			t.Fatal("defaulting aliases server fields")
		}
	})

	t.Run("resource maps and optional pointers", func(t *testing.T) {
		c := loadConfigCase(t, "public-routing")
		c.Overload = &OverloadConfig{MaxHeapBytes: 128 << 20, MaxDownstreamConnections: 1, HeapShrinkThreshold: new(0.7)}
		c.Kubernetes.EnvoyConcurrency = new(uint32(2))
		c.Kubernetes.Resources.Limits = map[string]string{}
		defaulted := c.withDefaults()
		if len(defaulted.Kubernetes.Resources.Limits) != 0 {
			t.Fatal("resource defaults merged into supplied maps")
		}
		*defaulted.Overload.HeapShrinkThreshold = 0.2
		*defaulted.Kubernetes.EnvoyConcurrency = 3
		defaulted.Kubernetes.Resources.Limits["memory"] = "512Mi"
		if *c.Overload.HeapShrinkThreshold != 0.7 || *c.Kubernetes.EnvoyConcurrency != 2 || len(c.Kubernetes.Resources.Limits) != 0 {
			t.Fatal("defaulting aliases resource maps or optional pointers")
		}
	})
}

func TestPublicOperationsPreserveConfiguration(t *testing.T) {
	c := loadAuthValidationFixture(t)
	before, err := yaml.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(c); err != nil {
		t.Fatal(err)
	}
	resources, err := GenerateKubernetes(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resources.YAML(); err != nil {
		t.Fatal(err)
	}
	after, err := yaml.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("validation or generation mutated the caller's configuration")
	}
}

func TestKubernetesYAMLOptions(t *testing.T) {
	c := loadTestConfig(t, readFixture(t, "kubernetes-options/nested-null.yaml"), "nested nulls")
	if c.Overload != nil || c.Kubernetes.EnvoyConcurrency != nil {
		t.Fatalf("defaulted Kubernetes settings = %#v", c.Kubernetes)
	}

	c = loadTestConfig(t, readFixture(t, "kubernetes-options/empty-resource-maps.yaml"), "empty resource maps")
	if c.Kubernetes.Resources.Requests == nil || c.Kubernetes.Resources.Limits == nil ||
		len(c.Kubernetes.Resources.Requests) != 0 || len(c.Kubernetes.Resources.Limits) != 0 {
		t.Fatal("supplied empty resource maps were merged with defaults")
	}
	if _, err := Load(strings.NewReader(readFixture(t, "kubernetes-options/overload-empty.yaml"))); err == nil || !strings.Contains(err.Error(), "overload.max_heap_bytes") {
		t.Fatalf("empty overload accepted: %v", err)
	}
}

func TestJWKSFetchTimeoutDefaultsForNull(t *testing.T) {
	c, err := Load(strings.NewReader(readFixture(t, "jwks-duration-null.yaml")))
	if err != nil || *c.Authenticators[0].JWT.JWKS.FetchTimeout != Duration(5*time.Second) {
		t.Fatalf("null fetch timeout default: %v", err)
	}
}
