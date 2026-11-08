package config

import (
	"reflect"
	"testing"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	headermutation "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/header_mutation/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
)

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
