package config

import (
	"fmt"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// RouteTimeouts overrides API or listener fallbacks independently for each timer.
type RouteTimeouts struct {
	ResponseTimeout   *Duration `yaml:"response_timeout,omitempty"`
	IdleTimeout       *Duration `yaml:"idle_timeout,omitempty"`
	MaxStreamDuration *Duration `yaml:"max_stream_duration,omitempty"`
}

// HTTP2Options bounds streams and flow-control windows on one HTTP/2 connection.
// Omitted fields retain Envoy's defaults.
type HTTP2Options struct {
	MaxConcurrentStreams        *uint32 `yaml:"max_concurrent_streams,omitempty"`
	InitialStreamWindowSize     *uint32 `yaml:"initial_stream_window_size,omitempty"`
	InitialConnectionWindowSize *uint32 `yaml:"initial_connection_window_size,omitempty"`
}

// UpstreamTLS enables server-authenticated TLS with a DNS or IP verification identity.
type UpstreamTLS struct {
	ServerName string     `yaml:"server_name,omitempty"`
	TrustedCA  *TrustedCA `yaml:"trusted_ca,omitempty"`
}

type effectiveConfig struct {
	Config
}

func resolveConfig(input Config) (effectiveConfig, error) {
	c := input.withDefaults()
	if err := c.validate(); err != nil {
		return effectiveConfig{}, err
	}
	for i := range c.APIs {
		api := &c.APIs[i]
		for j := range api.Routes {
			timers := resolveRouteTimeouts(c.Listener, api.Timeouts, api.Routes[j].Timeouts)
			if *timers.ResponseTimeout > *timers.MaxStreamDuration {
				field := fmt.Sprintf("apis[%d].routes[%d].timeouts", i, j)
				return effectiveConfig{}, fmt.Errorf("%s.response_timeout (%s) must not exceed effective %s.max_stream_duration (%s)", field, timers.ResponseTimeout, field, timers.MaxStreamDuration)
			}
			api.Routes[j].Timeouts = timers
		}
	}
	return effectiveConfig{Config: c}, nil
}

func (l Listener) withDefaults() Listener {
	l.Port = defaultUint32(l.Port, defaultListenerPort)
	l.PerConnectionBufferLimitBytes = defaultUint32(l.PerConnectionBufferLimitBytes, 1048576)
	l.MaxRequestHeadersKB = defaultUint32(l.MaxRequestHeadersKB, 32)
	l.MaxRequestHeadersCount = defaultUint32(l.MaxRequestHeadersCount, 100)
	l.RequestHeadersTimeout = defaultDuration(l.RequestHeadersTimeout, 5*time.Second)
	l.RequestTimeout = defaultDuration(l.RequestTimeout, 30*time.Second)
	l.ConnectionIdleTimeout = defaultDuration(l.ConnectionIdleTimeout, time.Minute)
	l.StreamIdleTimeout = defaultDuration(l.StreamIdleTimeout, time.Minute)
	l.MaxStreamDuration = defaultDuration(l.MaxStreamDuration, 30*time.Second)
	l.StreamFlushTimeout = defaultDuration(l.StreamFlushTimeout, 5*time.Second)
	l.TLSHandshakeTimeout = defaultDuration(l.TLSHandshakeTimeout, 5*time.Second)
	l.HTTP2 = cloneHTTP2(l.HTTP2)
	return l
}

func (l Listener) validate(kubernetes bool) error {
	if *l.Port == 0 || *l.Port > 65535 {
		return fmt.Errorf("listener.port must be between 1 and 65535")
	}
	if *l.Port == envoyAdminPort || (kubernetes && *l.Port == defaultOTelMetricsPort) {
		return fmt.Errorf("listener.port must not conflict with admin port %d or the Kubernetes metrics port %d", envoyAdminPort, defaultOTelMetricsPort)
	}
	for _, value := range []struct {
		name  string
		value *uint32
		max   uint32
	}{
		{"per_connection_buffer_limit_bytes", l.PerConnectionBufferLimitBytes, ^uint32(0)},
		{"max_request_headers_kb", l.MaxRequestHeadersKB, 8192},
		{"max_request_headers_count", l.MaxRequestHeadersCount, ^uint32(0)},
	} {
		if *value.value == 0 || *value.value > value.max {
			return fmt.Errorf("listener.%s must be between 1 and %d", value.name, value.max)
		}
	}
	for _, value := range []struct {
		name  string
		value *Duration
	}{
		{"request_headers_timeout", l.RequestHeadersTimeout}, {"request_timeout", l.RequestTimeout},
		{"connection_idle_timeout", l.ConnectionIdleTimeout}, {"stream_idle_timeout", l.StreamIdleTimeout},
		{"max_stream_duration", l.MaxStreamDuration}, {"stream_flush_timeout", l.StreamFlushTimeout},
		{"tls_handshake_timeout", l.TLSHandshakeTimeout},
	} {
		if err := validateDuration("listener."+value.name, value.value, false); err != nil {
			return err
		}
	}
	if *l.RequestHeadersTimeout > *l.RequestTimeout {
		return fmt.Errorf("listener.request_headers_timeout (%s) must not exceed listener.request_timeout (%s)", l.RequestHeadersTimeout, l.RequestTimeout)
	}
	return l.HTTP2.validate("listener.http2")
}

func (u Upstream) withDefaults() Upstream {
	u.ConnectTimeout = defaultDuration(u.ConnectTimeout, 5*time.Second)
	u.PerConnectionBufferLimitBytes = defaultUint32(u.PerConnectionBufferLimitBytes, 1048576)
	if u.HTTPProtocol == "" {
		u.HTTPProtocol = "http1"
	}
	u.HTTP2 = cloneHTTP2(u.HTTP2)
	if u.TLSConfig != nil {
		tls := *u.TLSConfig
		tls.TrustedCA = cloneTrustedCA(tls.TrustedCA)
		u.TLSConfig = &tls
	}
	return u
}

func (u Upstream) validate(name string, kubernetes bool) error {
	if err := validateDuration(name+".connect_timeout", u.ConnectTimeout, false); err != nil {
		return err
	}
	if *u.PerConnectionBufferLimitBytes == 0 {
		return fmt.Errorf("%s.per_connection_buffer_limit_bytes must be positive", name)
	}
	if u.HTTPProtocol != "http1" && u.HTTPProtocol != "http2" {
		return fmt.Errorf("%s.http_protocol must be http1 or http2", name)
	}
	if u.HTTP2 != nil && u.HTTPProtocol != "http2" {
		return fmt.Errorf("%s.http2 requires http_protocol: http2", name)
	}
	if err := u.HTTP2.validate(name + ".http2"); err != nil {
		return err
	}
	if u.TLSConfig != nil {
		if u.TLSConfig.ServerName != "" && !validDNSHost(u.TLSConfig.ServerName) {
			return fmt.Errorf("%s.tls_config.server_name must be an exact DNS hostname", name)
		}
		return validateTrustedCA(name+".tls_config.trusted_ca", u.TLSConfig.TrustedCA, kubernetes)
	}
	return nil
}

func cloneRouteTimeouts(t *RouteTimeouts) *RouteTimeouts {
	if t == nil {
		return nil
	}
	return &RouteTimeouts{ResponseTimeout: clonePointer(t.ResponseTimeout), IdleTimeout: clonePointer(t.IdleTimeout), MaxStreamDuration: clonePointer(t.MaxStreamDuration)}
}

func validateRouteTimeouts(name string, t *RouteTimeouts) error {
	if t == nil {
		return nil
	}
	for _, value := range []struct {
		name  string
		value *Duration
	}{
		{"response_timeout", t.ResponseTimeout}, {"idle_timeout", t.IdleTimeout}, {"max_stream_duration", t.MaxStreamDuration},
	} {
		if err := validateDuration(name+"."+value.name, value.value, false); err != nil {
			return err
		}
	}
	return nil
}

func resolveRouteTimeouts(l Listener, api, route *RouteTimeouts) *RouteTimeouts {
	resolved := &RouteTimeouts{
		ResponseTimeout:   new(Duration(30 * time.Second)),
		IdleTimeout:       clonePointer(l.StreamIdleTimeout),
		MaxStreamDuration: clonePointer(l.MaxStreamDuration),
	}
	for _, overrides := range []*RouteTimeouts{api, route} {
		if overrides == nil {
			continue
		}
		if overrides.ResponseTimeout != nil {
			resolved.ResponseTimeout = clonePointer(overrides.ResponseTimeout)
		}
		if overrides.IdleTimeout != nil {
			resolved.IdleTimeout = clonePointer(overrides.IdleTimeout)
		}
		if overrides.MaxStreamDuration != nil {
			resolved.MaxStreamDuration = clonePointer(overrides.MaxStreamDuration)
		}
	}
	return resolved
}

func cloneHTTP2(h *HTTP2Options) *HTTP2Options {
	if h == nil {
		return nil
	}
	return &HTTP2Options{MaxConcurrentStreams: clonePointer(h.MaxConcurrentStreams), InitialStreamWindowSize: clonePointer(h.InitialStreamWindowSize), InitialConnectionWindowSize: clonePointer(h.InitialConnectionWindowSize)}
}

func (h *HTTP2Options) validate(name string) error {
	if h == nil {
		return nil
	}
	for _, value := range []struct {
		name  string
		value *uint32
		min   uint32
	}{
		{"max_concurrent_streams", h.MaxConcurrentStreams, 1},
		{"initial_stream_window_size", h.InitialStreamWindowSize, 65535},
		{"initial_connection_window_size", h.InitialConnectionWindowSize, 65535},
	} {
		if value.value != nil && (*value.value < value.min || *value.value > 2147483647) {
			return fmt.Errorf("%s.%s must be between %d and 2147483647", name, value.name, value.min)
		}
	}
	if err := h.envoy().ValidateAll(); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

func (h *HTTP2Options) envoy() *core.Http2ProtocolOptions {
	if h == nil {
		return nil
	}
	return &core.Http2ProtocolOptions{
		MaxConcurrentStreams:        optionalUint32(h.MaxConcurrentStreams),
		InitialStreamWindowSize:     optionalUint32(h.InitialStreamWindowSize),
		InitialConnectionWindowSize: optionalUint32(h.InitialConnectionWindowSize),
	}
}

func optionalUint32(value *uint32) *wrapperspb.UInt32Value {
	if value == nil {
		return nil
	}
	return wrapperspb.UInt32(*value)
}
