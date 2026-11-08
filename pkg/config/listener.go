package config

import (
	"fmt"
	"time"

	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
)

const (
	EnvoyAdminAddress = "127.0.0.1"
	EnvoyAdminPort    = 9901
)

const (
	EnvoyListenerAddress = "0.0.0.0"
	DefaultListenerPort  = 8080
)

func withDefaultsListener(l gatewayapi.Listener) gatewayapi.Listener {
	l.Port = defaultValue(l.Port, DefaultListenerPort)
	l.PerConnectionBufferLimitBytes = defaultValue(l.PerConnectionBufferLimitBytes, 1048576)
	l.MaxRequestHeadersKB = defaultValue(l.MaxRequestHeadersKB, 32)
	l.MaxRequestHeadersCount = defaultValue(l.MaxRequestHeadersCount, 100)
	l.RequestHeadersTimeout = withDefaultDuration(l.RequestHeadersTimeout, 5*time.Second)
	l.RequestTimeout = withDefaultDuration(l.RequestTimeout, 30*time.Second)
	l.ConnectionIdleTimeout = withDefaultDuration(l.ConnectionIdleTimeout, time.Minute)
	l.StreamIdleTimeout = withDefaultDuration(l.StreamIdleTimeout, time.Minute)
	l.MaxStreamDuration = withDefaultDuration(l.MaxStreamDuration, 30*time.Second)
	l.StreamFlushTimeout = withDefaultDuration(l.StreamFlushTimeout, 5*time.Second)
	l.TLSHandshakeTimeout = withDefaultDuration(l.TLSHandshakeTimeout, 5*time.Second)
	return l
}

func cloneListener(l gatewayapi.Listener) gatewayapi.Listener {
	l.Port = clonePointer(l.Port)
	l.PerConnectionBufferLimitBytes = clonePointer(l.PerConnectionBufferLimitBytes)
	l.MaxRequestHeadersKB = clonePointer(l.MaxRequestHeadersKB)
	l.MaxRequestHeadersCount = clonePointer(l.MaxRequestHeadersCount)
	l.RequestHeadersTimeout = clonePointer(l.RequestHeadersTimeout)
	l.RequestTimeout = clonePointer(l.RequestTimeout)
	l.ConnectionIdleTimeout = clonePointer(l.ConnectionIdleTimeout)
	l.StreamIdleTimeout = clonePointer(l.StreamIdleTimeout)
	l.MaxStreamDuration = clonePointer(l.MaxStreamDuration)
	l.StreamFlushTimeout = clonePointer(l.StreamFlushTimeout)
	l.TLSHandshakeTimeout = clonePointer(l.TLSHandshakeTimeout)
	l.HTTP2 = cloneConfigPointer(l.HTTP2, cloneHTTP2Options)
	return l
}

func validateListener(l gatewayapi.Listener, metricsEnabled, tracingEnabled bool) error {
	if *l.Port == 0 || *l.Port > 65535 {
		return fmt.Errorf("listener.port must be between 1 and 65535")
	}
	if err := validateObservabilityListenerPort(l.Port, metricsEnabled, tracingEnabled); err != nil {
		return err
	}
	for _, value := range []struct {
		Name  string
		Value *uint32
		Max   uint32
	}{
		{"per_connection_buffer_limit_bytes", l.PerConnectionBufferLimitBytes, ^uint32(0)},
		{"max_request_headers_kb", l.MaxRequestHeadersKB, 8192},
		{"max_request_headers_count", l.MaxRequestHeadersCount, ^uint32(0)},
	} {
		if *value.Value == 0 || *value.Value > value.Max {
			return fmt.Errorf("listener.%s must be between 1 and %d", value.Name, value.Max)
		}
	}
	for _, value := range []struct {
		Name  string
		Value *gatewayapi.Duration
	}{
		{"request_headers_timeout", l.RequestHeadersTimeout}, {"request_timeout", l.RequestTimeout},
		{"connection_idle_timeout", l.ConnectionIdleTimeout}, {"stream_idle_timeout", l.StreamIdleTimeout},
		{MaxStreamDurationFieldName, l.MaxStreamDuration}, {"stream_flush_timeout", l.StreamFlushTimeout},
		{"tls_handshake_timeout", l.TLSHandshakeTimeout},
	} {
		if err := validateDuration("listener."+value.Name, value.Value, false); err != nil {
			return err
		}
	}
	if *l.RequestHeadersTimeout > *l.RequestTimeout {
		return fmt.Errorf("listener.request_headers_timeout (%s) must not exceed listener.request_timeout (%s)", l.RequestHeadersTimeout, l.RequestTimeout)
	}
	if l.HTTP2 != nil {
		return validateHTTP2Options(*l.HTTP2, "listener.http2")
	}
	return nil
}

const IngestionListenerName = "ingestion"
