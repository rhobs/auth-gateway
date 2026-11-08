package config

import (
	"fmt"
	"time"
)

const (
	envoyListenerAddress = "0.0.0.0"
	defaultListenerPort  = 8080
)

// Listener describes the socket shared by the configured servers.
type Listener struct {
	Port                          *uint32       `yaml:"port,omitempty"`
	PerConnectionBufferLimitBytes *uint32       `yaml:"per_connection_buffer_limit_bytes,omitempty"`
	MaxRequestHeadersKB           *uint32       `yaml:"max_request_headers_kb,omitempty"`
	MaxRequestHeadersCount        *uint32       `yaml:"max_request_headers_count,omitempty"`
	RequestHeadersTimeout         *Duration     `yaml:"request_headers_timeout,omitempty"`
	RequestTimeout                *Duration     `yaml:"request_timeout,omitempty"`
	ConnectionIdleTimeout         *Duration     `yaml:"connection_idle_timeout,omitempty"`
	StreamIdleTimeout             *Duration     `yaml:"stream_idle_timeout,omitempty"`
	MaxStreamDuration             *Duration     `yaml:"max_stream_duration,omitempty"`
	StreamFlushTimeout            *Duration     `yaml:"stream_flush_timeout,omitempty"`
	TLSHandshakeTimeout           *Duration     `yaml:"tls_handshake_timeout,omitempty"`
	HTTP2                         *HTTP2Options `yaml:"http2,omitempty"`
}

func (l Listener) withDefaults() Listener {
	l.Port = defaultValue(l.Port, defaultListenerPort)
	l.PerConnectionBufferLimitBytes = defaultValue(l.PerConnectionBufferLimitBytes, 1048576)
	l.MaxRequestHeadersKB = defaultValue(l.MaxRequestHeadersKB, 32)
	l.MaxRequestHeadersCount = defaultValue(l.MaxRequestHeadersCount, 100)
	l.RequestHeadersTimeout = l.RequestHeadersTimeout.withDefault(5 * time.Second)
	l.RequestTimeout = l.RequestTimeout.withDefault(30 * time.Second)
	l.ConnectionIdleTimeout = l.ConnectionIdleTimeout.withDefault(time.Minute)
	l.StreamIdleTimeout = l.StreamIdleTimeout.withDefault(time.Minute)
	l.MaxStreamDuration = l.MaxStreamDuration.withDefault(30 * time.Second)
	l.StreamFlushTimeout = l.StreamFlushTimeout.withDefault(5 * time.Second)
	l.TLSHandshakeTimeout = l.TLSHandshakeTimeout.withDefault(5 * time.Second)
	return l
}

func (l Listener) clone() Listener {
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
	l.HTTP2 = cloneConfigPointer(l.HTTP2)
	return l
}

func (l Listener) validate(metricsEnabled, tracingEnabled bool) error {
	if *l.Port == 0 || *l.Port > 65535 {
		return fmt.Errorf("listener.port must be between 1 and 65535")
	}
	if err := validateObservabilityListenerPort(l.Port, metricsEnabled, tracingEnabled); err != nil {
		return err
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
		{maxStreamDurationFieldName, l.MaxStreamDuration}, {"stream_flush_timeout", l.StreamFlushTimeout},
		{"tls_handshake_timeout", l.TLSHandshakeTimeout},
	} {
		if err := validateDuration("listener."+value.name, value.value, false); err != nil {
			return err
		}
	}
	if *l.RequestHeadersTimeout > *l.RequestTimeout {
		return fmt.Errorf("listener.request_headers_timeout (%s) must not exceed listener.request_timeout (%s)", l.RequestHeadersTimeout, l.RequestTimeout)
	}
	if l.HTTP2 != nil {
		return l.HTTP2.validate("listener.http2")
	}
	return nil
}
