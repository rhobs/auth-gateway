package config

import (
	"fmt"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
)

// HTTP2Options bounds streams and flow-control windows on one HTTP/2 connection.
// Omitted fields retain Envoy's defaults.
type HTTP2Options struct {
	MaxConcurrentStreams        *uint32 `yaml:"max_concurrent_streams,omitempty"`
	InitialStreamWindowSize     *uint32 `yaml:"initial_stream_window_size,omitempty"`
	InitialConnectionWindowSize *uint32 `yaml:"initial_connection_window_size,omitempty"`
}

func (h HTTP2Options) clone() HTTP2Options {
	h.MaxConcurrentStreams = clonePointer(h.MaxConcurrentStreams)
	h.InitialStreamWindowSize = clonePointer(h.InitialStreamWindowSize)
	h.InitialConnectionWindowSize = clonePointer(h.InitialConnectionWindowSize)
	return h
}

func (h HTTP2Options) validate(name string) error {
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

func (h HTTP2Options) envoy() *core.Http2ProtocolOptions {
	return &core.Http2ProtocolOptions{
		MaxConcurrentStreams:        optionalUint32(h.MaxConcurrentStreams),
		InitialStreamWindowSize:     optionalUint32(h.InitialStreamWindowSize),
		InitialConnectionWindowSize: optionalUint32(h.InitialConnectionWindowSize),
	}
}
