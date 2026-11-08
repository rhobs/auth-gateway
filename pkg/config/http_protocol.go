package config

import (
	"fmt"

	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
)

func cloneHTTP2Options(h gatewayapi.HTTP2Options) gatewayapi.HTTP2Options {
	h.MaxConcurrentStreams = clonePointer(h.MaxConcurrentStreams)
	h.InitialStreamWindowSize = clonePointer(h.InitialStreamWindowSize)
	h.InitialConnectionWindowSize = clonePointer(h.InitialConnectionWindowSize)
	return h
}

func validateHTTP2Options(h gatewayapi.HTTP2Options, name string) error {
	for _, value := range []struct {
		Name  string
		Value *uint32
		Min   uint32
	}{
		{"max_concurrent_streams", h.MaxConcurrentStreams, 1},
		{"initial_stream_window_size", h.InitialStreamWindowSize, 65535},
		{"initial_connection_window_size", h.InitialConnectionWindowSize, 65535},
	} {
		if value.Value != nil && (*value.Value < value.Min || *value.Value > 2147483647) {
			return fmt.Errorf("%s.%s must be between %d and 2147483647", name, value.Name, value.Min)
		}
	}
	return nil
}
