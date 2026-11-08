package config

import (
	"time"

	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
)

const MaxStreamDurationFieldName = "max_stream_duration"

func validateRouteTimeouts(name string, t *gatewayapi.RouteTimeouts) error {
	if t == nil {
		return nil
	}
	for _, value := range []struct {
		Name  string
		Value *gatewayapi.Duration
	}{
		{"response_timeout", t.ResponseTimeout}, {"idle_timeout", t.IdleTimeout}, {MaxStreamDurationFieldName, t.MaxStreamDuration},
	} {
		if err := validateDuration(name+"."+value.Name, value.Value, false); err != nil {
			return err
		}
	}
	return nil
}

func resolveRouteTimeouts(l gatewayapi.Listener, api, route *gatewayapi.RouteTimeouts) *gatewayapi.RouteTimeouts {
	resolved := &gatewayapi.RouteTimeouts{
		ResponseTimeout:   new(gatewayapi.Duration(30 * time.Second)),
		IdleTimeout:       clonePointer(l.StreamIdleTimeout),
		MaxStreamDuration: clonePointer(l.MaxStreamDuration),
	}
	for _, overrides := range []*gatewayapi.RouteTimeouts{api, route} {
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

func cloneRouteTimeouts(t gatewayapi.RouteTimeouts) gatewayapi.RouteTimeouts {
	t.ResponseTimeout = clonePointer(t.ResponseTimeout)
	t.IdleTimeout = clonePointer(t.IdleTimeout)
	t.MaxStreamDuration = clonePointer(t.MaxStreamDuration)
	return t
}
