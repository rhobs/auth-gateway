package config

import (
	"time"
)

const maxStreamDurationFieldName = "max_stream_duration"

// RouteTimeouts overrides API or listener fallbacks independently for each timer.
type RouteTimeouts struct {
	ResponseTimeout   *Duration `yaml:"response_timeout,omitempty"`
	IdleTimeout       *Duration `yaml:"idle_timeout,omitempty"`
	MaxStreamDuration *Duration `yaml:"max_stream_duration,omitempty"`
}

func validateRouteTimeouts(name string, t *RouteTimeouts) error {
	if t == nil {
		return nil
	}
	for _, value := range []struct {
		name  string
		value *Duration
	}{
		{"response_timeout", t.ResponseTimeout}, {"idle_timeout", t.IdleTimeout}, {maxStreamDurationFieldName, t.MaxStreamDuration},
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

func (t RouteTimeouts) clone() RouteTimeouts {
	t.ResponseTimeout = clonePointer(t.ResponseTimeout)
	t.IdleTimeout = clonePointer(t.IdleTimeout)
	t.MaxStreamDuration = clonePointer(t.MaxStreamDuration)
	return t
}
