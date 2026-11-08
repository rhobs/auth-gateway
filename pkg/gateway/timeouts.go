package gateway

import (
	"fmt"
	"time"

	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	yaml "go.yaml.in/yaml/v3"
)

const (
	maxStreamDurationFieldName = "max_stream_duration"
)

func withDefaultDuration(value *gatewayapi.Duration, fallback time.Duration) *gatewayapi.Duration {
	return defaultValue(value, gatewayapi.Duration(fallback))
}

func validateDuration(name string, value *gatewayapi.Duration, allowZero bool) error {
	if value == nil {
		return nil
	}
	if err := gatewayapi.ValidateDurationValue(*value, allowZero); err != nil {
		return fmt.Errorf("%s %w", name, err)
	}
	return nil
}

func yamlPathAtPosition(node *yaml.Node, line, column int, prefix string) string {
	if node.Line == line && node.Column == column && prefix != "" {
		return prefix
	}
	switch node.Kind {
	case yaml.DocumentNode:
		for _, child := range node.Content {
			if found := yamlPathAtPosition(child, line, column, prefix); found != "" {
				return found
			}
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			name := node.Content[i].Value
			if prefix != "" {
				name = prefix + "." + name
			}
			if found := yamlPathAtPosition(node.Content[i+1], line, column, name); found != "" {
				return found
			}
		}
	case yaml.SequenceNode:
		for i, child := range node.Content {
			if found := yamlPathAtPosition(child, line, column, fmt.Sprintf("%s[%d]", prefix, i)); found != "" {
				return found
			}
		}
	}
	return ""
}

func validateRouteTimeouts(name string, t *gatewayapi.RouteTimeouts) error {
	if t == nil {
		return nil
	}
	for _, value := range []struct {
		Name  string
		Value *gatewayapi.Duration
	}{
		{"response_timeout", t.ResponseTimeout}, {"idle_timeout", t.IdleTimeout}, {maxStreamDurationFieldName, t.MaxStreamDuration},
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
