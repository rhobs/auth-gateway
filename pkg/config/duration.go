package config

import (
	"fmt"
	"time"

	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	yaml "go.yaml.in/yaml/v3"
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
