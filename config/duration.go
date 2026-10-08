package config

import (
	"fmt"
	"time"

	"go.yaml.in/yaml/v3"
)

func (value *Duration) withDefault(fallback time.Duration) *Duration {
	return defaultValue(value, Duration(fallback))
}

func validateDurationValue(value Duration, allowZero bool) error {
	if allowZero && value == 0 {
		return nil
	}
	if value < Duration(time.Millisecond) {
		return fmt.Errorf("must be at least 1ms, got %s", value)
	}
	return nil
}

func validateDuration(name string, value *Duration, allowZero bool) error {
	if value == nil {
		return nil
	}
	if err := validateDurationValue(*value, allowZero); err != nil {
		return fmt.Errorf("%s %w", name, err)
	}
	return nil
}

type durationYAMLError struct {
	line   int
	column int
	err    error
}

func (e *durationYAMLError) Error() string { return fmt.Sprintf("line %d: %v", e.line, e.err) }

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
