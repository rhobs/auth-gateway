package config

import (
	"fmt"
	"time"

	"go.yaml.in/yaml/v3"
	"google.golang.org/protobuf/types/known/durationpb"
)

// NewDuration returns a pointer to a Duration with the given value.
func NewDuration(value time.Duration) *Duration {
	return new(Duration(value))
}

func (value *Duration) withDefault(fallback time.Duration) *Duration {
	return defaultValue(value, Duration(fallback))
}

// String returns the duration in Go's standard duration format.
func (duration *Duration) String() string { return time.Duration(*duration).String() }

// UnmarshalYAML parses and validates a duration string with units.
func (duration *Duration) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode || node.Tag != "!!str" || node.Value == "" {
		return &durationYAMLError{line: node.Line, column: node.Column, err: fmt.Errorf("must be a duration string with units, such as 250ms or 5s")}
	}
	value, err := time.ParseDuration(node.Value)
	if err != nil {
		return &durationYAMLError{line: node.Line, column: node.Column, err: fmt.Errorf("invalid duration %q: %w", node.Value, err)}
	}
	if err := validateDurationValue(Duration(value), true); err != nil {
		return &durationYAMLError{line: node.Line, column: node.Column, err: err}
	}
	*duration = Duration(value)
	return nil
}

// MarshalYAML validates the duration and returns its string form.
func (duration *Duration) MarshalYAML() (any, error) {
	if err := validateDurationValue(*duration, true); err != nil {
		return nil, err
	}
	return duration.String(), nil
}

func (duration *Duration) protobuf() *durationpb.Duration {
	return durationpb.New(time.Duration(*duration))
}

func validateDurationValue(value Duration, allowZero bool) error {
	if allowZero && value == 0 {
		return nil
	}
	if value < Duration(time.Millisecond) {
		return fmt.Errorf("must be at least 1ms, got %s", value.String())
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
