package api

import (
	"fmt"
	"time"

	yaml "go.yaml.in/yaml/v3"
)

type DurationYAMLError struct {
	Line   int
	Column int
	Err    error
}

// Duration is a Go duration encoded as a YAML string, such as 250ms or 5s.
// Zero is accepted only by settings that explicitly allow it.
type Duration time.Duration

// NewDuration returns a pointer to a Duration with the given value.
func NewDuration(value time.Duration) *Duration {
	return new(Duration(value))
}

// String returns the duration in Go's standard duration format.
func (duration *Duration) String() string { return time.Duration(*duration).String() }

// UnmarshalYAML parses and validates a duration string with units.
func (duration *Duration) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode || node.Tag != "!!str" || node.Value == "" {
		return &DurationYAMLError{Line: node.Line, Column: node.Column, Err: fmt.Errorf("must be a duration string with units, such as 250ms or 5s")}
	}
	value, err := time.ParseDuration(node.Value)
	if err != nil {
		return &DurationYAMLError{Line: node.Line, Column: node.Column, Err: fmt.Errorf("invalid duration %q: %w", node.Value, err)}
	}
	if err := ValidateDurationValue(Duration(value), true); err != nil {
		return &DurationYAMLError{Line: node.Line, Column: node.Column, Err: err}
	}
	*duration = Duration(value)
	return nil
}

// MarshalYAML validates the duration and returns its string form.
func (duration *Duration) MarshalYAML() (any, error) {
	if err := ValidateDurationValue(*duration, true); err != nil {
		return nil, err
	}
	return duration.String(), nil
}

func ValidateDurationValue(value Duration, allowZero bool) error {
	if allowZero && value == 0 {
		return nil
	}
	if value < Duration(time.Millisecond) {
		return fmt.Errorf("must be at least 1ms, got %s", value.String())
	}
	return nil
}

func (e *DurationYAMLError) Error() string { return fmt.Sprintf("line %d: %v", e.Line, e.Err) }
