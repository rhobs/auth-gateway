package config

import (
	"fmt"
	"maps"
	"net/http"
	"slices"
)

// FaultInjectionConfig optionally aborts requests to one API with HTTP errors.
type FaultInjectionConfig struct {
	Enabled bool              `yaml:"enabled,omitempty"`
	Abort   *FaultAbortConfig `yaml:"abort,omitempty"`
	Match   *FaultMatchConfig `yaml:"match,omitempty"`
}

// FaultMatchConfig limits faults to exact headers and authenticated attributes.
type FaultMatchConfig struct {
	Headers    map[string]string   `yaml:"headers,omitempty"`
	Attributes map[string][]string `yaml:"attributes,omitempty"`
}

// FaultAbortConfig sets the status and whole-number percentage of injected errors.
type FaultAbortConfig struct {
	HTTPStatus uint32 `yaml:"http_status"`
	Percentage uint32 `yaml:"percentage"`
}

func (c FaultInjectionConfig) clone() FaultInjectionConfig {
	c.Abort = cloneConfigPointer(c.Abort)
	c.Match = cloneConfigPointer(c.Match)
	return c
}

func (c FaultMatchConfig) clone() FaultMatchConfig {
	c.Headers = maps.Clone(c.Headers)
	c.Attributes = maps.Clone(c.Attributes)
	for name, values := range c.Attributes {
		c.Attributes[name] = slices.Clone(values)
	}
	return c
}

func (c FaultAbortConfig) clone() FaultAbortConfig {
	return c
}

func (c FaultInjectionConfig) validate(field string) error {
	if c.Match != nil {
		if err := c.Match.validate(field + ".match"); err != nil {
			return err
		}
	}
	if c.Abort == nil {
		if c.Enabled {
			return fmt.Errorf("%s.abort is required when enabled", field)
		}
		return nil
	}
	if c.Abort.HTTPStatus < http.StatusBadRequest || c.Abort.HTTPStatus >= 600 {
		return fmt.Errorf("%s.abort.http_status must be between 400 and 599", field)
	}
	if c.Abort.Percentage < 1 || c.Abort.Percentage > 100 {
		return fmt.Errorf("%s.abort.percentage must be between 1 and 100", field)
	}
	return nil
}
