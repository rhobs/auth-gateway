package config

import (
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"

	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
)

func cloneFaultInjectionConfig(c gatewayapi.FaultInjectionConfig) gatewayapi.FaultInjectionConfig {
	c.Abort = cloneConfigPointer(c.Abort, cloneFaultAbortConfig)
	c.Match = cloneConfigPointer(c.Match, cloneFaultMatchConfig)
	return c
}

func cloneFaultMatchConfig(c gatewayapi.FaultMatchConfig) gatewayapi.FaultMatchConfig {
	c.Headers = maps.Clone(c.Headers)
	c.Attributes = maps.Clone(c.Attributes)
	for name, values := range c.Attributes {
		c.Attributes[name] = slices.Clone(values)
	}
	return c
}

func cloneFaultAbortConfig(c gatewayapi.FaultAbortConfig) gatewayapi.FaultAbortConfig {
	return c
}

func validateFaultInjectionConfig(c gatewayapi.FaultInjectionConfig, field string) error {
	if c.Match != nil {
		if err := validateFaultMatchConfig(*c.Match, field+".match"); err != nil {
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

func validateFaultMatchConfig(c gatewayapi.FaultMatchConfig, field string) error {
	if len(c.Headers) == 0 && len(c.Attributes) == 0 {
		return fmt.Errorf("%s must contain headers or attributes", field)
	}
	seen := make(map[string]bool, len(c.Headers))
	for _, header := range slices.Sorted(maps.Keys(c.Headers)) {
		lower := strings.ToLower(header)
		if !validHeaderFieldName(header) || strings.Contains(header, "_") || ForbiddenIdentityHeader(lower) {
			return fmt.Errorf("%s.headers contains unsafe request header %q", field, header)
		}
		if seen[lower] {
			return fmt.Errorf("%s.headers contains duplicate header %q ignoring case", field, header)
		}
		seen[lower] = true
		if !validFaultMatchValue(c.Headers[header]) {
			return fmt.Errorf("%s.headers.%s must be nonempty and contain no control characters", field, header)
		}
	}
	for _, attribute := range slices.Sorted(maps.Keys(c.Attributes)) {
		if !AttributeNamePattern.MatchString(attribute) {
			return fmt.Errorf("%s.attributes contains invalid attribute name %q", field, attribute)
		}
		values := c.Attributes[attribute]
		if len(values) == 0 {
			return fmt.Errorf("%s.attributes.%s must contain at least one value", field, attribute)
		}
		seenValues := make(map[string]bool, len(values))
		for _, value := range values {
			if !validFaultMatchValue(value) || seenValues[value] {
				return fmt.Errorf("%s.attributes.%s must contain distinct nonempty values without control characters", field, attribute)
			}
			seenValues[value] = true
		}
	}
	return nil
}
