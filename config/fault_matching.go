package config

import (
	"fmt"
	"maps"
	"slices"
	"strings"
)

func (c FaultMatchConfig) validate(field string) error {
	if len(c.Headers) == 0 && len(c.Attributes) == 0 {
		return fmt.Errorf("%s must contain headers or attributes", field)
	}
	seen := make(map[string]bool, len(c.Headers))
	for _, header := range slices.Sorted(maps.Keys(c.Headers)) {
		lower := strings.ToLower(header)
		if !validHeaderFieldName(header) || strings.Contains(header, "_") || forbiddenIdentityHeader(lower) {
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
		if !attributeNamePattern.MatchString(attribute) {
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

func validFaultMatchValue(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func validateFaultHeaderReferences(apis []API, apiKeyHeader string) error {
	for i, api := range apis {
		if api.FaultInjection == nil || api.FaultInjection.Match == nil {
			continue
		}
		for _, header := range slices.Sorted(maps.Keys(api.FaultInjection.Match.Headers)) {
			field := fmt.Sprintf("apis[%d].fault_injection.match.headers.%s", i, header)
			if strings.EqualFold(header, apiKeyHeader) {
				return fmt.Errorf("%s is reserved for API-key credentials", field)
			}
			for _, apiRoute := range api.Routes {
				if apiRoute.Processing == nil {
					continue
				}
				for _, mapping := range apiRoute.Processing.RequestHeaders {
					if strings.EqualFold(header, mapping.Name) {
						return fmt.Errorf("%s is overwritten by route processing", field)
					}
				}
			}
		}
	}
	return nil
}

func validateFaultAttributeSources(serverName string, server resolvedServer) error {
	for _, api := range server.apis {
		if api.FaultInjection == nil || api.FaultInjection.Match == nil {
			continue
		}
		for _, attribute := range slices.Sorted(maps.Keys(api.FaultInjection.Match.Attributes)) {
			provided := false
			for _, authenticator := range server.authenticators {
				source, exists := authenticator.Attributes[attribute]
				if !exists {
					continue
				}
				if source.Header != nil {
					return fmt.Errorf("%s API %q fault_injection.match.attributes.%s requires an identity attribute, not a request header source", serverName, api.Name, attribute)
				}
				provided = true
			}
			if !provided {
				return fmt.Errorf("%s authentication does not provide fault_injection.match.attributes.%s for API %q", serverName, attribute, api.Name)
			}
		}
	}
	return nil
}

func hasFaultMatchAttributes(apis []API) bool {
	for _, api := range apis {
		if api.FaultInjection != nil && api.FaultInjection.Enabled && api.FaultInjection.Match != nil && len(api.FaultInjection.Match.Attributes) > 0 {
			return true
		}
	}
	return false
}
