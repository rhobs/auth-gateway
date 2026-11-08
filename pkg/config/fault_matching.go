package config

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
)

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

func validateFaultHeaderReferences(apis []gatewayapi.API, apiKeyHeader string) error {
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

func validateFaultAttributeSources(serverName string, server ResolvedServer) error {
	for _, api := range server.BoundAPIs {
		if api.FaultInjection == nil || api.FaultInjection.Match == nil {
			continue
		}
		for _, attribute := range slices.Sorted(maps.Keys(api.FaultInjection.Match.Attributes)) {
			provided := false
			for _, authenticator := range server.Authenticators {
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

func HasFaultMatchAttributes(apis []gatewayapi.API) bool {
	for _, api := range apis {
		if api.FaultInjection != nil && api.FaultInjection.Enabled && api.FaultInjection.Match != nil && len(api.FaultInjection.Match.Attributes) > 0 {
			return true
		}
	}
	return false
}
