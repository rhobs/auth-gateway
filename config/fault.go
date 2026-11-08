package config

import (
	"fmt"

	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	faultFilterName          = "envoy.filters.http.fault"
	faultCompositeFilterName = "auth_gateway.fault_injection"
)

func faultHTTPFilter(c effectiveConfig, hosts []indexedVirtualHost) (*hcm.HttpFilter, error) {
	chains := make(compositeFilterChains)
	for _, host := range hosts {
		for _, api := range c.servers[host.serverIndex].apis {
			if api.FaultInjection == nil || !api.FaultInjection.Enabled {
				continue
			}
			config, err := packEnvoy(api.FaultInjection.toEnvoy())
			if err != nil {
				return nil, fmt.Errorf("encode fault injection for API %q: %w", api.Name, err)
			}
			chains[api.Name] = compositeChain(faultFilterName, config)
		}
	}
	if len(chains) == 0 {
		return nil, nil
	}
	config, err := compositeConfig(chains)
	if err != nil {
		return nil, fmt.Errorf("encode fault filter: %w", err)
	}
	return &hcm.HttpFilter{Name: faultCompositeFilterName, ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: config}}, nil
}

func addAPIFaultRouteConfigs(routes []*route.Route, apis []API) error {
	routesByName := make(map[string]*route.Route, len(routes))
	for _, generatedRoute := range routes {
		routesByName[generatedRoute.Name] = generatedRoute
	}
	for apiIndex, api := range apis {
		if api.FaultInjection == nil || !api.FaultInjection.Enabled {
			continue
		}
		selector, err := api.FaultInjection.toMatcher(api.Name)
		if err != nil {
			return fmt.Errorf("encode fault selector for API %q: %w", api.Name, err)
		}
		perRoute, err := compositePerRouteConfig(selector)
		if err != nil {
			return fmt.Errorf("encode fault injection for API %q: %w", api.Name, err)
		}
		for routeIndex, apiRoute := range api.Routes {
			for methodIndex := range apiRoute.Methods {
				name := apiRouteName(apiIndex, api.Name, routeIndex, methodIndex)
				generatedRoute := routesByName[name]
				if generatedRoute == nil {
					return fmt.Errorf("generated route %q is missing", name)
				}
				if generatedRoute.TypedPerFilterConfig == nil {
					generatedRoute.TypedPerFilterConfig = make(map[string]*anypb.Any)
				}
				generatedRoute.TypedPerFilterConfig[faultCompositeFilterName] = perRoute
			}
		}
	}
	return nil
}
