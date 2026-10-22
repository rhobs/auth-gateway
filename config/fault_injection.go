package config

import (
	"fmt"
	"net/http"

	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	fault "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/fault/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoytype "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/protobuf/types/known/anypb"
)

const faultFilterName = "envoy.filters.http.fault"

// FaultInjectionConfig optionally aborts requests to one API with HTTP errors.
type FaultInjectionConfig struct {
	Enabled bool              `yaml:"enabled,omitempty"`
	Abort   *FaultAbortConfig `yaml:"abort,omitempty"`
}

// FaultAbortConfig sets the status and whole-number percentage of injected errors.
type FaultAbortConfig struct {
	HTTPStatus uint32 `yaml:"http_status"`
	Percentage uint32 `yaml:"percentage"`
}

func (c FaultInjectionConfig) clone() FaultInjectionConfig {
	c.Abort = cloneConfigPointer(c.Abort)
	return c
}

func (c FaultAbortConfig) clone() FaultAbortConfig {
	return c
}

func (c FaultInjectionConfig) validate(field string) error {
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

func (c FaultInjectionConfig) toEnvoy() *fault.HTTPFault {
	return envoyHTTPFault(*c.Abort)
}

func envoyHTTPFault(abort FaultAbortConfig) *fault.HTTPFault {
	return &fault.HTTPFault{
		Abort: &fault.FaultAbort{
			ErrorType:  &fault.FaultAbort_HttpStatus{HttpStatus: abort.HTTPStatus},
			Percentage: &envoytype.FractionalPercent{Numerator: abort.Percentage, Denominator: envoytype.FractionalPercent_HUNDRED},
		},
		DisableDownstreamClusterStats: true,
	}
}

func faultHTTPFilter() (*hcm.HttpFilter, error) {
	// Unconfigured routes inherit this zero-percent policy. Enabled API routes
	// override it with their own policy below.
	config, err := packEnvoy(envoyHTTPFault(FaultAbortConfig{HTTPStatus: http.StatusServiceUnavailable}))
	if err != nil {
		return nil, fmt.Errorf("encode fault filter: %w", err)
	}
	return &hcm.HttpFilter{Name: faultFilterName, ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: config}}, nil
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
		perRoute, err := packEnvoy(api.FaultInjection.toEnvoy())
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
				generatedRoute.TypedPerFilterConfig[faultFilterName] = perRoute
			}
		}
	}
	return nil
}

func hasFaultRouteConfigs(hosts []indexedVirtualHost) bool {
	for _, host := range hosts {
		for _, generatedRoute := range host.host.Routes {
			if generatedRoute.TypedPerFilterConfig[faultFilterName] != nil {
				return true
			}
		}
	}
	return false
}
