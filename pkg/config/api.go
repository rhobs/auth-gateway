package config

import (
	"fmt"

	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
)

func validateAPI(name string, api gatewayapi.API, hasKubernetes bool) error {
	if !validHost(api.Upstream.Address) {
		return fmt.Errorf("%s.upstream.address must be an IP address or DNS name", name)
	}
	if api.Upstream.Port == 0 || api.Upstream.Port > 65535 {
		return fmt.Errorf("%s.upstream.port must be between 1 and 65535", name)
	}
	if err := validateUpstream(api.Upstream, name+".upstream", hasKubernetes); err != nil {
		return err
	}
	if err := validateRouteTimeouts(name+".timeouts", api.Timeouts); err != nil {
		return err
	}
	if err := validateAPIMetrics(name+".metrics", api.Metrics); err != nil {
		return err
	}
	if api.AdmissionControl != nil {
		if err := validateAdmissionControlConfig(*api.AdmissionControl, name+".admission_control"); err != nil {
			return err
		}
	}
	if api.FaultInjection != nil {
		if err := validateFaultInjectionConfig(*api.FaultInjection, name+".fault_injection"); err != nil {
			return err
		}
	}
	if len(api.Routes) == 0 {
		return fmt.Errorf("%s.routes must contain at least one route", name)
	}
	routes := make(map[string]struct{}, len(api.Routes))
	for routeIndex, route := range api.Routes {
		routeName := fmt.Sprintf("%s.routes[%d]", name, routeIndex)
		if err := validateAPIRoute(routeName, route, routes); err != nil {
			return err
		}
	}
	return nil
}

func cloneAPI(a gatewayapi.API) gatewayapi.API {
	a.Routes = cloneSlice(a.Routes, cloneRoute)
	a.Upstream = cloneUpstream(a.Upstream)
	a.Metrics = cloneConfigPointer(a.Metrics, cloneAPIMetrics)
	a.AdmissionControl = cloneConfigPointer(a.AdmissionControl, cloneAdmissionControlConfig)
	a.FaultInjection = cloneConfigPointer(a.FaultInjection, cloneFaultInjectionConfig)
	if a.CircuitBreakers != nil {
		circuitBreakers := cloneCircuitBreakerConfig(a.CircuitBreakers)
		a.CircuitBreakers = &circuitBreakers
	}
	a.Timeouts = cloneConfigPointer(a.Timeouts, cloneRouteTimeouts)
	return a
}
