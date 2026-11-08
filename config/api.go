package config

import (
	"fmt"

	"google.golang.org/protobuf/types/known/structpb"
)

// API describes one upstream and its routes.
type API struct {
	Name             string                  `yaml:"name"`
	Routes           []Route                 `yaml:"routes"`
	Upstream         Upstream                `yaml:"upstream"`
	Metrics          *APIMetrics             `yaml:"metrics,omitempty"`
	AdmissionControl *AdmissionControlConfig `yaml:"admission_control,omitempty"`
	FaultInjection   *FaultInjectionConfig   `yaml:"fault_injection,omitempty"`
	CircuitBreakers  *CircuitBreakerConfig   `yaml:"circuit_breakers,omitempty"`
	Timeouts         *RouteTimeouts          `yaml:"timeouts,omitempty"`
}

func validateAPI(name string, api API, hasKubernetes bool) error {
	if !validHost(api.Upstream.Address) {
		return fmt.Errorf("%s.upstream.address must be an IP address or DNS name", name)
	}
	if api.Upstream.Port == 0 || api.Upstream.Port > 65535 {
		return fmt.Errorf("%s.upstream.port must be between 1 and 65535", name)
	}
	if err := api.Upstream.validate(name+".upstream", hasKubernetes); err != nil {
		return err
	}
	if err := validateRouteTimeouts(name+".timeouts", api.Timeouts); err != nil {
		return err
	}
	if err := validateAPIMetrics(name+".metrics", api.Metrics); err != nil {
		return err
	}
	if api.AdmissionControl != nil {
		if err := api.AdmissionControl.validate(name + ".admission_control"); err != nil {
			return err
		}
	}
	if api.FaultInjection != nil {
		if err := api.FaultInjection.validate(name + ".fault_injection"); err != nil {
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

func (a API) clone() API {
	a.Routes = cloneSlice(a.Routes)
	a.Upstream = a.Upstream.clone()
	a.Metrics = cloneConfigPointer(a.Metrics)
	a.AdmissionControl = cloneConfigPointer(a.AdmissionControl)
	a.FaultInjection = cloneConfigPointer(a.FaultInjection)
	if a.CircuitBreakers != nil {
		circuitBreakers := a.CircuitBreakers.clone()
		a.CircuitBreakers = &circuitBreakers
	}
	a.Timeouts = cloneConfigPointer(a.Timeouts)
	return a
}

func (api API) toRequestMetricsRouteMetadata() *structpb.Struct {
	labels := make(map[string]*structpb.Value, len(api.Metrics.Labels))
	for label, attribute := range api.Metrics.Labels {
		labels[label] = structpb.NewStringValue(attribute)
	}
	return &structpb.Struct{Fields: map[string]*structpb.Value{
		apiMetadataName: structpb.NewStringValue(api.Name),
		"labels":        structpb.NewStructValue(&structpb.Struct{Fields: labels}),
	}}
}
