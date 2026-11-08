package config

import (
	"fmt"

	xdsmatcher "github.com/cncf/xds/go/xds/type/matcher/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	admissioncontrol "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/admission_control/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoytype "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const admissionControlFilterName = "envoy.filters.http.admission_control"

func (c AdmissionControlConfig) toEnvoy() *admissioncontrol.AdmissionControl {
	config := defaultAdmissionControlEnvoyConfig()
	config.Enabled = &core.RuntimeFeatureFlag{DefaultValue: wrapperspb.Bool(c.Enabled)}
	if c.SamplingWindow != nil {
		config.SamplingWindow = c.SamplingWindow.protobuf()
	}
	if c.SrThreshold != nil {
		config.SrThreshold = &core.RuntimePercent{DefaultValue: &envoytype.Percent{Value: *c.SrThreshold}}
	}
	if c.RPSThreshold != nil {
		config.RpsThreshold = &core.RuntimeUInt32{DefaultValue: *c.RPSThreshold}
	}
	if c.MaxRejectionProbability != nil {
		config.MaxRejectionProbability = &core.RuntimePercent{DefaultValue: &envoytype.Percent{Value: *c.MaxRejectionProbability}}
	}
	return config
}

func defaultAdmissionControlEnvoyConfig() *admissioncontrol.AdmissionControl {
	return &admissioncontrol.AdmissionControl{
		EvaluationCriteria: &admissioncontrol.AdmissionControl_SuccessCriteria_{SuccessCriteria: &admissioncontrol.AdmissionControl_SuccessCriteria{}},
	}
}

func admissionChainName(apiName string) string {
	return "admission-" + apiName
}

func (c effectiveConfig) admissionHTTPFilter(hosts []indexedVirtualHost) (*hcm.HttpFilter, error) {
	// Named factories share one API's history across its routes and host bindings.
	chains := make(compositeFilterChains)
	for _, host := range hosts {
		for _, api := range c.servers[host.serverIndex].apis {
			if api.AdmissionControl == nil || !api.AdmissionControl.Enabled {
				continue
			}
			name := admissionChainName(api.Name)
			if chains[name] != nil {
				continue
			}
			config, err := packEnvoy(api.AdmissionControl.toEnvoy())
			if err != nil {
				return nil, fmt.Errorf("encode admission control for API %q: %w", api.Name, err)
			}
			chains[name] = compositeChain(admissionControlFilterName, config)
		}
	}
	if len(chains) == 0 {
		return nil, nil
	}
	config, err := compositeConfig(chains)
	if err != nil {
		return nil, fmt.Errorf("encode admission composite filter: %w", err)
	}
	return &hcm.HttpFilter{Name: admissionCompositeFilterName, ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: config}}, nil
}

func addAPIAdmissionRouteConfigs(routes []*route.Route, apis []API) error {
	selectors := make(map[string]*anypb.Any)
	for _, api := range apis {
		if api.AdmissionControl == nil || !api.AdmissionControl.Enabled {
			continue
		}
		action, err := compositeExecuteActionConfig(admissionChainName(api.Name))
		if err != nil {
			return fmt.Errorf("encode admission action for API %q: %w", api.Name, err)
		}
		selector, err := compositePerRouteConfig(&xdsmatcher.Matcher{OnNoMatch: compositeAction(action)})
		if err != nil {
			return fmt.Errorf("encode admission selector for API %q: %w", api.Name, err)
		}
		selectors[apiClusterName(api.Name)] = selector
	}
	for _, generatedRoute := range routes {
		selector := selectors[generatedRoute.GetRoute().GetCluster()]
		if selector == nil {
			continue
		}
		if generatedRoute.TypedPerFilterConfig == nil {
			generatedRoute.TypedPerFilterConfig = make(map[string]*anypb.Any)
		}
		generatedRoute.TypedPerFilterConfig[admissionCompositeFilterName] = selector
	}
	return nil
}
