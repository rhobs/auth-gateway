package config

import (
	"fmt"
	"math"

	xdscore "github.com/cncf/xds/go/xds/core/v3"
	xdsmatcher "github.com/cncf/xds/go/xds/type/matcher/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	admissioncontrol "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/admission_control/v3"
	composite "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/composite/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoytype "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	admissionControlFilterName   = "envoy.filters.http.admission_control"
	admissionCompositeFilterName = "envoy.filters.http.composite"
)

// AdmissionControlConfig optionally sheds requests based on one API's success rate.
type AdmissionControlConfig struct {
	Enabled                 bool      `yaml:"enabled,omitempty"`
	SamplingWindow          *Duration `yaml:"sampling_window,omitempty"`
	SrThreshold             *float64  `yaml:"sr_threshold,omitempty"`
	RPSThreshold            *uint32   `yaml:"rps_threshold,omitempty"`
	MaxRejectionProbability *float64  `yaml:"max_rejection_probability,omitempty"`
}

func (c AdmissionControlConfig) clone() AdmissionControlConfig {
	c.SamplingWindow = clonePointer(c.SamplingWindow)
	c.SrThreshold = clonePointer(c.SrThreshold)
	c.RPSThreshold = clonePointer(c.RPSThreshold)
	c.MaxRejectionProbability = clonePointer(c.MaxRejectionProbability)
	return c
}

func (c AdmissionControlConfig) validate(name string) error {
	if err := validateDuration(name+".sampling_window", c.SamplingWindow, false); err != nil {
		return err
	}
	for _, value := range []struct {
		name  string
		value *float64
	}{
		{"sr_threshold", c.SrThreshold},
		{"max_rejection_probability", c.MaxRejectionProbability},
	} {
		if value.value == nil {
			continue
		}
		if math.IsNaN(*value.value) || math.IsInf(*value.value, 0) || *value.value < 0 || *value.value > 100 {
			return fmt.Errorf("%s.%s must be between 0 and 100", name, value.name)
		}
	}
	return nil
}

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

func (c Config) admissionHTTPFilter(hosts []indexedVirtualHost) (*hcm.HttpFilter, error) {
	// Named factories share one API's history across its routes and host bindings.
	chains := make(map[string]*composite.FilterChainConfiguration)
	apis := c.apisByName()
	for _, host := range hosts {
		for _, apiName := range c.Servers[host.serverIndex].APIs {
			api := apis[apiName]
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
			chains[name] = &composite.FilterChainConfiguration{TypedConfig: []*core.TypedExtensionConfig{{
				Name: admissionControlFilterName, TypedConfig: config,
			}}}
		}
	}
	if len(chains) == 0 {
		return nil, nil
	}
	config, err := packEnvoy(&composite.Composite{NamedFilterChains: chains})
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
		action, err := packEnvoy(&composite.ExecuteFilterAction{FilterChainName: admissionChainName(api.Name)})
		if err != nil {
			return fmt.Errorf("encode admission action for API %q: %w", api.Name, err)
		}
		selector, err := packEnvoy(&composite.CompositePerRoute{Matcher: &xdsmatcher.Matcher{
			OnNoMatch: &xdsmatcher.Matcher_OnMatch{OnMatch: &xdsmatcher.Matcher_OnMatch_Action{Action: &xdscore.TypedExtensionConfig{
				Name: "envoy.filters.http.composite.execute_filter_action", TypedConfig: action,
			}}},
		}})
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
