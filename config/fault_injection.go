package config

import (
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"

	xdscore "github.com/cncf/xds/go/xds/core/v3"
	xdsmatcher "github.com/cncf/xds/go/xds/type/matcher/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	composite "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/composite/v3"
	fault "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/fault/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	networkinput "github.com/envoyproxy/go-control-plane/envoy/extensions/matching/common_inputs/network/v3"
	matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	envoytype "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	faultFilterName          = "envoy.filters.http.fault"
	faultCompositeFilterName = "auth_gateway.fault_injection"
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

func (c FaultInjectionConfig) toEnvoy() *fault.HTTPFault {
	config := &fault.HTTPFault{
		Abort: &fault.FaultAbort{
			ErrorType:  &fault.FaultAbort_HttpStatus{HttpStatus: c.Abort.HTTPStatus},
			Percentage: &envoytype.FractionalPercent{Numerator: c.Abort.Percentage, Denominator: envoytype.FractionalPercent_HUNDRED},
		},
		DisableDownstreamClusterStats: true,
		FilterMetadata: &structpb.Struct{Fields: map[string]*structpb.Value{
			"fault_injected": structpb.NewBoolValue(true),
		}},
	}
	if c.Match != nil {
		for _, header := range slices.Sorted(maps.Keys(c.Match.Headers)) {
			config.Headers = append(config.Headers, &route.HeaderMatcher{
				Name: strings.ToLower(header), HeaderMatchSpecifier: &route.HeaderMatcher_StringMatch{
					StringMatch: &matcher.StringMatcher{MatchPattern: &matcher.StringMatcher_Exact{Exact: c.Match.Headers[header]}},
				},
			})
		}
	}
	return config
}

func (c effectiveConfig) faultHTTPFilter(hosts []indexedVirtualHost) (*hcm.HttpFilter, error) {
	chains := make(map[string]*composite.FilterChainConfiguration)
	for _, host := range hosts {
		for _, api := range c.servers[host.serverIndex].apis {
			if api.FaultInjection == nil || !api.FaultInjection.Enabled {
				continue
			}
			config, err := packEnvoy(api.FaultInjection.toEnvoy())
			if err != nil {
				return nil, fmt.Errorf("encode fault injection for API %q: %w", api.Name, err)
			}
			chains[api.Name] = &composite.FilterChainConfiguration{TypedConfig: []*core.TypedExtensionConfig{{Name: faultFilterName, TypedConfig: config}}}
		}
	}
	if len(chains) == 0 {
		return nil, nil
	}
	config, err := packEnvoy(&composite.Composite{NamedFilterChains: chains})
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
		perRoute, err := packEnvoy(&composite.CompositePerRoute{Matcher: selector})
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

func (c FaultInjectionConfig) toMatcher(chain string) (*xdsmatcher.Matcher, error) {
	action, err := packEnvoy(&composite.ExecuteFilterAction{FilterChainName: chain})
	if err != nil {
		return nil, err
	}
	onMatch := &xdsmatcher.Matcher_OnMatch{OnMatch: &xdsmatcher.Matcher_OnMatch_Action{Action: &xdscore.TypedExtensionConfig{
		Name: "envoy.filters.http.composite.execute_filter_action", TypedConfig: action,
	}}}
	if c.Match == nil || len(c.Match.Attributes) == 0 {
		return &xdsmatcher.Matcher{OnNoMatch: onMatch}, nil
	}
	var predicates []*xdsmatcher.Matcher_MatcherList_Predicate
	for _, attribute := range slices.Sorted(maps.Keys(c.Match.Attributes)) {
		input, err := packEnvoy(&networkinput.FilterStateInput{Key: filterStateKey(attribute)})
		if err != nil {
			return nil, err
		}
		var values []*xdsmatcher.Matcher_MatcherList_Predicate
		for _, value := range c.Match.Attributes[attribute] {
			values = append(values, &xdsmatcher.Matcher_MatcherList_Predicate{MatchType: &xdsmatcher.Matcher_MatcherList_Predicate_SinglePredicate_{SinglePredicate: &xdsmatcher.Matcher_MatcherList_Predicate_SinglePredicate{
				Input:   &xdscore.TypedExtensionConfig{Name: "envoy.matching.inputs.filter_state", TypedConfig: input},
				Matcher: &xdsmatcher.Matcher_MatcherList_Predicate_SinglePredicate_ValueMatch{ValueMatch: &xdsmatcher.StringMatcher{MatchPattern: &xdsmatcher.StringMatcher_Exact{Exact: value}}},
			}}})
		}
		predicate := values[0]
		if len(values) > 1 {
			predicate = &xdsmatcher.Matcher_MatcherList_Predicate{MatchType: &xdsmatcher.Matcher_MatcherList_Predicate_OrMatcher{OrMatcher: &xdsmatcher.Matcher_MatcherList_Predicate_PredicateList{Predicate: values}}}
		}
		predicates = append(predicates, predicate)
	}
	predicate := predicates[0]
	if len(predicates) > 1 {
		predicate = &xdsmatcher.Matcher_MatcherList_Predicate{MatchType: &xdsmatcher.Matcher_MatcherList_Predicate_AndMatcher{AndMatcher: &xdsmatcher.Matcher_MatcherList_Predicate_PredicateList{Predicate: predicates}}}
	}
	return &xdsmatcher.Matcher{MatcherType: &xdsmatcher.Matcher_MatcherList_{MatcherList: &xdsmatcher.Matcher_MatcherList{
		Matchers: []*xdsmatcher.Matcher_MatcherList_FieldMatcher{{Predicate: predicate, OnMatch: onMatch}},
	}}}, nil
}
