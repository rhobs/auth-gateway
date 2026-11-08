package envoy

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	xdsmatcher "github.com/cncf/xds/go/xds/type/matcher/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	fault "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/fault/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	envoytype "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	configuration "github.com/rhobs/auth-gateway/pkg/config"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	faultFilterName          = "envoy.filters.http.fault"
	faultCompositeFilterName = "auth_gateway.fault_injection"
)

func faultHTTPFilter(c configuration.ResolvedConfig, hosts []indexedVirtualHost) (*hcm.HttpFilter, error) {
	chains := make(compositeFilterChains)
	for _, host := range hosts {
		for _, api := range c.ResolvedServers[host.serverIndex].BoundAPIs {
			if api.FaultInjection == nil || !api.FaultInjection.Enabled {
				continue
			}
			config, err := packEnvoy(faultConfig(*api.FaultInjection))
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

func addAPIFaultRouteConfigs(routes []*route.Route, apis []gatewayapi.API) error {
	routesByName := make(map[string]*route.Route, len(routes))
	for _, generatedRoute := range routes {
		routesByName[generatedRoute.Name] = generatedRoute
	}
	for apiIndex, api := range apis {
		if api.FaultInjection == nil || !api.FaultInjection.Enabled {
			continue
		}
		selector, err := faultMatcher(*api.FaultInjection, api.Name)
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

func faultConfig(c gatewayapi.FaultInjectionConfig) *fault.HTTPFault {
	config := &fault.HTTPFault{
		Abort: &fault.FaultAbort{
			ErrorType:  &fault.FaultAbort_HttpStatus{HttpStatus: c.Abort.HTTPStatus},
			Percentage: &envoytype.FractionalPercent{Numerator: c.Abort.Percentage, Denominator: envoytype.FractionalPercent_HUNDRED},
		},
		DisableDownstreamClusterStats: true,
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

func faultMatcher(c gatewayapi.FaultInjectionConfig, chain string) (*xdsmatcher.Matcher, error) {
	action, err := compositeExecuteActionConfig(chain)
	if err != nil {
		return nil, err
	}
	onMatch := compositeAction(action)
	if c.Match == nil || len(c.Match.Attributes) == 0 {
		return &xdsmatcher.Matcher{OnNoMatch: onMatch}, nil
	}
	var predicates []*xdsmatcher.Matcher_MatcherList_Predicate
	for _, attribute := range slices.Sorted(maps.Keys(c.Match.Attributes)) {
		input, err := filterStateMatcherInput(filterStateKey(attribute))
		if err != nil {
			return nil, err
		}
		var values []*xdsmatcher.Matcher_MatcherList_Predicate
		for _, value := range c.Match.Attributes[attribute] {
			values = append(values, &xdsmatcher.Matcher_MatcherList_Predicate{MatchType: &xdsmatcher.Matcher_MatcherList_Predicate_SinglePredicate_{SinglePredicate: &xdsmatcher.Matcher_MatcherList_Predicate_SinglePredicate{
				Input:   input,
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
