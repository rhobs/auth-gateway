package gateway

import (
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"

	xdsmatcher "github.com/cncf/xds/go/xds/type/matcher/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	fault "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/fault/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	envoytype "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	faultFilterName          = "envoy.filters.http.fault"
	faultCompositeFilterName = "auth_gateway.fault_injection"
)

func cloneFaultInjectionConfig(c gatewayapi.FaultInjectionConfig) gatewayapi.FaultInjectionConfig {
	c.Abort = cloneConfigPointer(c.Abort, cloneFaultAbortConfig)
	c.Match = cloneConfigPointer(c.Match, cloneFaultMatchConfig)
	return c
}

func cloneFaultMatchConfig(c gatewayapi.FaultMatchConfig) gatewayapi.FaultMatchConfig {
	c.Headers = maps.Clone(c.Headers)
	c.Attributes = maps.Clone(c.Attributes)
	for name, values := range c.Attributes {
		c.Attributes[name] = slices.Clone(values)
	}
	return c
}

func cloneFaultAbortConfig(c gatewayapi.FaultAbortConfig) gatewayapi.FaultAbortConfig {
	return c
}

func validateFaultInjectionConfig(c gatewayapi.FaultInjectionConfig, field string) error {
	if c.Match != nil {
		if err := validateFaultMatchConfig(*c.Match, field+".match"); err != nil {
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

func validateFaultMatchConfig(c gatewayapi.FaultMatchConfig, field string) error {
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

func validateFaultAttributeSources(serverName string, server resolvedServer) error {
	for _, binding := range server.bindings {
		api := binding.api
		if api.FaultInjection == nil || api.FaultInjection.Match == nil {
			continue
		}
		for _, attribute := range slices.Sorted(maps.Keys(api.FaultInjection.Match.Attributes)) {
			missing := func() error {
				return fmt.Errorf("%s authentication does not provide fault_injection.match.attributes.%s for API %q", serverName, attribute, api.Name)
			}
			if len(binding.access) == 0 {
				return missing()
			}
			for _, access := range binding.access {
				if access.Authorization.ExtAuthz != nil {
					if _, exists := access.Authorization.ExtAuthz.ResponseAttributes[attribute]; exists {
						continue
					}
				}
				if len(access.authenticators) == 0 {
					return missing()
				}
				for _, authenticator := range access.authenticators {
					source, exists := authenticator.Attributes[attribute]
					if !exists {
						return missing()
					}
					if source.Header != nil {
						return fmt.Errorf("%s API %q fault_injection.match.attributes.%s requires an identity attribute, not a request header source", serverName, api.Name, attribute)
					}
				}
			}
		}
	}
	return nil
}

func hasFaultMatchAttributes(apis []gatewayapi.API) bool {
	for _, api := range apis {
		if api.FaultInjection != nil && api.FaultInjection.Enabled && api.FaultInjection.Match != nil && len(api.FaultInjection.Match.Attributes) > 0 {
			return true
		}
	}
	return false
}

func faultHTTPFilter(c resolvedConfig, hosts []indexedVirtualHost) (*hcm.HttpFilter, error) {
	chains := make(compositeFilterChains)
	for _, host := range hosts {
		for _, api := range c.servers[host.serverIndex].apis {
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
