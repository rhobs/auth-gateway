package gateway

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	xdsmatcher "github.com/cncf/xds/go/xds/type/matcher/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	fault "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/fault/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	envoytype "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
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
	c.Headers = cloneMatchExpressions(c.Headers)
	c.Attributes = cloneMatchExpressions(c.Attributes)
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
	for i, condition := range c.Headers {
		conditionField := fmt.Sprintf("%s.headers[%d]", field, i)
		lower := strings.ToLower(condition.Name)
		if !validHeaderFieldName(condition.Name) || strings.Contains(condition.Name, "_") || forbiddenIdentityHeader(lower) {
			return fmt.Errorf("%s contains unsafe request header %q", conditionField, condition.Name)
		}
		if seen[lower] {
			return fmt.Errorf("%s duplicates header %q ignoring case", conditionField, condition.Name)
		}
		seen[lower] = true
		if err := validateFaultExpression(conditionField, condition); err != nil {
			return err
		}
	}
	seen = make(map[string]bool, len(c.Attributes))
	for i, condition := range c.Attributes {
		conditionField := fmt.Sprintf(attributeIndexFieldFormat, field, i)
		if !attributeNamePattern.MatchString(condition.Name) {
			return fmt.Errorf("%s contains invalid attribute name %q", conditionField, condition.Name)
		}
		if seen[condition.Name] {
			return fmt.Errorf("%s duplicates attribute %q", conditionField, condition.Name)
		}
		seen[condition.Name] = true
		if err := validateFaultExpression(conditionField, condition); err != nil {
			return err
		}
	}
	return nil
}

func validateFaultExpression(field string, condition gatewayapi.MatchExpression) error {
	if condition.Expression != gatewayapi.ExpressionEquals && condition.Expression != gatewayapi.ExpressionIn && condition.Expression != gatewayapi.ExpressionPresent {
		return fmt.Errorf("%s.expression must be equals, in, or present", field)
	}
	return validateMatchExpression(field, condition, false)
}

func validateFaultBindings(serverName string, server resolvedServer, apiKeyHeader string) error {
	for i, binding := range server.bindings {
		if binding.FaultInjection == nil {
			continue
		}
		field := fmt.Sprintf("%s.apis[%d].fault_injection", serverName, i)
		if err := validateFaultInjectionConfig(*binding.FaultInjection, field); err != nil {
			return err
		}
		if binding.FaultInjection.Match == nil {
			continue
		}
		for j, condition := range binding.FaultInjection.Match.Headers {
			header := condition.Name
			conditionField := fmt.Sprintf("%s.match.headers[%d]", field, j)
			if strings.EqualFold(header, apiKeyHeader) {
				return fmt.Errorf("%s is reserved for API-key credentials", conditionField)
			}
			for _, apiRoute := range binding.api.Routes {
				if apiRoute.Processing == nil {
					continue
				}
				for _, mapping := range apiRoute.Processing.RequestHeaders {
					if strings.EqualFold(header, mapping.Name) {
						return fmt.Errorf("%s is overwritten by route processing", conditionField)
					}
				}
			}
		}
	}
	return nil
}

func validateFaultAttributeSources(serverName string, server resolvedServer, services map[string]gatewayapi.ExternalAuthorizationService) error {
	for _, binding := range server.bindings {
		if binding.FaultInjection == nil || binding.FaultInjection.Match == nil {
			continue
		}
		for _, condition := range binding.FaultInjection.Match.Attributes {
			attribute := condition.Name
			missing := func() error {
				return fmt.Errorf("%s authentication does not provide fault_injection.match.attributes.%s for API %q", serverName, attribute, binding.Name)
			}
			if len(binding.access) == 0 {
				return missing()
			}
			for _, access := range binding.access {
				if access.Authorization.ExtAuthz != nil {
					service := services[access.Authorization.ExtAuthz.Service]
					if source, exists := extAuthzAttribute(service, attribute); exists && source.FromSource == attributeSourceHeader {
						return fmt.Errorf("%s API %q fault_injection.match.attributes.%s requires an identity attribute, not a request header source", serverName, binding.Name, attribute)
					}
					if extAuthzProvidesAttribute(access, service, attribute) {
						continue
					}
				}
				if len(access.authenticators) == 0 {
					return missing()
				}
				for _, authenticator := range access.authenticators {
					source, exists := authenticatorAttribute(authenticator, attribute)
					if !exists {
						return missing()
					}
					if source.FromSource == attributeSourceHeader {
						return fmt.Errorf("%s API %q fault_injection.match.attributes.%s requires an identity attribute, not a request header source", serverName, binding.Name, attribute)
					}
				}
			}
		}
	}
	return nil
}

func hasFaultMatchAttributes(servers []gatewayapi.Server) bool {
	for _, server := range servers {
		for _, binding := range server.APIs {
			if binding.FaultInjection != nil && binding.FaultInjection.Enabled && binding.FaultInjection.Match != nil && len(binding.FaultInjection.Match.Attributes) > 0 {
				return true
			}
		}
	}
	return false
}

func faultHTTPFilter(c resolvedConfig, hosts []indexedVirtualHost) (*hcm.HttpFilter, error) {
	chains := make(compositeFilterChains)
	for _, host := range hosts {
		for bindingIndex, binding := range c.servers[host.serverIndex].bindings {
			if binding.FaultInjection == nil || !binding.FaultInjection.Enabled {
				continue
			}
			config, err := packEnvoy(faultConfig(*binding.FaultInjection))
			if err != nil {
				return nil, fmt.Errorf("encode fault injection for API %q: %w", binding.Name, err)
			}
			chains[faultChainName(host.serverIndex, bindingIndex)] = compositeChain(faultFilterName, config)
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

func faultChainName(serverIndex, bindingIndex int) string {
	return fmt.Sprintf("server-%d-api-%d", serverIndex, bindingIndex)
}

func addFaultRouteConfig(generated *route.Route, binding resolvedAPIBinding, serverIndex int) error {
	if binding.FaultInjection == nil || !binding.FaultInjection.Enabled {
		return nil
	}
	selector, err := faultMatcher(*binding.FaultInjection, faultChainName(serverIndex, binding.index))
	if err != nil {
		return fmt.Errorf("encode fault selector for API %q: %w", binding.Name, err)
	}
	perRoute, err := compositePerRouteConfig(selector)
	if err != nil {
		return fmt.Errorf("encode fault injection for API %q: %w", binding.Name, err)
	}
	generated.TypedPerFilterConfig[faultCompositeFilterName] = perRoute
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
		for _, condition := range sortedMatchExpressions(c.Match.Headers) {
			header := &route.HeaderMatcher{Name: strings.ToLower(condition.Name)}
			switch condition.Expression {
			case gatewayapi.ExpressionPresent:
				header.HeaderMatchSpecifier = &route.HeaderMatcher_PresentMatch{PresentMatch: true}
			case gatewayapi.ExpressionIn:
				alternatives := make([]string, 0, len(condition.Value.Items))
				for _, value := range condition.Value.Items {
					alternatives = append(alternatives, regexp.QuoteMeta(value))
				}
				header.HeaderMatchSpecifier = &route.HeaderMatcher_StringMatch{StringMatch: &matcher.StringMatcher{MatchPattern: &matcher.StringMatcher_SafeRegex{SafeRegex: &matcher.RegexMatcher{Regex: "^(?:" + strings.Join(alternatives, "|") + ")$"}}}}
			default:
				header.HeaderMatchSpecifier = &route.HeaderMatcher_StringMatch{StringMatch: &matcher.StringMatcher{MatchPattern: &matcher.StringMatcher_Exact{Exact: condition.Value.Text}}}
			}
			config.Headers = append(config.Headers, header)
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
	for _, condition := range sortedMatchExpressions(c.Match.Attributes) {
		input, err := filterStateMatcherInput(filterStateKey(condition.Name))
		if err != nil {
			return nil, err
		}
		var values []*xdsmatcher.Matcher_MatcherList_Predicate
		matchers := make([]*xdsmatcher.StringMatcher, 0, 1)
		if condition.Expression == gatewayapi.ExpressionPresent {
			matchers = append(matchers, &xdsmatcher.StringMatcher{MatchPattern: &xdsmatcher.StringMatcher_SafeRegex{SafeRegex: &xdsmatcher.RegexMatcher{
				EngineType: &xdsmatcher.RegexMatcher_GoogleRe2{GoogleRe2: &xdsmatcher.RegexMatcher_GoogleRE2{}},
				Regex:      ".+",
			}}})
		} else {
			for _, value := range matchValues(condition) {
				matchers = append(matchers, &xdsmatcher.StringMatcher{MatchPattern: &xdsmatcher.StringMatcher_Exact{Exact: value}})
			}
		}
		for _, valueMatcher := range matchers {
			values = append(values, &xdsmatcher.Matcher_MatcherList_Predicate{MatchType: &xdsmatcher.Matcher_MatcherList_Predicate_SinglePredicate_{SinglePredicate: &xdsmatcher.Matcher_MatcherList_Predicate_SinglePredicate{
				Input:   input,
				Matcher: &xdsmatcher.Matcher_MatcherList_Predicate_SinglePredicate_ValueMatch{ValueMatch: valueMatcher},
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
