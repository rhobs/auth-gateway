package config

import (
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"

	xdsmatcher "github.com/cncf/xds/go/xds/type/matcher/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	fault "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/fault/v3"
	matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	envoytype "github.com/envoyproxy/go-control-plane/envoy/type/v3"
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

func (c FaultInjectionConfig) toMatcher(chain string) (*xdsmatcher.Matcher, error) {
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

func (c FaultMatchConfig) validate(field string) error {
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
