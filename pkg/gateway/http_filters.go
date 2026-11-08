package gateway

import (
	"fmt"

	xdscore "github.com/cncf/xds/go/xds/core/v3"
	xdsmatcher "github.com/cncf/xds/go/xds/type/matcher/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	matching "github.com/envoyproxy/go-control-plane/envoy/extensions/common/matching/v3"
	skip "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/common/matcher/action/v3"
	composite "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/composite/v3"
	router "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	networkinput "github.com/envoyproxy/go-control-plane/envoy/extensions/matching/common_inputs/network/v3"
	matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	admissionCompositeFilterName = "envoy.filters.http.composite"
	routerFilterName             = "envoy.filters.http.router"
)

type compositeFilterChains map[string]*composite.FilterChainConfiguration

func compositeChain(name string, config *anypb.Any) *composite.FilterChainConfiguration {
	return &composite.FilterChainConfiguration{TypedConfig: []*core.TypedExtensionConfig{{Name: name, TypedConfig: config}}}
}

func compositeConfig(chains compositeFilterChains) (*anypb.Any, error) {
	return packEnvoy(&composite.Composite{NamedFilterChains: chains})
}

func compositeExecuteActionConfig(chain string) (*anypb.Any, error) {
	return packEnvoy(&composite.ExecuteFilterAction{FilterChainName: chain})
}

func compositeAction(config *anypb.Any) *xdsmatcher.Matcher_OnMatch {
	return &xdsmatcher.Matcher_OnMatch{OnMatch: &xdsmatcher.Matcher_OnMatch_Action{Action: &xdscore.TypedExtensionConfig{
		Name: "envoy.filters.http.composite.execute_filter_action", TypedConfig: config,
	}}}
}

func compositePerRouteConfig(m *xdsmatcher.Matcher) (*anypb.Any, error) {
	return packEnvoy(&composite.CompositePerRoute{Matcher: m})
}

func toAPIKeyPerRouteConfig(c resolvedConfig, server resolvedServer) (*anypb.Any, error) {
	config := &matching.ExtensionWithMatcherPerRoute{}
	if server.mixedAnyOf() {
		matcher, err := toAPIKeySkipMatcher(c, server)
		if err != nil {
			return nil, err
		}
		config.XdsMatcher = matcher
	}
	perRoute, err := packEnvoy(config)
	if err != nil {
		return nil, err
	}
	return packEnvoy(&route.FilterConfig{Config: perRoute})
}

func toAPIKeySkipMatcher(c resolvedConfig, server resolvedServer) (*xdsmatcher.Matcher, error) {
	action, err := apiKeySkipAction()
	if err != nil {
		return nil, err
	}
	var fields []*xdsmatcher.Matcher_MatcherList_FieldMatcher
	for _, authenticator := range server.authenticators {
		if authenticator.JWT == nil {
			continue
		}
		input, err := requestHeaderMatcherInput(jwtVerifiedHeaderName(authenticator.Name))
		if err != nil {
			return nil, fmt.Errorf("encode JWT marker input: %w", err)
		}
		fields = append(fields, &xdsmatcher.Matcher_MatcherList_FieldMatcher{
			Predicate: &xdsmatcher.Matcher_MatcherList_Predicate{MatchType: &xdsmatcher.Matcher_MatcherList_Predicate_SinglePredicate_{SinglePredicate: &xdsmatcher.Matcher_MatcherList_Predicate_SinglePredicate{
				Input:   input,
				Matcher: &xdsmatcher.Matcher_MatcherList_Predicate_SinglePredicate_ValueMatch{ValueMatch: &xdsmatcher.StringMatcher{MatchPattern: &xdsmatcher.StringMatcher_Exact{Exact: authenticator.JWT.Issuer}}},
			}}},
			OnMatch: action,
		})
	}
	if server.usesMTLS() {
		input, err := requestHeaderMatcherInput(mtlsFingerprintHeaderName)
		if err != nil {
			return nil, fmt.Errorf("encode mTLS marker input: %w", err)
		}
		fields = append(fields, &xdsmatcher.Matcher_MatcherList_FieldMatcher{
			Predicate: &xdsmatcher.Matcher_MatcherList_Predicate{MatchType: &xdsmatcher.Matcher_MatcherList_Predicate_SinglePredicate_{SinglePredicate: &xdsmatcher.Matcher_MatcherList_Predicate_SinglePredicate{
				Input: input,
				Matcher: &xdsmatcher.Matcher_MatcherList_Predicate_SinglePredicate_ValueMatch{ValueMatch: &xdsmatcher.StringMatcher{
					MatchPattern: &xdsmatcher.StringMatcher_SafeRegex{SafeRegex: &xdsmatcher.RegexMatcher{
						EngineType: &xdsmatcher.RegexMatcher_GoogleRe2{GoogleRe2: &xdsmatcher.RegexMatcher_GoogleRE2{}},
						Regex:      mtlsFingerprintPattern,
					}},
				}},
			}}},
			OnMatch: action,
		})
	}
	return &xdsmatcher.Matcher{MatcherType: &xdsmatcher.Matcher_MatcherList_{MatcherList: &xdsmatcher.Matcher_MatcherList{Matchers: fields}}}, nil
}

func extensionWithMatcherConfig(config *core.TypedExtensionConfig) (*anypb.Any, error) {
	return packEnvoy(&matching.ExtensionWithMatcher{ExtensionConfig: config})
}

func extensionWithMatcherTypeName() string {
	return string((&matching.ExtensionWithMatcher{}).ProtoReflect().Descriptor().FullName())
}

func toHTTPFilters(c resolvedConfig, hosts []indexedVirtualHost, protected bool) ([]*hcm.HttpFilter, error) {
	filters, err := requestControlFilters(c, routeVirtualHosts(hosts))
	if err != nil {
		return nil, err
	}
	if protected {
		filters, err = protectedHTTPFilters(c, filters, hosts)
		if err != nil {
			return nil, err
		}
	}
	if (c.usesAPIKeys() || c.usesJWT() || c.usesMTLS()) && !protected {
		cleanup, err := toCredentialCleanupFilter(c)
		if err != nil {
			return nil, err
		}
		filters = append(filters, cleanup)
	}
	fault, err := faultHTTPFilter(c, hosts)
	if err != nil {
		return nil, err
	}
	if fault != nil {
		filters = append(filters, fault)
	}
	admission, err := admissionHTTPFilter(c, hosts)
	if err != nil {
		return nil, err
	}
	if admission != nil {
		filters = append(filters, admission)
	}
	terminalRouter, err := routerHTTPFilter()
	if err != nil {
		return nil, err
	}
	return append(filters, terminalRouter), nil
}

func requestControlFilters(c resolvedConfig, hosts []*route.VirtualHost) ([]*hcm.HttpFilter, error) {
	controls, err := requestControlHeaderFilter(c)
	if err != nil {
		return nil, err
	}
	filters := []*hcm.HttpFilter{controls}
	if !hasRequestMetricRoutes(hosts) {
		return filters, nil
	}
	metric, err := requestMetricsHTTPFilter(c)
	if err != nil {
		return nil, err
	}
	filters = append(filters, metric)
	return filters, nil
}

func protectedHTTPFilters(c resolvedConfig, filters []*hcm.HttpFilter, hosts []indexedVirtualHost) ([]*hcm.HttpFilter, error) {
	usesJWT, usesKey, usesMTLS := false, false, false
	serverIndexes := make([]int, 0, len(hosts))
	for _, host := range hosts {
		serverIndexes = append(serverIndexes, host.serverIndex)
		usesJWT = usesJWT || c.servers[host.serverIndex].hasJWT
		usesKey = usesKey || c.servers[host.serverIndex].hasAPIKey
		usesMTLS = usesMTLS || c.servers[host.serverIndex].usesMTLS()
	}
	var err error
	filters, err = authenticationHTTPFilters(c, filters, serverIndexes, usesJWT, usesKey, usesMTLS)
	if err != nil {
		return nil, err
	}
	if needsWorkingAttributes(c) {
		filters, err = attributeHTTPFilters(c, filters, hosts)
		if err != nil {
			return nil, err
		}
	}
	return authorizationHTTPFilters(c, filters)
}

func authenticationHTTPFilters(c resolvedConfig, filters []*hcm.HttpFilter, serverIndexes []int, usesJWT, usesKey, usesMTLS bool) ([]*hcm.HttpFilter, error) {
	if usesMTLS {
		peer, err := mtlsPeerHeadersFilter()
		if err != nil {
			return nil, fmt.Errorf("encode mTLS peer headers: %w", err)
		}
		filters = append(filters, peer)
	}
	if usesJWT {
		jwtFilter, err := jwtHTTPFilter(c, serverIndexes)
		if err != nil {
			return nil, err
		}
		filters = append(filters, jwtFilter)
	}
	headers := requestHeaderSources(c, serverIndexes)
	var keyAuthenticator gatewayapi.Authenticator
	if usesKey {
		filters = append(filters, apiKeyFilter())
		keyAuthenticator, _ = c.apiKeyAuthenticator()
	}
	if usesKey || usesMTLS || len(headers) > 0 {
		metadata, err := requestMetadataFilter(keyAuthenticator, headers, usesMTLS)
		if err != nil {
			return nil, fmt.Errorf("encode request metadata filter: %w", err)
		}
		filters = append(filters, metadata)
	}
	if usesKey || usesMTLS {
		var err error
		filters, err = appendAuthenticationRBAC(filters)
		if err != nil {
			return nil, err
		}
	}
	if usesMTLS {
		cleanup, err := mtlsPendingCleanupFilter()
		if err != nil {
			return nil, fmt.Errorf("encode mTLS authentication marker cleanup: %w", err)
		}
		filters = append(filters, cleanup)
		cardinality, err := mtlsSANCardinalityFilter()
		if err != nil {
			return nil, fmt.Errorf("encode mTLS SAN cardinality: %w", err)
		}
		filters = append(filters, cardinality)
		shared, err := mtlsSharedAttributesHTTPFilter()
		if err != nil {
			return nil, err
		}
		filters = append(filters, shared)
	}
	return filters, nil
}

func authorizationHTTPFilters(c resolvedConfig, filters []*hcm.HttpFilter) ([]*hcm.HttpFilter, error) {
	authorization, err := authorizationHTTPFilter()
	if err != nil {
		return nil, err
	}
	filters = append(filters, authorization)
	if hasRequestHeaderProcessing(c.APIs) {
		filters, err = appendRequiredHeaderRBAC(filters)
		if err != nil {
			return nil, err
		}
	}
	if c.usesAPIKeys() || c.usesJWT() || c.usesMTLS() {
		cleanup, err := toCredentialCleanupFilter(c)
		if err != nil {
			return nil, err
		}
		filters = append(filters, cleanup)
	}
	if hasRequestHeaderProcessing(c.APIs) {
		headers, err := requestHeaderHTTPFilter(c.APIs)
		if err != nil {
			return nil, err
		}
		filters = append(filters, headers)
	}
	return filters, nil
}

func hasProtectedHosts(hosts []indexedVirtualHost) bool {
	for _, host := range hosts {
		if host.host != nil && host.host.TypedPerFilterConfig[authorizationFilterName] != nil {
			return true
		}
	}
	return false
}

func filterStateMatcherInput(key string) (*xdscore.TypedExtensionConfig, error) {
	config, err := packEnvoy(&networkinput.FilterStateInput{Key: key})
	if err != nil {
		return nil, err
	}
	return &xdscore.TypedExtensionConfig{Name: "envoy.matching.inputs.filter_state", TypedConfig: config}, nil
}

func requestHeaderMatcherInput(header string) (*xdscore.TypedExtensionConfig, error) {
	config, err := packEnvoy(&matcher.HttpRequestHeaderMatchInput{HeaderName: header})
	if err != nil {
		return nil, err
	}
	return &xdscore.TypedExtensionConfig{Name: "envoy.matching.inputs.request_headers", TypedConfig: config}, nil
}

func apiKeySkipAction() (*xdsmatcher.Matcher_OnMatch, error) {
	packedSkip, err := packEnvoy(&skip.SkipFilter{})
	if err != nil {
		return nil, fmt.Errorf("encode API-key skip action: %w", err)
	}
	return &xdsmatcher.Matcher_OnMatch{OnMatch: &xdsmatcher.Matcher_OnMatch_Action{Action: &xdscore.TypedExtensionConfig{Name: "skip", TypedConfig: packedSkip}}}, nil
}

func routerHTTPFilter() (*hcm.HttpFilter, error) {
	config, err := packEnvoy(&router.Router{})
	if err != nil {
		return nil, err
	}
	return &hcm.HttpFilter{Name: routerFilterName, ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: config}}, nil
}
