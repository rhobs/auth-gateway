package gateway

import (
	xdscore "github.com/cncf/xds/go/xds/core/v3"
	xdsmatcher "github.com/cncf/xds/go/xds/type/matcher/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	composite "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/composite/v3"
	router "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	networkinput "github.com/envoyproxy/go-control-plane/envoy/extensions/matching/common_inputs/network/v3"
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

func httpFilters(c resolvedConfig, hosts []indexedVirtualHost, protected bool) ([]*hcm.HttpFilter, error) {
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
	cleanup, err := credentialCleanupFilter(c)
	if err != nil {
		return nil, err
	}
	filters = append(filters, cleanup)
	if len(c.ExtAuthzServices) != 0 {
		credentials, err := extAuthzCredentialCleanupFilter()
		if err != nil {
			return nil, err
		}
		filters = append(filters, credentials)
	}
	if apis := apisForHosts(c, hosts); hasRequestHeaderProcessing(apis) {
		headers, err := requestHeaderHTTPFilter(apis)
		if err != nil {
			return nil, err
		}
		filters = append(filters, headers)
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
	router, err := routerHTTPFilter()
	if err != nil {
		return nil, err
	}
	return append(filters, router), nil
}

func requestControlFilters(c resolvedConfig, hosts []*route.VirtualHost) ([]*hcm.HttpFilter, error) {
	controls, err := requestControlHeaderFilter()
	if err != nil {
		return nil, err
	}
	filters := []*hcm.HttpFilter{controls}
	if hasRequestMetricRoutes(hosts) {
		metrics, err := requestMetricsHTTPFilter(c)
		if err != nil {
			return nil, err
		}
		filters = append(filters, metrics)
	}
	return filters, nil
}

func protectedHTTPFilters(c resolvedConfig, filters []*hcm.HttpFilter, hosts []indexedVirtualHost) ([]*hcm.HttpFilter, error) {
	usesJWT, usesKey, usesMTLS := false, false, false
	var indexes []int
	for _, host := range hosts {
		server := c.servers[host.serverIndex]
		indexes = append(indexes, host.serverIndex)
		usesJWT = usesJWT || server.hasJWT
		usesKey = usesKey || server.hasAPIKey
		usesMTLS = usesMTLS || server.usesMTLS()
	}
	validation, err := requestValidationHTTPFilter()
	if err != nil {
		return nil, err
	}
	begin, err := requestValidationMarkerFilter(true)
	if err != nil {
		return nil, err
	}
	end, err := requestValidationMarkerFilter(false)
	if err != nil {
		return nil, err
	}
	filters = append(filters, begin, validation, end)
	if usesMTLS {
		peer, err := mtlsPeerHeadersFilter()
		if err != nil {
			return nil, err
		}
		cardinality, err := mtlsSANCardinalityFilter()
		if err != nil {
			return nil, err
		}
		filters = append(filters, peer, cardinality)
	}
	if usesJWT {
		jwt, err := jwtHTTPFilter(c, indexes)
		if err != nil {
			return nil, err
		}
		filters = append(filters, jwt)
	}
	if usesKey {
		filters = append(filters, apiKeyFilter())
	}
	headers := requestHeaderSources(c, indexes)
	if usesKey || usesMTLS || len(headers) != 0 {
		metadata, err := requestMetadataFilter(c.apiKey, headers, usesMTLS)
		if err != nil {
			return nil, err
		}
		filters = append(filters, metadata)
	}
	if needsWorkingAttributes(c) {
		attributes, err := attributeHTTPFilter()
		if err != nil {
			return nil, err
		}
		filters = append(filters, attributes)
	}
	authorization, err := authorizationHTTPFilter()
	if err != nil {
		return nil, err
	}
	filters = append(filters, authorization)
	for _, service := range c.ExtAuthzServices {
		filter, err := extAuthzHTTPFilter(service)
		if err != nil {
			return nil, err
		}
		filters = append(filters, filter)
	}
	if len(c.ExtAuthzServices) != 0 {
		filter, err := extAuthzAttributeFilter()
		if err != nil {
			return nil, err
		}
		filters = append(filters, filter)
	}
	if hasRequestHeaderProcessing(apisForHosts(c, hosts)) {
		return appendRequiredHeaderRBAC(filters)
	}
	return filters, nil
}

func hasProtectedHosts(c resolvedConfig, hosts []indexedVirtualHost) bool {
	for _, host := range hosts {
		if len(c.servers[host.serverIndex].authenticators) != 0 {
			return true
		}
		for _, binding := range c.servers[host.serverIndex].bindings {
			if len(binding.access) != 0 {
				return true
			}
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

func routerHTTPFilter() (*hcm.HttpFilter, error) {
	config, err := packEnvoy(&router.Router{})
	if err != nil {
		return nil, err
	}
	return &hcm.HttpFilter{Name: routerFilterName, ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: config}}, nil
}

func apisForHosts(c resolvedConfig, hosts []indexedVirtualHost) []gatewayapi.API {
	var apis []gatewayapi.API
	for _, host := range hosts {
		apis = append(apis, c.servers[host.serverIndex].apis...)
	}
	return apis
}
