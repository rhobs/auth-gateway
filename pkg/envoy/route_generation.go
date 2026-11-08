package envoy

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	configuration "github.com/rhobs/auth-gateway/pkg/config"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
)

func apiRouteName(apiIndex int, apiName string, routeIndex, methodIndex int) string {
	return "api-" + strconv.Itoa(apiIndex) + "-" + apiName + "-route-" + strconv.Itoa(routeIndex) + "-method-" + strconv.Itoa(methodIndex)
}

type indexedVirtualHost struct {
	serverIndex int
	host        *route.VirtualHost
}

type methodFallback struct {
	path    gatewayapi.PathMatch
	methods []string
}

func routeVirtualHosts(hosts []indexedVirtualHost) []*route.VirtualHost {
	virtualHosts := make([]*route.VirtualHost, len(hosts))
	for i, host := range hosts {
		virtualHosts[i] = host.host
	}
	return virtualHosts
}

func serverVirtualHost(c configuration.ResolvedConfig, index int, server configuration.ResolvedServer) (*route.VirtualHost, error) {
	bound := server.BoundAPIs
	routes, err := apiRoutesWithRequestHeaderMutations(bound, configuration.HasAuthenticationConfigConfig(c.Config))
	if err != nil {
		return nil, fmt.Errorf("servers[%d] routes: %w", index, err)
	}
	if err := addAPIFaultRouteConfigs(routes, bound); err != nil {
		return nil, fmt.Errorf("servers[%d] routes: %w", index, err)
	}
	if err := addAPIAdmissionRouteConfigs(routes, bound); err != nil {
		return nil, fmt.Errorf("servers[%d] routes: %w", index, err)
	}
	host := &route.VirtualHost{Name: server.Hostname, Domains: []string{server.Hostname}, Routes: routes}
	if server.Authentication == nil {
		return host, nil
	}
	host.TypedPerFilterConfig = make(map[string]*anypb.Any)
	if err := addServerJWTRequirement(c, host, index, server); err != nil {
		return nil, err
	}
	if err := addServerAPIKeyConfig(c, host, index, server); err != nil {
		return nil, err
	}
	if err := addServerAuthenticationConfig(c, host, index, server); err != nil {
		return nil, err
	}
	if err := addServerMTLSSharedAttributeConfig(c, host, index, server); err != nil {
		return nil, err
	}
	rbacConfig, err := serverAuthorizationPerRouteConfig(c, server)
	if err != nil {
		return nil, fmt.Errorf("servers[%d] RBAC rules: %w", index, err)
	}
	host.TypedPerFilterConfig[authorizationFilterName] = rbacConfig
	return host, nil
}

func apiRoutesWithRequestHeaderMutations(apis []gatewayapi.API, includeMetadata bool) ([]*route.Route, error) {
	routes := apiRoutesWithMetadata(apis, includeMetadata)
	routesByName := make(map[string]*route.Route, len(routes))
	for _, generatedRoute := range routes {
		routesByName[generatedRoute.Name] = generatedRoute
	}
	for apiIndex, api := range apis {
		for routeIndex, apiRoute := range api.Routes {
			if apiRoute.Processing == nil || len(apiRoute.Processing.RequestHeaders) == 0 {
				continue
			}
			for methodIndex := range apiRoute.Methods {
				name := apiRouteName(apiIndex, api.Name, routeIndex, methodIndex)
				generatedRoute := routesByName[name]
				if generatedRoute == nil {
					return nil, fmt.Errorf("generated route %q is missing", name)
				}
				perRouteConfig, err := requestHeaderPerRouteConfig(apiRoute.Processing.RequestHeaders)
				if err != nil {
					return nil, fmt.Errorf("encode request header mutations for route %q: %w", name, err)
				}
				headerRBACConfig, err := requiredHeaderPerRouteConfig(name, apiRoute.Processing.RequestHeaders)
				if err != nil {
					return nil, err
				}
				generatedRoute.TypedPerFilterConfig = map[string]*anypb.Any{
					headerMutationFilterName: perRouteConfig,
					requiredHeaderFilterName: headerRBACConfig,
				}
			}
		}
	}
	return routes, nil
}

func apiRoutesWithMetadata(apis []gatewayapi.API, includeMetadata bool) []*route.Route {
	routes, fallbacks := apiMethodRoutes(apis, includeMetadata)
	return append(routes, apiFallbackRoutes(fallbacks, includeMetadata)...)
}

func apiMethodRoutes(apis []gatewayapi.API, includeMetadata bool) ([]*route.Route, []methodFallback) {
	var routes []*route.Route
	fallbacks := make([]methodFallback, 0, len(apis))
	fallbackIndexes := make(map[string]int, len(apis))
	for apiIndex, api := range apis {
		for routeIndex, apiRoute := range api.Routes {
			key := configuration.PathMatchKey(apiRoute.Path)
			fallbackIndex, ok := fallbackIndexes[key]
			if !ok {
				fallbackIndex = len(fallbacks)
				fallbackIndexes[key] = fallbackIndex
				fallbacks = append(fallbacks, methodFallback{path: apiRoute.Path})
			}
			for methodIndex, method := range apiRoute.Methods {
				routes = append(routes, apiMethodRoute(api, apiIndex, routeIndex, methodIndex, method, apiRoute, includeMetadata))
				fallbacks[fallbackIndex].methods = append(fallbacks[fallbackIndex].methods, method)
			}
		}
	}
	return routes, fallbacks
}

func apiMethodRoute(api gatewayapi.API, apiIndex, routeIndex, methodIndex int, method string, apiRoute gatewayapi.Route, includeMetadata bool) *route.Route {
	name := apiRouteName(apiIndex, api.Name, routeIndex, methodIndex)
	action := &route.RouteAction{
		ClusterSpecifier:  &route.RouteAction_Cluster{Cluster: apiClusterName(api.Name)},
		Timeout:           protobufDuration(apiRoute.Timeouts.ResponseTimeout),
		IdleTimeout:       protobufDuration(apiRoute.Timeouts.IdleTimeout),
		MaxStreamDuration: &route.RouteAction_MaxStreamDuration{MaxStreamDuration: protobufDuration(apiRoute.Timeouts.MaxStreamDuration)},
	}
	applyPathRewrite(action, apiRoute.Rewrite)
	match := routeMatch(apiRoute.Path)
	match.Headers = []*route.HeaderMatcher{methodHeader(method)}
	routeConfig := &route.Route{
		Name: name, StatPrefix: name, Match: match,
		Action: &route.Route_Route{Route: action},
	}
	if includeMetadata {
		routeConfig.Metadata = apiRouteMetadata(api.Name)
	}
	if api.Metrics != nil {
		if routeConfig.Metadata == nil {
			routeConfig.Metadata = &core.Metadata{FilterMetadata: make(map[string]*structpb.Struct)}
		}
		routeConfig.Metadata.FilterMetadata[requestMetricsFilterName] = requestMetricsRouteMetadata(api)
	}
	return routeConfig
}

func apiFallbackRoutes(fallbacks []methodFallback, includeMetadata bool) []*route.Route {
	routes := make([]*route.Route, 0, len(fallbacks)+1)
	for i, fallback := range fallbacks {
		methods := fallback.methods
		sort.Strings(methods)
		var allow strings.Builder
		for index, method := range methods {
			if index > 0 {
				allow.WriteString(", ")
			}
			allow.WriteString(method)
		}
		routeConfig := &route.Route{
			Name:  "method-not-allowed-" + strconv.Itoa(i),
			Match: routeMatch(fallback.path),
			Action: &route.Route_DirectResponse{DirectResponse: &route.DirectResponseAction{
				Status: 405,
			}},
			ResponseHeadersToAdd: []*core.HeaderValueOption{{
				Header:       &core.HeaderValue{Key: "allow", Value: allow.String()},
				AppendAction: core.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
			}},
		}
		if includeMetadata {
			routeConfig.Metadata = apiRouteMetadata(configuration.LocalResponseAPIName)
		}
		routes = append(routes, routeConfig)
	}
	notFound := &route.Route{
		Name: "not-found", Match: &route.RouteMatch{PathSpecifier: &route.RouteMatch_Prefix{Prefix: "/"}},
		Action: &route.Route_DirectResponse{DirectResponse: &route.DirectResponseAction{Status: 404}},
	}
	if includeMetadata {
		notFound.Metadata = apiRouteMetadata(configuration.LocalResponseAPIName)
	}
	return append(routes, notFound)
}

func apiRouteMetadata(apiName string) *core.Metadata {
	api, _ := structpb.NewStruct(map[string]any{configuration.ApiMetadataName: apiName})
	return &core.Metadata{FilterMetadata: map[string]*structpb.Struct{authorizationFilterName: api}}
}

func methodHeader(method string) *route.HeaderMatcher {
	return &route.HeaderMatcher{
		Name: ":method",
		HeaderMatchSpecifier: &route.HeaderMatcher_StringMatch{
			StringMatch: &matcher.StringMatcher{MatchPattern: &matcher.StringMatcher_Exact{Exact: method}},
		},
	}
}

func envoySafeRegex(pattern string) *matcher.RegexMatcher {
	return &matcher.RegexMatcher{
		Regex: pattern,
	}
}

func applyPathRewrite(action *route.RouteAction, rewrite *gatewayapi.PathRewrite) {
	if rewrite == nil {
		return
	}
	switch {
	case rewrite.Path != "":
		action.PathRewrite = rewrite.Path
	case rewrite.Prefix != "":
		action.PrefixRewrite = rewrite.Prefix
	case rewrite.Regex != nil:
		action.RegexRewrite = &matcher.RegexMatchAndSubstitute{
			Pattern:      envoySafeRegex(rewrite.Regex.Pattern),
			Substitution: rewrite.Regex.Substitution,
		}
	}
}

func routeMatch(path gatewayapi.PathMatch) *route.RouteMatch {
	switch {
	case path.Exact != "":
		return &route.RouteMatch{PathSpecifier: &route.RouteMatch_Path{Path: path.Exact}}
	case path.Prefix != "":
		return &route.RouteMatch{PathSpecifier: &route.RouteMatch_Prefix{Prefix: path.Prefix}}
	default:
		return &route.RouteMatch{PathSpecifier: &route.RouteMatch_SafeRegex{SafeRegex: envoySafeRegex(path.Regex)}}
	}
}
