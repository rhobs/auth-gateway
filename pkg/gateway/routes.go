package gateway

import (
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	rbac "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	jwt "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/jwt_authn/v3"
	httpRBAC "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rbac/v3"
	matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	localResponseAPIName  = "__local"
	apiMetadataName       = "api"
	serverFieldPathFormat = "servers[%d]"
)

type indexedVirtualHost struct {
	serverIndex int
	host        *route.VirtualHost
}

type methodFallback struct {
	path    gatewayapi.PathMatch
	methods []string
}

func validDNSHost(value string) bool {
	return net.ParseIP(value) == nil && len(validation.IsDNS1123Subdomain(value)) == 0
}

func validateServers(c gatewayapi.Config, apis map[string]gatewayapi.API) ([]resolvedServer, error) {
	if len(c.Servers) == 0 {
		return nil, fmt.Errorf("servers must contain at least one server")
	}
	servers := make([]resolvedServer, len(c.Servers))
	hosts := make(map[string]int, len(c.Servers))
	for i, server := range c.Servers {
		name := fmt.Sprintf(serverFieldPathFormat, i)
		if !validDNSHost(server.Hostname) {
			return nil, fmt.Errorf("%s.hostname must be an exact DNS hostname", name)
		}
		if previous, exists := hosts[server.Hostname]; exists {
			return nil, fmt.Errorf("%s.hostname %q is already used by servers[%d]", name, server.Hostname, previous)
		}
		hosts[server.Hostname] = i
		if server.TLSConfig != nil {
			if err := validateServerTLS(name+".tls_config", *server.TLSConfig); err != nil {
				return nil, err
			}
		}
		bound, err := boundAPIsServer(server, apis)
		if err != nil {
			return nil, fmt.Errorf("%s.apis: %w", name, err)
		}
		routes := make(map[string]struct{})
		for _, api := range bound {
			for _, route := range api.Routes {
				for _, method := range route.Methods {
					if err := addRouteKey(routes, route.Path, method); err != nil {
						return nil, fmt.Errorf("%s.apis: %w", name, err)
					}
				}
			}
		}
		servers[i] = resolvedServer{Server: &c.Servers[i], apis: bound}
	}
	return servers, nil
}

func validateAPIRoute(name string, route gatewayapi.Route, routes map[string]struct{}) error {
	if err := validateRouteTimeouts(name+".timeouts", route.Timeouts); err != nil {
		return err
	}
	if err := validateRouteProcessing(name+".processing", route.Processing); err != nil {
		return err
	}
	if err := validatePathMatch(name+".path", route.Path); err != nil {
		return err
	}
	if err := validatePathRewrite(name+".rewrite", route.Rewrite); err != nil {
		return err
	}
	if len(route.Methods) == 0 {
		return fmt.Errorf("%s.methods must contain at least one supported HTTP method", name)
	}
	seenMethods := make(map[string]struct{}, len(route.Methods))
	for _, method := range route.Methods {
		if !validMethod(method) {
			return fmt.Errorf("%s.methods must contain supported HTTP methods", name)
		}
		if _, exists := seenMethods[method]; exists {
			return fmt.Errorf("%s.methods contains duplicate method %q", name, method)
		}
		seenMethods[method] = struct{}{}
		if err := addRouteKey(routes, route.Path, method); err != nil {
			return err
		}
	}
	return nil
}

func addRouteKey(routes map[string]struct{}, path gatewayapi.PathMatch, method string) error {
	key := pathMatchKey(path) + "\x00" + method
	if _, exists := routes[key]; exists {
		return fmt.Errorf("duplicate API route for method %s and path matcher %q", method, pathMatchValue(path))
	}
	routes[key] = struct{}{}
	return nil
}

func pathMatchKey(path gatewayapi.PathMatch) string {
	switch {
	case path.Exact != "":
		return "exact\x00" + path.Exact
	case path.Prefix != "":
		return "prefix\x00" + path.Prefix
	default:
		return "regex\x00" + path.Regex
	}
}

func pathMatchValue(path gatewayapi.PathMatch) string {
	switch {
	case path.Exact != "":
		return path.Exact
	case path.Prefix != "":
		return path.Prefix
	default:
		return path.Regex
	}
}

func validatePathMatch(name string, path gatewayapi.PathMatch) error {
	count := 0
	if path.Exact != "" {
		count++
		if err := validatePath(name+".exact", path.Exact); err != nil {
			return err
		}
	}
	if path.Prefix != "" {
		count++
		if err := validatePathPrefix(name+".prefix", path.Prefix); err != nil {
			return err
		}
	}
	if path.Regex != "" {
		count++
		if _, err := regexp.Compile(path.Regex); err != nil {
			return fmt.Errorf("%s.regex must be a valid RE2 expression: %w", name, err)
		}
	}
	if count != 1 {
		return fmt.Errorf("%s must set exactly one of exact, prefix, or regex", name)
	}
	return nil
}

func validatePathRewrite(name string, rewrite *gatewayapi.PathRewrite) error {
	if rewrite == nil {
		return nil
	}

	count := 0
	if rewrite.Path != "" {
		count++
		if err := validatePath(name+".path", rewrite.Path); err != nil {
			return err
		}
	}
	if rewrite.Prefix != "" {
		count++
		if err := validatePathPrefix(name+".prefix", rewrite.Prefix); err != nil {
			return err
		}
	}
	if rewrite.Regex != nil {
		count++
		if rewrite.Regex.Pattern == "" {
			return fmt.Errorf("%s.regex.pattern must not be empty", name)
		}
		if _, err := regexp.Compile(rewrite.Regex.Pattern); err != nil {
			return fmt.Errorf("%s.regex.pattern must be a valid RE2 expression: %w", name, err)
		}
		if strings.ContainsAny(rewrite.Regex.Substitution, "?#\r\n") {
			return fmt.Errorf("%s.regex.substitution must not contain a query, fragment, or newline", name)
		}
	}
	if count != 1 {
		return fmt.Errorf("%s must set exactly one of path, prefix, or regex", name)
	}
	return nil
}

func validMethod(method string) bool {
	switch method {
	case http.MethodConnect,
		http.MethodDelete,
		http.MethodGet,
		http.MethodHead,
		http.MethodOptions,
		http.MethodPatch,
		http.MethodPost,
		http.MethodPut,
		http.MethodTrace:
		return true
	default:
		return false
	}
}

func validatePath(name, value string) error {
	if value == "" || !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") ||
		strings.ContainsAny(value, "?#\\\r\n") || path.Clean(value) != value {
		return fmt.Errorf("%s must be a clean absolute path without a query or fragment", name)
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.IsAbs() {
		return fmt.Errorf("%s must be a valid request path", name)
	}
	return nil
}

func validatePathPrefix(name, value string) error {
	if value == "" {
		return fmt.Errorf("%s must not be empty", name)
	}
	if strings.HasPrefix(value, "//") {
		return fmt.Errorf("%s must be an absolute path prefix", name)
	}
	cleanable := value
	if value != "/" && strings.HasSuffix(value, "/") {
		cleanable = strings.TrimSuffix(value, "/")
	}
	return validatePath(name, cleanable)
}

func cloneRoute(r gatewayapi.Route) gatewayapi.Route {
	r.Methods = slices.Clone(r.Methods)
	r.Rewrite = cloneConfigPointer(r.Rewrite, clonePathRewrite)
	r.Processing = cloneConfigPointer(r.Processing, cloneRouteProcessing)
	r.Timeouts = cloneConfigPointer(r.Timeouts, cloneRouteTimeouts)
	return r
}

func clonePathRewrite(r gatewayapi.PathRewrite) gatewayapi.PathRewrite {
	r.Regex = cloneConfigPointer(r.Regex, cloneRegexRewrite)
	return r
}

func cloneRegexRewrite(r gatewayapi.RegexRewrite) gatewayapi.RegexRewrite {
	return r
}

func cloneRouteProcessing(p gatewayapi.RouteProcessing) gatewayapi.RouteProcessing {
	p.RequestHeaders = slices.Clone(p.RequestHeaders)
	return p
}

func boundAPIsServer(s gatewayapi.Server, apis map[string]gatewayapi.API) ([]gatewayapi.API, error) {
	bound := make([]gatewayapi.API, 0, len(s.APIs))
	seen := make(map[string]struct{}, len(s.APIs))
	for _, binding := range s.APIs {
		name := binding.Name
		api, ok := apis[name]
		if !ok {
			return nil, fmt.Errorf("unknown API %q", name)
		}
		if _, exists := seen[name]; exists {
			return nil, fmt.Errorf("duplicate API binding %q", name)
		}
		seen[name] = struct{}{}
		bound = append(bound, api)
	}
	return bound, nil
}

func cloneServer(s gatewayapi.Server) gatewayapi.Server {
	s.TLSConfig = cloneConfigPointer(s.TLSConfig, cloneServerTLS)
	s.APIs = cloneSlice(s.APIs, cloneAPIBinding)
	return s
}

func apiRouteName(apiIndex int, apiName string, routeIndex, methodIndex int) string {
	return "api-" + strconv.Itoa(apiIndex) + "-" + apiName + "-route-" + strconv.Itoa(routeIndex) + "-method-" + strconv.Itoa(methodIndex)
}

func routeVirtualHosts(hosts []indexedVirtualHost) []*route.VirtualHost {
	virtualHosts := make([]*route.VirtualHost, len(hosts))
	for i, host := range hosts {
		virtualHosts[i] = host.host
	}
	return virtualHosts
}

func serverVirtualHost(c resolvedConfig, index int, server resolvedServer) (*route.VirtualHost, error) {
	routes, err := apiRoutesWithRequestHeaderMutations(server.apis, true)
	if err != nil {
		return nil, err
	}
	if err := addAPIFaultRouteConfigs(routes, server.apis); err != nil {
		return nil, err
	}
	if err := addAPIAdmissionRouteConfigs(routes, server.apis); err != nil {
		return nil, err
	}
	disabled, err := packEnvoy(&httpRBAC.RBACPerRoute{})
	if err != nil {
		return nil, err
	}
	defaultAuthorization := disabled
	if len(server.authenticators) > 0 {
		defaultAuthorization, err = packEnvoy(&httpRBAC.RBACPerRoute{Rbac: &httpRBAC.RBAC{Rules: &rbac.RBAC{Action: rbac.RBAC_ALLOW}}})
		if err != nil {
			return nil, err
		}
	}
	host := &route.VirtualHost{
		Name: server.Hostname, Domains: []string{server.Hostname},
		TypedPerFilterConfig: map[string]*anypb.Any{authorizationFilterName: defaultAuthorization},
	}
	if c.usesJWT() {
		disabledJWT, err := packEnvoy(&jwt.PerRouteConfig{RequirementSpecifier: &jwt.PerRouteConfig_Disabled{Disabled: true}})
		if err != nil {
			return nil, err
		}
		host.TypedPerFilterConfig[jwtAuthnFilterName] = disabledJWT
	}
	bindings := make(map[string]resolvedAPIBinding)
	for _, binding := range server.bindings {
		bindings[binding.Name] = binding
	}
	for _, base := range routes {
		if base.TypedPerFilterConfig == nil {
			base.TypedPerFilterConfig = make(map[string]*anypb.Any)
		}
		if base.GetRoute() == nil {
			base.TypedPerFilterConfig[authorizationFilterName] = disabled
			host.Routes = append(host.Routes, base)
			continue
		}
		apiName := base.Metadata.FilterMetadata[authorizationFilterName].Fields[apiMetadataName].GetStringValue()
		binding := bindings[apiName]
		if binding.Public {
			base.TypedPerFilterConfig[authorizationFilterName] = disabled
			host.Routes = append(host.Routes, base)
			continue
		}
		selectorHeaders := make(map[string]bool)
		for accessIndex, access := range binding.access {
			for _, header := range access.Match.Headers {
				selectorHeaders[strings.ToLower(header.Name)] = true
			}
			for combinationIndex, headers := range accessHeaderCombinations(access.Match) {
				generated := proto.Clone(base).(*route.Route)
				generated.Name = fmt.Sprintf("%s-access-%d-match-%d", base.Name, accessIndex, combinationIndex)
				generated.StatPrefix = generated.Name
				generated.Match.Headers = append(generated.Match.Headers, headers...)
				if err := addAccessRouteConfigs(c, generated, access); err != nil {
					return nil, fmt.Errorf("servers[%d] route %q: %w", index, generated.Name, err)
				}
				host.Routes = append(host.Routes, generated)
			}
		}
		denied := proto.Clone(base).(*route.Route)
		denied.Name += "-access-denied"
		denied.StatPrefix = denied.Name
		denied.Action = &route.Route_DirectResponse{DirectResponse: &route.DirectResponseAction{Status: 403}}
		validation, err := requestValidationPerRouteConfig(slices.Sorted(maps.Keys(selectorHeaders)))
		if err != nil {
			return nil, err
		}
		denied.TypedPerFilterConfig = map[string]*anypb.Any{requestValidationFilterName: validation}
		host.Routes = append(host.Routes, denied)
	}
	return host, nil
}

func accessHeaderCombinations(match gatewayapi.AccessMatch) [][]*route.HeaderMatcher {
	combinations := [][]*route.HeaderMatcher{nil}
	for _, condition := range sortedMatchExpressions(match.Headers) {
		var expanded [][]*route.HeaderMatcher
		for _, headers := range combinations {
			if condition.Expression == gatewayapi.ExpressionPresent {
				matcher := &route.HeaderMatcher{Name: strings.ToLower(condition.Name), HeaderMatchSpecifier: &route.HeaderMatcher_PresentMatch{PresentMatch: true}}
				expanded = append(expanded, append(slices.Clone(headers), matcher))
				continue
			}
			for _, value := range matchValues(condition) {
				matcher := &route.HeaderMatcher{Name: strings.ToLower(condition.Name), HeaderMatchSpecifier: &route.HeaderMatcher_StringMatch{StringMatch: &matcher.StringMatcher{MatchPattern: &matcher.StringMatcher_Exact{Exact: value}}}}
				expanded = append(expanded, append(slices.Clone(headers), matcher))
			}
		}
		combinations = expanded
	}
	return combinations
}

func sortedMatchExpressions(expressions []gatewayapi.MatchExpression) []gatewayapi.MatchExpression {
	return slices.SortedFunc(slices.Values(expressions), func(a, b gatewayapi.MatchExpression) int {
		return strings.Compare(a.Name, b.Name)
	})
}

func accessHeaderNames(match gatewayapi.AccessMatch) []string {
	names := make([]string, 0, len(match.Headers))
	for _, condition := range match.Headers {
		names = append(names, condition.Name)
	}
	slices.Sort(names)
	return names
}

func addAccessRouteConfigs(c resolvedConfig, generated *route.Route, access resolvedAccess) error {
	if generated.TypedPerFilterConfig == nil {
		generated.TypedPerFilterConfig = make(map[string]*anypb.Any)
	}
	authorization, err := authorizationPerRouteConfig(c, access)
	if err != nil {
		return err
	}
	generated.TypedPerFilterConfig[authorizationFilterName] = authorization
	headers := accessHeaderNames(access.Match)
	if access.Authentication != nil {
		if access.Authentication.JWT != nil {
			headers = append(headers, authorizationHeaderName)
			config, err := jwtPerRouteConfig(access)
			if err != nil {
				return err
			}
			generated.TypedPerFilterConfig[jwtAuthnFilterName] = config
		} else {
			headers = append(headers, c.apiKey.APIKey.Header)
			config, err := apiKeyPerRouteConfig()
			if err != nil {
				return err
			}
			generated.TypedPerFilterConfig[apiKeyFilterName] = config
		}
	}
	validation, err := requestValidationPerRouteConfig(headers)
	if err != nil {
		return err
	}
	generated.TypedPerFilterConfig[requestValidationFilterName] = validation
	if needsWorkingAttributes(c) {
		for _, authenticator := range access.authenticators {
			if len(authenticator.Attributes) != 0 {
				attributes, err := attributePerRouteConfig(access)
				if err != nil {
					return err
				}
				generated.TypedPerFilterConfig[attributeFilterName] = attributes
				break
			}
		}
	}
	return nil
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
			key := pathMatchKey(apiRoute.Path)
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
			routeConfig.Metadata = apiRouteMetadata(localResponseAPIName)
		}
		routes = append(routes, routeConfig)
	}
	notFound := &route.Route{
		Name: "not-found", Match: &route.RouteMatch{PathSpecifier: &route.RouteMatch_Prefix{Prefix: "/"}},
		Action: &route.Route_DirectResponse{DirectResponse: &route.DirectResponseAction{Status: 404}},
	}
	if includeMetadata {
		notFound.Metadata = apiRouteMetadata(localResponseAPIName)
	}
	return append(routes, notFound)
}

func apiRouteMetadata(apiName string) *core.Metadata {
	api, _ := structpb.NewStruct(map[string]any{apiMetadataName: apiName})
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
