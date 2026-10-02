package config

import (
	"fmt"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	bootstrap "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	mutationrules "github.com/envoyproxy/go-control-plane/envoy/config/common/mutation_rules/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	rbac "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	headermutation "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/header_mutation/v3"
	jwt "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/jwt_authn/v3"
	lua "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/lua/v3"
	httpRBAC "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rbac/v3"
	router "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	inspector "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/tls_inspector/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"go.yaml.in/yaml/v3"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type envoyValidator interface {
	ValidateAll() error
}

// Generate builds Envoy bootstrap files from the high-level gateway configuration.
func Generate(c Config) (map[string][]byte, error) {
	c = c.withDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	clusters := apiClusters(c.APIs)
	jwks, err := jwksClusters(c.Authenticators, c.Servers)
	if err != nil {
		return nil, err
	}
	clusters = append(clusters, jwks...)
	apis := c.apisByName()
	var filterChains []*listener.FilterChain
	var httpHosts []*route.VirtualHost
	for i, server := range c.Servers {
		bound, err := server.boundAPIs(apis)
		if err != nil {
			return nil, fmt.Errorf("servers[%d].apis: %w", i, err)
		}
		routes, err := apiRoutesWithRequestHeaderMutations(bound, c.hasAuthenticationConfig())
		if err != nil {
			return nil, fmt.Errorf("servers[%d] routes: %w", i, err)
		}
		host := &route.VirtualHost{
			Name:    server.Hostname,
			Domains: []string{server.Hostname},
			Routes:  routes,
		}
		if server.Authentication != nil {
			requirementName := serverJWTRequirementName(i)
			perRoute, err := packEnvoy(&jwt.PerRouteConfig{RequirementSpecifier: &jwt.PerRouteConfig_RequirementName{RequirementName: requirementName}})
			if err != nil {
				return nil, fmt.Errorf("servers[%d] JWT requirement: %w", i, err)
			}
			host.TypedPerFilterConfig = map[string]*anypb.Any{"envoy.filters.http.jwt_authn": perRoute}
			rbacConfig, err := packEnvoy(&httpRBAC.RBACPerRoute{Rbac: &httpRBAC.RBAC{Rules: serverRBACRules(c, server)}})
			if err != nil {
				return nil, fmt.Errorf("servers[%d] RBAC rules: %w", i, err)
			}
			host.TypedPerFilterConfig["envoy.filters.http.rbac"] = rbacConfig
		}
		if server.TLSConfig == nil {
			httpHosts = append(httpHosts, host)
			continue
		}
		chain, err := httpFilterChain([]*route.VirtualHost{host}, c)
		if err != nil {
			return nil, fmt.Errorf("servers[%d]: %w", i, err)
		}
		chain.FilterChainMatch = &listener.FilterChainMatch{
			TransportProtocol: "tls",
			ServerNames:       []string{server.Hostname},
		}
		chain.TransportSocket, err = serverTLSTransportSocket(i)
		if err != nil {
			return nil, fmt.Errorf("servers[%d] downstream TLS context: %w", i, err)
		}
		filterChains = append(filterChains, chain)
	}
	if len(httpHosts) > 0 {
		chain, err := httpFilterChain(httpHosts, c)
		if err != nil {
			return nil, err
		}
		if c.hasHTTPS() {
			chain.FilterChainMatch = &listener.FilterChainMatch{TransportProtocol: "raw_buffer"}
		}
		filterChains = append([]*listener.FilterChain{chain}, filterChains...)
	}
	var listenerFilters []*listener.ListenerFilter
	if c.hasHTTPS() {
		inspectorConfig, err := packEnvoy(&inspector.TlsInspector{})
		if err != nil {
			return nil, fmt.Errorf("encode TLS inspector: %w", err)
		}
		listenerFilters = []*listener.ListenerFilter{{
			Name:       "envoy.filters.listener.tls_inspector",
			ConfigType: &listener.ListenerFilter_TypedConfig{TypedConfig: inspectorConfig},
		}}
	}

	bootstrapConfig := &bootstrap.Bootstrap{
		Node:  &core.Node{Id: c.Node.ID, Cluster: c.Node.Cluster},
		Admin: &bootstrap.Admin{Address: socket(envoyAdminAddress, envoyAdminPort)},
		StaticResources: &bootstrap.Bootstrap_StaticResources{
			Listeners: []*listener.Listener{{
				Name:                          "ingestion",
				Address:                       socket(envoyListenerAddress, c.Listener.Port),
				PerConnectionBufferLimitBytes: wrapperspb.UInt32(1048576),
				ListenerFilters:               listenerFilters,
				FilterChains:                  filterChains,
			}},
			Clusters: clusters,
		},
	}

	data, err := marshalEnvoyYAML(bootstrapConfig)
	if err != nil {
		return nil, fmt.Errorf("encode Envoy bootstrap: %w", err)
	}
	files := map[string][]byte{"envoy.yaml": append([]byte("# Generated by github.com/rhobs/auth-gateway.\n"), data...)}
	if hasProtectedServers(c.Servers) {
		script := identityMappingScript(c)
		files["lua/jwt.lua"] = []byte(script)
		resource, err := identityMappingECDSResource(script)
		if err != nil {
			return nil, fmt.Errorf("encode identity mapping ECDS resource: %w", err)
		}
		ecdsData, err := marshalEnvoyFileDiscoveryResponse(resource)
		if err != nil {
			return nil, fmt.Errorf("encode identity mapping ECDS response: %w", err)
		}
		files[identityMappingECDSRelativePath] = append([]byte("# Generated by github.com/rhobs/auth-gateway.\n"), ecdsData...)
	}
	for i, server := range c.Servers {
		if server.TLSConfig == nil {
			continue
		}
		secretData, err := marshalEnvoyFileDiscoveryResponse(serverTLSSecret(i, *server.TLSConfig))
		if err != nil {
			return nil, fmt.Errorf("servers[%d] certificate SDS resource: %w", i, err)
		}
		files[serverTLSResourceFilename(i)] = append([]byte("# Generated by github.com/rhobs/auth-gateway.\n"), secretData...)
	}
	return files, nil
}

func httpFilterChain(hosts []*route.VirtualHost, c Config) (*listener.FilterChain, error) {
	manager, err := httpManager(hosts, c)
	if err != nil {
		return nil, err
	}
	managerConfig, err := packEnvoy(manager)
	if err != nil {
		return nil, fmt.Errorf("encode HTTP connection manager: %w", err)
	}
	return &listener.FilterChain{Filters: []*listener.Filter{{
		Name:       "envoy.filters.network.http_connection_manager",
		ConfigType: &listener.Filter_TypedConfig{TypedConfig: managerConfig},
	}}}, nil
}

func httpManager(hosts []*route.VirtualHost, c Config) (*hcm.HttpConnectionManager, error) {
	routerConfig, err := packEnvoy(&router.Router{SuppressEnvoyHeaders: true})
	if err != nil {
		return nil, err
	}
	accessLogs, err := errorAccessLogs()
	if err != nil {
		return nil, err
	}
	filters := make([]*hcm.HttpFilter, 0, 5)
	if hasProtectedHosts(hosts) {
		jwtConfig, err := jwtFilterConfig(c)
		if err != nil {
			return nil, err
		}
		packed, err := packEnvoy(jwtConfig)
		if err != nil {
			return nil, fmt.Errorf("encode JWT authentication filter: %w", err)
		}
		filters = append(filters, &hcm.HttpFilter{Name: "envoy.filters.http.jwt_authn", ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: packed}})
		filters = append(filters, &hcm.HttpFilter{
			Name: "envoy.filters.http.lua",
			ConfigType: &hcm.HttpFilter_ConfigDiscovery{ConfigDiscovery: &core.ExtensionConfigSource{
				ConfigSource: fileConfigSource(path.Join(configDirectory, identityMappingECDSRelativePath)),
				TypeUrls:     []string{string((&lua.Lua{}).ProtoReflect().Descriptor().FullName())},
			}},
		})
		rbacConfig, err := packEnvoy(&httpRBAC.RBAC{})
		if err != nil {
			return nil, fmt.Errorf("encode RBAC filter: %w", err)
		}
		filters = append(filters, &hcm.HttpFilter{Name: "envoy.filters.http.rbac", ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: rbacConfig}})
		if hasRequestHeaderProcessing(c.APIs) {
			headerMutationConfig, err := packEnvoy(requestHeaderMutationConfig(c.APIs))
			if err != nil {
				return nil, fmt.Errorf("encode request header mutation filter: %w", err)
			}
			filters = append(filters, &hcm.HttpFilter{Name: "envoy.filters.http.header_mutation", ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: headerMutationConfig}})
		}
	}
	filters = append(filters, &hcm.HttpFilter{Name: "envoy.filters.http.router", ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: routerConfig}})
	return &hcm.HttpConnectionManager{
		StatPrefix:            "ingress",
		CodecType:             hcm.HttpConnectionManager_AUTO,
		MaxRequestHeadersKb:   wrapperspb.UInt32(32),
		RequestHeadersTimeout: durationpb.New(5 * time.Second),
		StreamIdleTimeout:     durationpb.New(time.Minute),
		CommonHttpProtocolOptions: &core.HttpProtocolOptions{
			IdleTimeout:                  durationpb.New(time.Minute),
			MaxStreamDuration:            durationpb.New(30 * time.Second),
			HeadersWithUnderscoresAction: core.HttpProtocolOptions_REJECT_REQUEST,
		},
		RequestTimeout:               durationpb.New(30 * time.Second),
		NormalizePath:                wrapperspb.Bool(false),
		PathWithEscapedSlashesAction: hcm.HttpConnectionManager_KEEP_UNCHANGED,
		RouteSpecifier: &hcm.HttpConnectionManager_RouteConfig{RouteConfig: &route.RouteConfiguration{
			Name:         "ingestion",
			VirtualHosts: hosts,
		}},
		AccessLog:   accessLogs,
		HttpFilters: filters,
	}, nil
}

func hasProtectedHosts(hosts []*route.VirtualHost) bool {
	for _, host := range hosts {
		if host.TypedPerFilterConfig["envoy.filters.http.jwt_authn"] != nil {
			return true
		}
	}
	return false
}

func hasProtectedServers(servers []Server) bool {
	for _, server := range servers {
		if server.Authentication != nil {
			return true
		}
	}
	return false
}

func serverJWTRequirementName(index int) string { return "server-" + strconv.Itoa(index) }

func jwtFilterConfig(c Config) (*jwt.JwtAuthentication, error) {
	config := &jwt.JwtAuthentication{Providers: map[string]*jwt.JwtProvider{}, RequirementMap: map[string]*jwt.JwtRequirement{}, StripFailureResponse: true}
	for _, authenticator := range c.Authenticators {
		if !authenticatorUsed(c.Servers, authenticator.Name) {
			continue
		}
		config.Providers[authenticator.Name] = &jwt.JwtProvider{
			Issuer:            authenticator.JWT.Issuer,
			Audiences:         authenticator.JWT.Audiences,
			RequireExpiration: true,
			JwksSourceSpecifier: &jwt.JwtProvider_RemoteJwks{RemoteJwks: &jwt.RemoteJwks{
				HttpUri:       &core.HttpUri{Uri: authenticator.JWT.JWKSURI, HttpUpstreamType: &core.HttpUri_Cluster{Cluster: jwksClusterName(authenticator.Name)}, Timeout: durationpb.New(5 * time.Second)},
				CacheDuration: durationpb.New(5 * time.Minute),
			}},
			FromHeaders:       []*jwt.JwtHeader{{Name: "Authorization", ValuePrefix: "Bearer "}},
			PayloadInMetadata: authenticator.Name,
		}
	}
	for i, server := range c.Servers {
		if server.Authentication == nil {
			continue
		}
		names := server.Authentication.AnyOf
		if len(server.Authentication.AllOf) > 0 {
			names = server.Authentication.AllOf
		}
		requirements := make([]*jwt.JwtRequirement, 0, len(names))
		for _, name := range names {
			requirements = append(requirements, &jwt.JwtRequirement{RequiresType: &jwt.JwtRequirement_ProviderName{ProviderName: name}})
		}
		var requirement *jwt.JwtRequirement
		if len(requirements) == 1 {
			requirement = requirements[0]
		} else if len(server.Authentication.AllOf) > 0 {
			requirement = &jwt.JwtRequirement{RequiresType: &jwt.JwtRequirement_RequiresAll{RequiresAll: &jwt.JwtRequirementAndList{Requirements: requirements}}}
		} else {
			requirement = &jwt.JwtRequirement{RequiresType: &jwt.JwtRequirement_RequiresAny{RequiresAny: &jwt.JwtRequirementOrList{Requirements: requirements}}}
		}
		config.RequirementMap[serverJWTRequirementName(i)] = requirement
	}
	return config, nil
}

func serverRBACRules(c Config, server Server) *rbac.RBAC {
	policies := map[string]*rbac.Policy{
		"local-responses": {
			Permissions: []*rbac.Permission{apiPermission("__local")},
			Principals:  []*rbac.Principal{{Identifier: &rbac.Principal_Any{Any: true}}},
		},
	}
	if server.Authorization != nil {
		for _, apiName := range server.APIs {
			var principal *rbac.Principal
			if len(server.Authorization.AnyOf) > 0 {
				var grants []*rbac.Principal
				for _, policyName := range server.Authorization.AnyOf {
					for _, grant := range authorizationPolicy(c, policyName).Grants {
						if contains(grant.APIs, apiName) {
							grants = append(grants, grantPrincipal(grant))
						}
					}
				}
				if len(grants) > 0 {
					principal = &rbac.Principal{Identifier: &rbac.Principal_OrIds{OrIds: &rbac.Principal_Set{Ids: grants}}}
				}
			} else {
				var policyPrincipals []*rbac.Principal
				allowed := true
				for _, policyName := range server.Authorization.AllOf {
					var grants []*rbac.Principal
					for _, grant := range authorizationPolicy(c, policyName).Grants {
						if contains(grant.APIs, apiName) {
							grants = append(grants, grantPrincipal(grant))
						}
					}
					if len(grants) == 0 {
						allowed = false
						break
					}
					policyPrincipals = append(policyPrincipals, &rbac.Principal{Identifier: &rbac.Principal_OrIds{OrIds: &rbac.Principal_Set{Ids: grants}}})
				}
				if allowed {
					principal = &rbac.Principal{Identifier: &rbac.Principal_AndIds{AndIds: &rbac.Principal_Set{Ids: policyPrincipals}}}
				}
			}
			if principal != nil {
				policies["api-"+apiName] = &rbac.Policy{Permissions: []*rbac.Permission{apiPermission(apiName)}, Principals: []*rbac.Principal{principal}}
			}
		}
	}
	return &rbac.RBAC{Action: rbac.RBAC_ALLOW, Policies: policies}
}

func authorizationPolicy(c Config, name string) AuthorizationPolicy {
	for _, policy := range c.AuthorizationPolicies {
		if policy.Name == name {
			return policy
		}
	}
	return AuthorizationPolicy{}
}

func apiPermission(api string) *rbac.Permission {
	return &rbac.Permission{Rule: &rbac.Permission_SourcedMetadata{SourcedMetadata: &rbac.SourcedMetadata{MetadataSource: rbac.MetadataSource_ROUTE, MetadataMatcher: &matcher.MetadataMatcher{
		Filter: "envoy.filters.http.rbac", Path: []*matcher.MetadataMatcher_PathSegment{metadataPathSegment("api")},
		Value: &matcher.ValueMatcher{MatchPattern: &matcher.ValueMatcher_StringMatch{StringMatch: &matcher.StringMatcher{MatchPattern: &matcher.StringMatcher_Exact{Exact: api}}}},
	}}}}
}

func grantPrincipal(grant AuthorizationGrant) *rbac.Principal {
	conditions := []*rbac.Principal{identityMetadataPrincipal([]string{"identity", "authenticator"}, grant.Authenticator)}
	for _, attribute := range sortedKeys(grant.Attributes) {
		values := make([]*matcher.ValueMatcher, 0, len(grant.Attributes[attribute]))
		for _, value := range grant.Attributes[attribute] {
			values = append(values, &matcher.ValueMatcher{MatchPattern: &matcher.ValueMatcher_StringMatch{StringMatch: &matcher.StringMatcher{MatchPattern: &matcher.StringMatcher_Exact{Exact: value}}}})
		}
		var valueMatcher *matcher.ValueMatcher
		if len(values) == 1 {
			valueMatcher = values[0]
		} else {
			valueMatcher = &matcher.ValueMatcher{MatchPattern: &matcher.ValueMatcher_OrMatch{OrMatch: &matcher.OrMatcher{ValueMatchers: values}}}
		}
		conditions = append(conditions, &rbac.Principal{Identifier: &rbac.Principal_SourcedMetadata{SourcedMetadata: &rbac.SourcedMetadata{MetadataSource: rbac.MetadataSource_DYNAMIC, MetadataMatcher: &matcher.MetadataMatcher{
			Filter: "auth_gateway", Path: []*matcher.MetadataMatcher_PathSegment{metadataPathSegment("identity"), metadataPathSegment("attributes"), metadataPathSegment(attribute)},
			Value: valueMatcher,
		}}}})
	}
	if len(conditions) == 1 {
		return conditions[0]
	}
	return &rbac.Principal{Identifier: &rbac.Principal_AndIds{AndIds: &rbac.Principal_Set{Ids: conditions}}}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func identityMetadataPrincipal(path []string, value string) *rbac.Principal {
	metadataPath := make([]*matcher.MetadataMatcher_PathSegment, 0, len(path))
	for _, key := range path {
		metadataPath = append(metadataPath, metadataPathSegment(key))
	}
	return &rbac.Principal{Identifier: &rbac.Principal_SourcedMetadata{SourcedMetadata: &rbac.SourcedMetadata{MetadataSource: rbac.MetadataSource_DYNAMIC, MetadataMatcher: &matcher.MetadataMatcher{
		Filter: "auth_gateway", Path: metadataPath,
		Value: &matcher.ValueMatcher{MatchPattern: &matcher.ValueMatcher_StringMatch{StringMatch: &matcher.StringMatcher{MatchPattern: &matcher.StringMatcher_Exact{Exact: value}}}},
	}}}}
}

func metadataPathSegment(key string) *matcher.MetadataMatcher_PathSegment {
	return &matcher.MetadataMatcher_PathSegment{Segment: &matcher.MetadataMatcher_PathSegment_Key{Key: key}}
}

func identityMappingScript(c Config) string {
	settings := map[string]any{"authenticators": map[string]any{}, "servers": map[string]any{}}
	authenticators := settings["authenticators"].(map[string]any)
	for _, authenticator := range c.Authenticators {
		if authenticator.JWT != nil {
			attributes := map[string]any{}
			for name, attribute := range authenticator.JWT.Attributes {
				var mappings any
				if attribute.Mappings != nil {
					mappings = attribute.Mappings
				}
				attributes[name] = map[string]any{"claim_path": attribute.ClaimPath, "mappings": mappings}
			}
			authenticators[authenticator.Name] = map[string]any{"issuer": authenticator.JWT.Issuer, "attributes": attributes}
		}
	}
	servers := settings["servers"].(map[string]any)
	for _, server := range c.Servers {
		value := map[string]any{"protected": server.Authentication != nil}
		if server.Authentication != nil {
			names, mode := server.Authentication.AnyOf, "any_of"
			if len(server.Authentication.AllOf) > 0 {
				names, mode = server.Authentication.AllOf, "all_of"
			}
			value["authenticators"], value["mode"] = names, mode
		}
		servers[server.Hostname] = value
	}
	return `local settings = ` + luaValue(settings) + `
local function reject(handle)
  handle:respond({[":status"] = "403"}, "Forbidden")
end
local function mapped_attributes(authenticator, payload)
  local attributes = {}
  for name, mapping in pairs(authenticator.attributes or {}) do
    local value = payload
    for _, key in ipairs(mapping.claim_path) do
      if type(value) ~= "table" then value = nil; break end
      value = value[key]
    end
    if type(value) ~= "string" or value == "" then return nil end
    if mapping.mappings ~= nil then
      value = mapping.mappings[value]
      if type(value) ~= "string" or value == "" then return nil end
    end
    attributes[name] = value
  end
  return attributes
end
function envoy_on_request(handle)
  local headers = handle:headers()
  local authority = string.lower((headers:get(":authority") or ""):gsub(":%d+$", ""))
  local server = settings.servers[authority]
  if server == nil or not server.protected then return end
  local verified = handle:streamInfo():dynamicMetadata():get("envoy.filters.http.jwt_authn") or {}
  local selected, combined, credentials, saw_verified = nil, {}, {}, false
  for _, name in ipairs(server.authenticators) do
    local payload = verified[name]
    if type(payload) == "table" then
      saw_verified = true
      local attributes = mapped_attributes(settings.authenticators[name], payload)
      if attributes ~= nil then
        if selected == nil then selected = name end
        credentials[#credentials + 1] = {authenticator = name, issuer = settings.authenticators[name].issuer}
        local conflict = false
        for key, value in pairs(attributes) do
          if combined[key] ~= nil and combined[key] ~= value then conflict = true end
        end
        if conflict then
          if server.mode == "all_of" then reject(handle); return end
        else
          for key, value in pairs(attributes) do combined[key] = value end
        end
        if server.mode == "any_of" then break end
      end
    end
  end
  if not saw_verified then handle:respond({[":status"] = "401"}, "Unauthorized"); return end
  if selected == nil or (server.mode == "all_of" and #credentials ~= #server.authenticators) then reject(handle); return end
  local metadata = handle:streamInfo():dynamicMetadata()
  metadata:set("auth_gateway", "identity", {authenticator = selected, credentials = credentials, attributes = combined})
  for name, value in pairs(combined) do
    metadata:set("auth_gateway_attributes", name, value)
  end
end`
}

func apiRoutesWithRequestHeaderMutations(apis []API, includeMetadata bool) ([]*route.Route, error) {
	routes := apiRoutesWithMetadata(apis, includeMetadata)
	routesByName := make(map[string]*route.Route, len(routes))
	for _, generatedRoute := range routes {
		routesByName[generatedRoute.Name] = generatedRoute
	}
	for apiIndex, api := range apis {
		for routeIndex, apiRoute := range api.Routes {
			if apiRoute.Processing == nil {
				continue
			}
			mutations := requestHeaderMutations(apiRoute.Processing.RequestHeaders)
			for methodIndex := range apiRoute.Methods {
				name := apiRouteName(apiIndex, api.Name, routeIndex, methodIndex)
				generatedRoute := routesByName[name]
				if generatedRoute == nil {
					return nil, fmt.Errorf("generated route %q is missing", name)
				}
				perRouteConfig, err := packEnvoy(&headermutation.HeaderMutationPerRoute{Mutations: &headermutation.Mutations{RequestMutations: mutations}})
				if err != nil {
					return nil, fmt.Errorf("encode request header mutations for route %q: %w", name, err)
				}
				generatedRoute.TypedPerFilterConfig = map[string]*anypb.Any{"envoy.filters.http.header_mutation": perRouteConfig}
			}
		}
	}
	return routes, nil
}

func apiRouteName(apiIndex int, apiName string, routeIndex, methodIndex int) string {
	return "api-" + strconv.Itoa(apiIndex) + "-" + apiName + "-route-" + strconv.Itoa(routeIndex) + "-method-" + strconv.Itoa(methodIndex)
}

func hasRequestHeaderProcessing(apis []API) bool {
	for _, api := range apis {
		for _, apiRoute := range api.Routes {
			if apiRoute.Processing != nil && len(apiRoute.Processing.RequestHeaders) > 0 {
				return true
			}
		}
	}
	return false
}

func requestHeaderMutationConfig(apis []API) *headermutation.HeaderMutation {
	managed := make(map[string]struct{})
	for _, api := range apis {
		for _, apiRoute := range api.Routes {
			if apiRoute.Processing == nil {
				continue
			}
			for _, mapping := range apiRoute.Processing.RequestHeaders {
				managed[strings.ToLower(mapping.Name)] = struct{}{}
			}
		}
	}
	mutations := make([]*mutationrules.HeaderMutation, 0, len(managed))
	for _, name := range sortedKeys(managed) {
		mutations = append(mutations, &mutationrules.HeaderMutation{Action: &mutationrules.HeaderMutation_Remove{Remove: name}})
	}
	return &headermutation.HeaderMutation{Mutations: &headermutation.Mutations{RequestMutations: mutations}}
}

func requestHeaderMutations(mappings []RequestHeaderMapping) []*mutationrules.HeaderMutation {
	mutations := make([]*mutationrules.HeaderMutation, 0, len(mappings))
	for _, mapping := range mappings {
		mutations = append(mutations, &mutationrules.HeaderMutation{Action: &mutationrules.HeaderMutation_Append{Append: &core.HeaderValueOption{
			Header:       &core.HeaderValue{Key: mapping.Name, Value: "%DYNAMIC_METADATA(auth_gateway_attributes:" + mapping.FromAttribute + ")%"},
			AppendAction: core.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		}}})
	}
	return mutations
}

func luaValue(value any) string {
	switch value := value.(type) {
	case nil:
		return "nil"
	case string:
		return luaQuote(value)
	case bool:
		if value {
			return "true"
		}
		return "false"
	case []string:
		items := make([]string, len(value))
		for i := range value {
			items[i] = luaValue(value[i])
		}
		return "{" + strings.Join(items, ",") + "}"
	case []any:
		items := make([]string, len(value))
		for i := range value {
			items[i] = luaValue(value[i])
		}
		return "{" + strings.Join(items, ",") + "}"
	case map[string]any:
		keys := sortedKeys(value)
		items := make([]string, 0, len(keys))
		for _, key := range keys {
			items = append(items, "["+luaQuote(key)+"]="+luaValue(value[key]))
		}
		return "{" + strings.Join(items, ",") + "}"
	case map[string]string:
		keys := sortedKeys(value)
		items := make([]string, 0, len(keys))
		for _, key := range keys {
			items = append(items, "["+luaQuote(key)+"]="+luaQuote(value[key]))
		}
		return "{" + strings.Join(items, ",") + "}"
	default:
		panic(fmt.Sprintf("unsupported Lua settings value %T", value))
	}
}

func luaQuote(value string) string {
	var out strings.Builder
	out.WriteByte('"')
	for _, r := range value {
		switch r {
		case '\\', '"':
			out.WriteByte('\\')
			out.WriteRune(r)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(&out, `\%03d`, r)
			} else {
				out.WriteRune(r)
			}
		}
	}
	out.WriteByte('"')
	return out.String()
}

func authenticatorUsed(servers []Server, name string) bool {
	for _, server := range servers {
		if server.Authentication != nil {
			for _, candidate := range append(append([]string{}, server.Authentication.AnyOf...), server.Authentication.AllOf...) {
				if candidate == name {
					return true
				}
			}
		}
	}
	return false
}

func jwksClusterName(name string) string { return "jwks-" + name }

func jwksClusters(authenticators []Authenticator, servers []Server) ([]*cluster.Cluster, error) {
	var clusters []*cluster.Cluster
	for _, authenticator := range authenticators {
		if authenticator.JWT == nil || !authenticatorUsed(servers, authenticator.Name) {
			continue
		}
		parsed, err := url.Parse(authenticator.JWT.JWKSURI)
		if err != nil {
			return nil, fmt.Errorf("authenticators.%s.jwt.jwks_uri: %w", authenticator.Name, err)
		}
		port := uint32(443)
		if parsed.Port() != "" {
			value, err := strconv.ParseUint(parsed.Port(), 10, 32)
			if err != nil {
				return nil, fmt.Errorf("authenticators.%s.jwt.jwks_uri port: %w", authenticator.Name, err)
			}
			port = uint32(value)
		}
		name := jwksClusterName(authenticator.Name)
		tlsConfig, err := packEnvoy(&tls.UpstreamTlsContext{Sni: parsed.Hostname(), CommonTlsContext: &tls.CommonTlsContext{ValidationContextType: &tls.CommonTlsContext_ValidationContext{ValidationContext: &tls.CertificateValidationContext{TrustedCa: &core.DataSource{Specifier: &core.DataSource_Filename{Filename: "/etc/ssl/certs/ca-certificates.crt"}}}}}})
		if err != nil {
			return nil, fmt.Errorf("authenticators.%s JWKS TLS: %w", authenticator.Name, err)
		}
		clusters = append(clusters, &cluster.Cluster{
			Name: name, ConnectTimeout: durationpb.New(5 * time.Second),
			ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_STRICT_DNS},
			LoadAssignment:       &endpoint.ClusterLoadAssignment{ClusterName: name, Endpoints: []*endpoint.LocalityLbEndpoints{{LbEndpoints: []*endpoint.LbEndpoint{{HostIdentifier: &endpoint.LbEndpoint_Endpoint{Endpoint: &endpoint.Endpoint{Address: socket(parsed.Hostname(), port)}}}}}}},
			TransportSocket:      &core.TransportSocket{Name: "envoy.transport_sockets.tls", ConfigType: &core.TransportSocket_TypedConfig{TypedConfig: tlsConfig}},
		})
	}
	return clusters, nil
}

func apiRoutes(apis []API) []*route.Route {
	return apiRoutesWithMetadata(apis, false)
}

func apiRoutesWithMetadata(apis []API, includeMetadata bool) []*route.Route {
	var routes []*route.Route
	type methodFallback struct {
		path    PathMatch
		methods []string
	}
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
				name := apiRouteName(apiIndex, api.Name, routeIndex, methodIndex)
				action := &route.RouteAction{
					ClusterSpecifier: &route.RouteAction_Cluster{Cluster: "api-" + api.Name},
					Timeout:          durationpb.New(30 * time.Second),
				}
				applyPathRewrite(action, apiRoute.Rewrite)
				match := pathMatch(apiRoute.Path)
				match.Headers = []*route.HeaderMatcher{methodHeader(method)}
				routeConfig := &route.Route{
					Name:   name,
					Match:  match,
					Action: &route.Route_Route{Route: action},
				}
				if includeMetadata {
					routeConfig.Metadata = apiRouteMetadata(api.Name)
				}
				routes = append(routes, routeConfig)
				fallbacks[fallbackIndex].methods = append(fallbacks[fallbackIndex].methods, method)
			}
		}
	}

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
		methodRoute := &route.Route{
			Name:  "method-not-allowed-" + strconv.Itoa(i),
			Match: pathMatch(fallback.path),
			Action: &route.Route_DirectResponse{DirectResponse: &route.DirectResponseAction{
				Status: 405,
			}},
			ResponseHeadersToAdd: []*core.HeaderValueOption{{
				Header:       &core.HeaderValue{Key: "allow", Value: allow.String()},
				AppendAction: core.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
			}},
		}
		if includeMetadata {
			methodRoute.Metadata = apiRouteMetadata("__local")
		}
		routes = append(routes, methodRoute)
	}
	notFound := &route.Route{
		Name:   "not-found",
		Match:  &route.RouteMatch{PathSpecifier: &route.RouteMatch_Prefix{Prefix: "/"}},
		Action: &route.Route_DirectResponse{DirectResponse: &route.DirectResponseAction{Status: 404}},
	}
	if includeMetadata {
		notFound.Metadata = apiRouteMetadata("__local")
	}
	routes = append(routes, notFound)
	return routes
}

func apiRouteMetadata(apiName string) *core.Metadata {
	api, _ := structpb.NewStruct(map[string]any{"api": apiName})
	return &core.Metadata{FilterMetadata: map[string]*structpb.Struct{"envoy.filters.http.rbac": api}}
}

func serverTLSSecretName(index int) string {
	return "gateway_server_" + strconv.Itoa(index)
}

func serverTLSResourceFilename(index int) string {
	return "server-certificate-" + strconv.Itoa(index) + ".yaml"
}

func serverTLSTransportSocket(index int) (*core.TransportSocket, error) {
	config, err := packEnvoy(&tls.DownstreamTlsContext{CommonTlsContext: &tls.CommonTlsContext{
		TlsParams: &tls.TlsParameters{
			TlsMinimumProtocolVersion: tls.TlsParameters_TLSv1_2,
			TlsMaximumProtocolVersion: tls.TlsParameters_TLSv1_3,
		},
		AlpnProtocols: []string{"h2", "http/1.1"},
		TlsCertificateSdsSecretConfigs: []*tls.SdsSecretConfig{{
			Name:      serverTLSSecretName(index),
			SdsConfig: serverTLSSecretConfigSource(index),
		}},
	}})
	if err != nil {
		return nil, err
	}
	return &core.TransportSocket{
		Name:       "envoy.transport_sockets.tls",
		ConfigType: &core.TransportSocket_TypedConfig{TypedConfig: config},
	}, nil
}

func serverTLSSecretConfigSource(index int) *core.ConfigSource {
	return &core.ConfigSource{
		ResourceApiVersion: core.ApiVersion_V3,
		ConfigSourceSpecifier: &core.ConfigSource_PathConfigSource{PathConfigSource: &core.PathConfigSource{
			Path:             path.Join(configDirectory, serverTLSResourceFilename(index)),
			WatchedDirectory: &core.WatchedDirectory{Path: configDirectory},
		}},
	}
}

const identityMappingECDSRelativePath = "lua/jwt.yaml"

func fileConfigSource(filename string) *core.ConfigSource {
	return &core.ConfigSource{
		ResourceApiVersion: core.ApiVersion_V3,
		ConfigSourceSpecifier: &core.ConfigSource_PathConfigSource{PathConfigSource: &core.PathConfigSource{
			Path:             filename,
			WatchedDirectory: &core.WatchedDirectory{Path: path.Dir(filename)},
		}},
	}
}

func identityMappingECDSResource(script string) (*core.TypedExtensionConfig, error) {
	filterConfig, err := packEnvoy(&lua.Lua{DefaultSourceCode: &core.DataSource{
		Specifier: &core.DataSource_InlineString{InlineString: script},
	}})
	if err != nil {
		return nil, fmt.Errorf("encode Lua filter config: %w", err)
	}
	return &core.TypedExtensionConfig{
		Name:        "envoy.filters.http.lua",
		TypedConfig: filterConfig,
	}, nil
}

func serverTLSSecret(index int, config ServerTLS) *tls.Secret {
	return &tls.Secret{
		Name: serverTLSSecretName(index),
		Type: &tls.Secret_TlsCertificate{TlsCertificate: &tls.TlsCertificate{
			CertificateChain: fileDataSource(config.Certificate),
			PrivateKey:       fileDataSource(config.PrivateKey),
			WatchedDirectory: &core.WatchedDirectory{Path: path.Dir(config.Certificate)},
		}},
	}
}

func fileDataSource(filename string) *core.DataSource {
	return &core.DataSource{Specifier: &core.DataSource_Filename{Filename: filename}}
}

func marshalEnvoyFileDiscoveryResponse(resource proto.Message) ([]byte, error) {
	packed, err := packEnvoy(resource)
	if err != nil {
		return nil, err
	}
	resourceData, err := marshalEnvoyYAML(packed)
	if err != nil {
		return nil, err
	}
	var document any
	if err := yaml.Unmarshal(resourceData, &document); err != nil {
		return nil, fmt.Errorf("decode packed discovery resource: %w", err)
	}
	data, err := yaml.Marshal(map[string]any{"resources": []any{document}})
	if err != nil {
		return nil, fmt.Errorf("encode file discovery response: %w", err)
	}
	return data, nil
}

func pathMatch(path PathMatch) *route.RouteMatch {
	switch {
	case path.Exact != "":
		return &route.RouteMatch{PathSpecifier: &route.RouteMatch_Path{Path: path.Exact}}
	case path.Prefix != "":
		return &route.RouteMatch{PathSpecifier: &route.RouteMatch_Prefix{Prefix: path.Prefix}}
	default:
		return &route.RouteMatch{PathSpecifier: &route.RouteMatch_SafeRegex{SafeRegex: envoySafeRegex(path.Regex)}}
	}
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
		EngineType: &matcher.RegexMatcher_GoogleRe2{GoogleRe2: &matcher.RegexMatcher_GoogleRE2{}},
		Regex:      pattern,
	}
}

func applyPathRewrite(action *route.RouteAction, rewrite *PathRewrite) {
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

func apiClusters(apis []API) []*cluster.Cluster {
	clusters := make([]*cluster.Cluster, 0, len(apis))
	for _, api := range apis {
		name := "api-" + api.Name
		clusters = append(clusters, &cluster.Cluster{
			Name:                          name,
			ConnectTimeout:                durationpb.New(5 * time.Second),
			ClusterDiscoveryType:          &cluster.Cluster_Type{Type: cluster.Cluster_STRICT_DNS},
			PerConnectionBufferLimitBytes: wrapperspb.UInt32(1048576),
			CircuitBreakers: &cluster.CircuitBreakers{Thresholds: []*cluster.CircuitBreakers_Thresholds{{
				Priority:           core.RoutingPriority_DEFAULT,
				MaxConnections:     wrapperspb.UInt32(*api.CircuitBreakers.MaxConnections),
				MaxPendingRequests: wrapperspb.UInt32(*api.CircuitBreakers.MaxPendingRequests),
				MaxRequests:        wrapperspb.UInt32(*api.CircuitBreakers.MaxRequests),
				MaxRetries:         wrapperspb.UInt32(*api.CircuitBreakers.MaxRetries),
			}}},
			LoadAssignment: &endpoint.ClusterLoadAssignment{
				ClusterName: name,
				Endpoints: []*endpoint.LocalityLbEndpoints{{
					LbEndpoints: []*endpoint.LbEndpoint{{
						HostIdentifier: &endpoint.LbEndpoint_Endpoint{Endpoint: &endpoint.Endpoint{
							Address: socket(api.Upstream.Address, api.Upstream.Port),
						}},
					}},
				}},
			},
		})
	}
	return clusters
}

func socket(address string, port uint32) *core.Address {
	return &core.Address{Address: &core.Address_SocketAddress{SocketAddress: &core.SocketAddress{
		Address: address,
		PortSpecifier: &core.SocketAddress_PortValue{
			PortValue: port,
		},
	}}}
}

func packEnvoy(message proto.Message) (*anypb.Any, error) {
	if validatable, ok := message.(envoyValidator); ok {
		if err := validatable.ValidateAll(); err != nil {
			return nil, fmt.Errorf("validate %s: %w", message.ProtoReflect().Descriptor().FullName(), err)
		}
	}
	packed, err := anypb.New(message)
	if err != nil {
		return nil, fmt.Errorf("pack %s: %w", message.ProtoReflect().Descriptor().FullName(), err)
	}
	return packed, nil
}

func marshalEnvoyYAML(message proto.Message) ([]byte, error) {
	if validatable, ok := message.(envoyValidator); ok {
		if err := validatable.ValidateAll(); err != nil {
			return nil, fmt.Errorf("validate %s: %w", message.ProtoReflect().Descriptor().FullName(), err)
		}
	}
	data, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(message)
	if err != nil {
		return nil, fmt.Errorf("encode %s: %w", message.ProtoReflect().Descriptor().FullName(), err)
	}
	var value any
	if err := yaml.Unmarshal(data, &value); err != nil {
		return nil, fmt.Errorf("encode %s: convert JSON to YAML: %w", message.ProtoReflect().Descriptor().FullName(), err)
	}
	data, err = yaml.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode %s: marshal YAML: %w", message.ProtoReflect().Descriptor().FullName(), err)
	}
	return data, nil
}
