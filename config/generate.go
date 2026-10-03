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
	setfilterstatecommon "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/common/set_filter_state/v3"
	headermutation "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/header_mutation/v3"
	jwt "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/jwt_authn/v3"
	httpRBAC "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rbac/v3"
	router "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	setfilterstate "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"
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

const (
	authorizationFilterName  = "envoy.filters.http.rbac"
	attributeFilterName      = "envoy.filters.http.set_filter_state"
	requiredHeaderFilterName = "auth_gateway.required_headers"
	managedAttributePrefix   = "auth_gateway.attributes."
	processingConfigFilename = "processing.yaml"
	headerValuePattern       = `^[^\x00-\x1f\x7f]+$`
)

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
			host.TypedPerFilterConfig[authorizationFilterName] = rbacConfig
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
	if c.hasAttributeMappings() {
		resource, err := processingECDSResource(c)
		if err != nil {
			return nil, fmt.Errorf("encode attribute processing ECDS resource: %w", err)
		}
		processingData, err := marshalEnvoyFileDiscoveryResponse(resource)
		if err != nil {
			return nil, fmt.Errorf("encode attribute processing ECDS response: %w", err)
		}
		files[processingConfigFilename] = append([]byte("# Generated by github.com/rhobs/auth-gateway.\n"), processingData...)
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
	filters := make([]*hcm.HttpFilter, 0, 8)
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
		rbacConfig, err := packEnvoy(&httpRBAC.RBAC{})
		if err != nil {
			return nil, fmt.Errorf("encode RBAC filter: %w", err)
		}
		filters = append(filters, &hcm.HttpFilter{Name: authorizationFilterName, ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: rbacConfig}})
		if needsWorkingAttributes(c) {
			attributeFilter := &hcm.HttpFilter{Name: attributeFilterName}
			if c.hasAttributeMappings() {
				attributeFilter.ConfigType = &hcm.HttpFilter_ConfigDiscovery{ConfigDiscovery: &core.ExtensionConfigSource{
					ConfigSource: fileConfigSource(path.Join(processingDirectory, processingConfigFilename)),
					TypeUrls:     []string{string((&setfilterstate.Config{}).ProtoReflect().Descriptor().FullName())},
				}}
			} else {
				attributeConfig, err := packEnvoy(attributeInitializationConfig(c))
				if err != nil {
					return nil, fmt.Errorf("encode attribute initialization filter: %w", err)
				}
				attributeFilter.ConfigType = &hcm.HttpFilter_TypedConfig{TypedConfig: attributeConfig}
			}
			filters = append(filters, attributeFilter)
		}
		if hasRequestHeaderProcessing(c.APIs) {
			headerRBACConfig, err := packEnvoy(&httpRBAC.RBAC{})
			if err != nil {
				return nil, fmt.Errorf("encode required-header RBAC filter: %w", err)
			}
			filters = append(filters, &hcm.HttpFilter{Name: requiredHeaderFilterName, ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: headerRBACConfig}})
		}
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
							grants = append(grants, grantPrincipal(c, grant))
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
							grants = append(grants, grantPrincipal(c, grant))
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

func grantPrincipal(c Config, grant AuthorizationGrant) *rbac.Principal {
	conditions := make([]*rbac.Principal, 0, len(grant.Attributes))
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
		authenticator := findAuthenticator(c, grant.Authenticator)
		claimPath := append([]string{grant.Authenticator}, authenticator.JWT.Attributes[attribute].ClaimPath...)
		conditions = append(conditions, jwtClaimPrincipal(claimPath, valueMatcher))
	}
	if len(conditions) == 1 {
		return conditions[0]
	}
	return &rbac.Principal{Identifier: &rbac.Principal_AndIds{AndIds: &rbac.Principal_Set{Ids: conditions}}}
}

func jwtClaimPrincipal(claimPath []string, value *matcher.ValueMatcher) *rbac.Principal {
	metadataPath := make([]*matcher.MetadataMatcher_PathSegment, 0, len(claimPath))
	for _, key := range claimPath {
		metadataPath = append(metadataPath, metadataPathSegment(key))
	}
	return &rbac.Principal{Identifier: &rbac.Principal_SourcedMetadata{SourcedMetadata: &rbac.SourcedMetadata{MetadataSource: rbac.MetadataSource_DYNAMIC, MetadataMatcher: &matcher.MetadataMatcher{
		Filter: "envoy.filters.http.jwt_authn", Path: metadataPath, Value: value,
	}}}}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func metadataPathSegment(key string) *matcher.MetadataMatcher_PathSegment {
	return &matcher.MetadataMatcher_PathSegment{Segment: &matcher.MetadataMatcher_PathSegment_Key{Key: key}}
}

func findAuthenticator(c Config, name string) Authenticator {
	for _, authenticator := range c.Authenticators {
		if authenticator.Name == name {
			return authenticator
		}
	}
	return Authenticator{}
}

func needsWorkingAttributes(c Config) bool {
	return c.hasAttributeMappings() || hasRequestHeaderProcessing(c.APIs)
}

func attributeInitializationConfig(c Config) *setfilterstate.Config {
	config := &setfilterstate.Config{}
	for _, authenticator := range c.Authenticators {
		if !authenticatorUsed(c.Servers, authenticator.Name) || authenticator.JWT == nil {
			continue
		}
		for _, attribute := range sortedKeys(authenticator.JWT.Attributes) {
			claimPath := append([]string{authenticator.Name}, authenticator.JWT.Attributes[attribute].ClaimPath...)
			config.OnRequestHeaders = append(config.OnRequestHeaders, filterStateValue(filterStateKey(attribute), jwtClaimExpression(claimPath)))
		}
	}
	return config
}

func attributeProcessingConfig(c Config) *setfilterstate.Config {
	config := attributeInitializationConfig(c)
	if c.hasAttributeMappings() {
		config.OnRequestHeaders = append(config.OnRequestHeaders, processingMappingConfig(c).OnRequestHeaders...)
	}
	return config
}

func processingECDSResource(c Config) (*core.TypedExtensionConfig, error) {
	filterConfig, err := packEnvoy(attributeProcessingConfig(c))
	if err != nil {
		return nil, fmt.Errorf("encode set_filter_state config: %w", err)
	}
	return &core.TypedExtensionConfig{Name: attributeFilterName, TypedConfig: filterConfig}, nil
}

func processingMappingConfig(c Config) *setfilterstate.Config {
	config := &setfilterstate.Config{}
	for _, processor := range c.Processing {
		for _, attribute := range sortedKeys(processor.Attributes) {
			mappings := processor.Attributes[attribute].Mappings
			if len(mappings) == 0 {
				continue
			}
			config.OnRequestHeaders = append(config.OnRequestHeaders, filterStateValue(filterStateKey(attribute), attributeMappingExpression(attribute, mappings)))
		}
	}
	return config
}

func filterStateValue(key, expression string) *setfilterstatecommon.FilterStateValue {
	return &setfilterstatecommon.FilterStateValue{
		Key:        &setfilterstatecommon.FilterStateValue_ObjectKey{ObjectKey: key},
		FactoryKey: "envoy.string",
		Value: &setfilterstatecommon.FilterStateValue_FormatString{FormatString: &core.SubstitutionFormatString{
			Format:          &core.SubstitutionFormatString_TextFormat{TextFormat: "%CEL(" + expression + ")%"},
			OmitEmptyValues: true,
		}},
		SkipIfEmpty: true,
	}
}

func filterStateKey(attribute string) string {
	return managedAttributePrefix + attribute
}

func jwtClaimExpression(claimPath []string) string {
	current := `metadata.filter_metadata["envoy.filters.http.jwt_authn"]`
	checks := make([]string, 0, len(claimPath))
	for _, key := range claimPath {
		literal := celStringLiteral(key)
		checks = append(checks, literal+" in "+current)
		current += "[" + literal + "]"
	}
	return "((" + strings.Join(checks, " && ") + ") && type(" + current + ") == string && " + current + " != \"\") ? " + current + " : \"\""
}

func attributeMappingExpression(attribute string, mappings map[string]string) string {
	key := celStringLiteral(filterStateKey(attribute))
	value := "filter_state[" + key + "]"
	// An unmatched value returns empty so skip_if_empty preserves the current value.
	result := `""`
	for _, source := range sortedKeys(mappings) {
		result = "(" + value + " == " + celBytesLiteral(source) + " ? " + celStringLiteral(mappings[source]) + " : " + result + ")"
	}
	return "(" + key + " in filter_state && type(" + value + ") == bytes && " + value + " != b\"\") ? " + result + " : \"\""
}

func celStringLiteral(value string) string {
	var out strings.Builder
	out.WriteByte('"')
	for _, character := range value {
		switch character {
		case '\\', '"':
			out.WriteByte('\\')
			out.WriteRune(character)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		case '\b':
			out.WriteString(`\b`)
		case '\f':
			out.WriteString(`\f`)
		default:
			if character < 0x20 || character == 0x7f {
				fmt.Fprintf(&out, `\u%04x`, character)
			} else {
				out.WriteRune(character)
			}
		}
	}
	out.WriteByte('"')
	return out.String()
}

func celBytesLiteral(value string) string {
	var out strings.Builder
	out.WriteString(`b"`)
	for _, character := range []byte(value) {
		switch character {
		case '\\', '"':
			out.WriteByte('\\')
			out.WriteByte(character)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		case '\b':
			out.WriteString(`\b`)
		case '\f':
			out.WriteString(`\f`)
		default:
			if character < 0x20 || character > 0x7e {
				fmt.Fprintf(&out, `\x%02x`, character)
			} else {
				out.WriteByte(character)
			}
		}
	}
	out.WriteByte('"')
	return out.String()
}

func requiredHeaderRBACRules(mappings []RequestHeaderMapping) *rbac.RBAC {
	attributes := make(map[string]struct{}, len(mappings))
	for _, mapping := range mappings {
		attributes[mapping.FromAttribute] = struct{}{}
	}
	principals := make([]*rbac.Principal, 0, len(attributes))
	for _, attribute := range sortedKeys(attributes) {
		principals = append(principals, &rbac.Principal{Identifier: &rbac.Principal_FilterState{FilterState: &matcher.FilterStateMatcher{
			Key: filterStateKey(attribute),
			Matcher: &matcher.FilterStateMatcher_StringMatch{StringMatch: &matcher.StringMatcher{MatchPattern: &matcher.StringMatcher_SafeRegex{SafeRegex: &matcher.RegexMatcher{
				EngineType: &matcher.RegexMatcher_GoogleRe2{GoogleRe2: &matcher.RegexMatcher_GoogleRE2{}},
				Regex:      headerValuePattern,
			}}}},
		}}})
	}
	principal := principals[0]
	if len(principals) > 1 {
		principal = &rbac.Principal{Identifier: &rbac.Principal_AndIds{AndIds: &rbac.Principal_Set{Ids: principals}}}
	}
	return &rbac.RBAC{Action: rbac.RBAC_ALLOW, Policies: map[string]*rbac.Policy{
		"required-attributes": {
			Permissions: []*rbac.Permission{{Rule: &rbac.Permission_Any{Any: true}}},
			Principals:  []*rbac.Principal{principal},
		},
	}}
}

func apiRoutesWithRequestHeaderMutations(apis []API, includeMetadata bool) ([]*route.Route, error) {
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
				perRouteConfig, err := packEnvoy(&headermutation.HeaderMutationPerRoute{Mutations: &headermutation.Mutations{RequestMutations: requestHeaderMutations(apiRoute.Processing.RequestHeaders)}})
				if err != nil {
					return nil, fmt.Errorf("encode request header mutations for route %q: %w", name, err)
				}
				headerRBACConfig, err := packEnvoy(&httpRBAC.RBACPerRoute{Rbac: &httpRBAC.RBAC{Rules: requiredHeaderRBACRules(apiRoute.Processing.RequestHeaders)}})
				if err != nil {
					return nil, fmt.Errorf("encode required-header RBAC rules for route %q: %w", name, err)
				}
				generatedRoute.TypedPerFilterConfig = map[string]*anypb.Any{
					"envoy.filters.http.header_mutation": perRouteConfig,
					requiredHeaderFilterName:             headerRBACConfig,
				}
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
			Header:       &core.HeaderValue{Key: mapping.Name, Value: "%FILTER_STATE(" + filterStateKey(mapping.FromAttribute) + ":PLAIN)%"},
			AppendAction: core.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		}}})
	}
	return mutations
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
	return fileConfigSource(path.Join(configDirectory, serverTLSResourceFilename(index)))
}

func fileConfigSource(filename string) *core.ConfigSource {
	return &core.ConfigSource{
		ResourceApiVersion: core.ApiVersion_V3,
		ConfigSourceSpecifier: &core.ConfigSource_PathConfigSource{PathConfigSource: &core.PathConfigSource{
			Path:             filename,
			WatchedDirectory: &core.WatchedDirectory{Path: path.Dir(filename)},
		}},
	}
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
