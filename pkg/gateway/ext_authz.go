package gateway

import (
	"fmt"
	"slices"
	"strings"
	"time"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	mutationrules "github.com/envoyproxy/go-control-plane/envoy/config/common/mutation_rules/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	extauthz "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	headermutation "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/header_mutation/v3"
	lua "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/lua/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	envoytype "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	extAuthzFilterPrefix          = "auth_gateway.ext_authz."
	extAuthzMetadataName          = "auth_gateway.ext_authz.access"
	extAuthzInputMetadataName     = "auth_gateway.ext_authz.attributes"
	extAuthzAttributeBridgeName   = "auth_gateway.ext_authz.attribute_bridge"
	extAuthzCredentialCleanupName = "auth_gateway.ext_authz.credentials"
)

func extAuthzFilterName(service string) string  { return extAuthzFilterPrefix + service }
func extAuthzClusterName(service string) string { return "ext-authz-" + service }

func cloneExtAuthzService(service gatewayapi.ExternalAuthorizationService) gatewayapi.ExternalAuthorizationService {
	service.Upstream = cloneUpstream(service.Upstream)
	service.Timeout = clonePointer(service.Timeout)
	service.RequestHeaders = slices.Clone(service.RequestHeaders)
	service.CredentialHeaders = slices.Clone(service.CredentialHeaders)
	service.Attributes = cloneSlice(service.Attributes, cloneAttributeSource)
	return service
}

func withDefaultsExtAuthzService(service gatewayapi.ExternalAuthorizationService) gatewayapi.ExternalAuthorizationService {
	service.Upstream = withDefaultsUpstream(service.Upstream)
	service.Timeout = withDefaultDuration(service.Timeout, 300*time.Millisecond)
	return service
}

func validateExtAuthzServices(c gatewayapi.Config) (map[string]gatewayapi.ExternalAuthorizationService, error) {
	known := make(map[string]gatewayapi.ExternalAuthorizationService, len(c.ExtAuthzServices))
	for index, service := range c.ExtAuthzServices {
		field := fmt.Sprintf("ext_authz_services[%d]", index)
		if err := validateGatewayName(field, service.Name); err != nil {
			return nil, err
		}
		if _, exists := known[service.Name]; exists {
			return nil, fmt.Errorf("duplicate ext_authz service %q", service.Name)
		}
		if service.Upstream.HTTPProtocol != http2Protocol {
			return nil, fmt.Errorf("%s.upstream.http_protocol must be http2", field)
		}
		if service.Upstream.TLSConfig == nil {
			return nil, fmt.Errorf("%s.upstream.tls_config is required", field)
		}
		if !validHost(service.Upstream.Address) || service.Upstream.Port == 0 || service.Upstream.Port > 65535 {
			return nil, fmt.Errorf("%s.upstream must have a valid address and port", field)
		}
		if err := validateUpstream(service.Upstream, field+".upstream", c.Kubernetes != nil); err != nil {
			return nil, err
		}
		if err := validateDuration(field+".timeout", service.Timeout, false); err != nil {
			return nil, err
		}
		if len(service.RequestHeaders) == 0 {
			return nil, fmt.Errorf("%s.request_headers must not be empty", field)
		}
		allowed := make(map[string]bool, len(service.RequestHeaders))
		for _, header := range service.RequestHeaders {
			name := strings.ToLower(header)
			if !validExtAuthzHeader(header) || allowed[name] {
				return nil, fmt.Errorf("%s.request_headers contains invalid or duplicate header %q", field, header)
			}
			allowed[name] = true
		}
		seen := make(map[string]bool, len(service.CredentialHeaders))
		for _, header := range service.CredentialHeaders {
			name := strings.ToLower(header)
			if !allowed[name] || seen[name] {
				return nil, fmt.Errorf("%s.credential_headers must contain distinct request_headers", field)
			}
			seen[name] = true
		}
		if err := validateExtAuthzAttributes(field, service, allowed, seen); err != nil {
			return nil, err
		}
		known[service.Name] = service
	}
	return known, nil
}

func validateExtAuthzAttributes(field string, service gatewayapi.ExternalAuthorizationService, allowed, credentials map[string]bool) error {
	seen := make(map[string]bool, len(service.Attributes))
	for index, source := range service.Attributes {
		name := fmt.Sprintf("%s.attributes[%d]", field, index)
		if !attributeNamePattern.MatchString(source.Name) || seen[source.Name] {
			return fmt.Errorf("%s.name must be a unique valid attribute name", name)
		}
		seen[source.Name] = true
		if source.Value.IsPath {
			return fmt.Errorf("%s.value must be a single name", name)
		}
		switch source.FromSource {
		case attributeSourceHeader:
			header := strings.ToLower(source.Value.Text)
			if !allowed[header] || credentials[header] || forbiddenIdentityHeader(header) {
				return fmt.Errorf("%s.value must name a safe request_headers entry", name)
			}
		case "authenticator":
			if source.Name != source.Value.Text {
				return fmt.Errorf("%s.value must match name for an authenticator attribute", name)
			}
		default:
			return fmt.Errorf("%s.from_source must be header or authenticator", name)
		}
	}
	return nil
}

func validExtAuthzHeader(name string) bool {
	if !validHeaderFieldName(name) || strings.Contains(name, "_") {
		return false
	}
	lower := strings.ToLower(name)
	return lower == authorizationHeaderName || lower == "cookie" || !forbiddenIdentityHeader(lower)
}

func validateExtAuthzAccess(field string, access resolvedAccess, known map[string]gatewayapi.ExternalAuthorizationService) error {
	selected := access.Authorization.ExtAuthz
	if selected == nil {
		return nil
	}
	service, exists := known[selected.Service]
	if !exists {
		return fmt.Errorf("%s.authorization.ext_authz.service references unknown service %q", field, selected.Service)
	}
	for _, source := range service.Attributes {
		for _, authenticator := range access.authenticators {
			_, ok := authenticatorAttribute(authenticator, source.Name)
			if source.FromSource == attributeSourceHeader && ok {
				return fmt.Errorf("%s.authorization.ext_authz.service attribute %q collides with authenticator %q", field, source.Name, authenticator.Name)
			}
			if source.FromSource == "authenticator" && !ok {
				return fmt.Errorf("%s.authorization.ext_authz.service attribute %q requires an attribute from authenticator %q", field, source.Name, authenticator.Name)
			}
		}
	}
	return nil
}

func extAuthzAttribute(service gatewayapi.ExternalAuthorizationService, name string) (gatewayapi.AttributeSource, bool) {
	for _, source := range service.Attributes {
		if source.Name == name {
			return source, true
		}
	}
	return gatewayapi.AttributeSource{}, false
}

func extAuthzProvidesAttribute(access resolvedAccess, service gatewayapi.ExternalAuthorizationService, name string) bool {
	source, ok := extAuthzAttribute(service, name)
	if !ok {
		return false
	}
	if source.FromSource == attributeSourceHeader {
		return true
	}
	if len(access.authenticators) == 0 {
		return false
	}
	for _, authenticator := range access.authenticators {
		_, exists := authenticatorAttribute(authenticator, source.Value.Text)
		if !exists {
			return false
		}
	}
	return true
}

func extAuthzCluster(service gatewayapi.ExternalAuthorizationService) (*cluster.Cluster, error) {
	upstream := service.Upstream
	options, err := upstreamHTTPProtocolOptions(upstream)
	if err != nil {
		return nil, err
	}
	identity := upstream.TLSConfig.ServerName
	if identity == "" {
		identity = upstream.Address
	}
	tlsSocket, err := verifiedTLS(identity, upstream.TLSConfig.TrustedCA, []string{"h2"})
	if err != nil {
		return nil, err
	}
	name := extAuthzClusterName(service.Name)
	return &cluster.Cluster{
		Name: name, ConnectTimeout: protobufDuration(upstream.ConnectTimeout),
		ClusterDiscoveryType:          &cluster.Cluster_Type{Type: cluster.Cluster_STRICT_DNS},
		PerConnectionBufferLimitBytes: optionalUint32(upstream.PerConnectionBufferLimitBytes),
		TypedExtensionProtocolOptions: map[string]*anypb.Any{upstreamHTTPProtocolOptionsTypeURL: options},
		CircuitBreakers:               circuitBreakers(withDefaultsCircuitBreakerConfig(nil)),
		LoadAssignment:                &endpoint.ClusterLoadAssignment{ClusterName: name, Endpoints: []*endpoint.LocalityLbEndpoints{{LbEndpoints: []*endpoint.LbEndpoint{{HostIdentifier: &endpoint.LbEndpoint_Endpoint{Endpoint: &endpoint.Endpoint{Address: socket(upstream.Address, upstream.Port)}}}}}}},
		TransportSocket:               tlsSocket,
	}, nil
}

func extAuthzHTTPFilter(service gatewayapi.ExternalAuthorizationService) (*hcm.HttpFilter, error) {
	patterns := make([]*matcher.StringMatcher, 0, len(service.RequestHeaders))
	for _, header := range service.RequestHeaders {
		patterns = append(patterns, &matcher.StringMatcher{MatchPattern: &matcher.StringMatcher_Exact{Exact: strings.ToLower(header)}})
	}
	grpc := &core.GrpcService{TargetSpecifier: &core.GrpcService_EnvoyGrpc_{EnvoyGrpc: &core.GrpcService_EnvoyGrpc{ClusterName: extAuthzClusterName(service.Name)}}, Timeout: protobufDuration(service.Timeout)}
	config, err := packEnvoy(&extauthz.ExtAuthz{
		Services:                       &extauthz.ExtAuthz_GrpcService{GrpcService: grpc},
		TransportApiVersion:            core.ApiVersion_V3,
		StatusOnError:                  &envoytype.HttpStatus{Code: envoytype.StatusCode_ServiceUnavailable},
		ValidateMutations:              true,
		MetadataContextNamespaces:      []string{extAuthzInputMetadataName, jwtAuthnFilterName},
		RouteMetadataContextNamespaces: []string{extAuthzMetadataName},
		AllowedHeaders:                 &matcher.ListStringMatcher{Patterns: patterns},
		DecoderHeaderMutationRules:     &mutationrules.HeaderMutationRules{DisallowAll: wrapperspb.Bool(true), DisallowIsError: wrapperspb.Bool(true)},
	})
	if err != nil {
		return nil, err
	}
	return &hcm.HttpFilter{Name: extAuthzFilterName(service.Name), Disabled: true, ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: config}}, nil
}

func extAuthzPerRouteConfig() (*anypb.Any, error) {
	return packEnvoy(&extauthz.ExtAuthzPerRoute{Override: &extauthz.ExtAuthzPerRoute_Disabled{Disabled: false}})
}

func extAuthzAttributeBridgeFilter() (*hcm.HttpFilter, error) {
	config, err := packEnvoy(&lua.Lua{
		DefaultSourceCode: &core.DataSource{Specifier: &core.DataSource_InlineString{InlineString: "function envoy_on_request(handle) end"}},
		ClearRouteCache:   wrapperspb.Bool(false),
	})
	if err != nil {
		return nil, err
	}
	return &hcm.HttpFilter{Name: extAuthzAttributeBridgeName, ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: config}}, nil
}

func extAuthzAttributeBridgePerRouteConfig(attributes []gatewayapi.AttributeSource) (*anypb.Any, error) {
	names := make([]string, 0, len(attributes))
	for _, source := range attributes {
		names = append(names, source.Name)
	}
	slices.Sort(names)
	var script strings.Builder
	script.WriteString("function envoy_on_request(handle)\n  local state = handle:streamInfo():filterState()\n  local metadata = handle:streamInfo():dynamicMetadata()\n")
	for _, name := range names {
		fmt.Fprintf(&script, "  do\n    local value = state:get(%q)\n    if value ~= nil and value ~= \"\" then\n      metadata:set(%q, %q, value)\n    end\n  end\n", filterStateKey(name), extAuthzInputMetadataName, name)
	}
	script.WriteString("end\n")
	return packEnvoy(&lua.LuaPerRoute{Override: &lua.LuaPerRoute_SourceCode{SourceCode: &core.DataSource{Specifier: &core.DataSource_InlineString{InlineString: script.String()}}}})
}

func extAuthzRouteMetadata(apiName string, access resolvedAccess) *structpb.Struct {
	label := access.Name
	if access.Tenant != "" {
		label = access.Tenant
	}
	metadata, _ := structpb.NewStruct(map[string]any{"api": apiName, "access": label})
	return metadata
}

func extAuthzCredentialCleanupFilter() (*hcm.HttpFilter, error) {
	config, err := packEnvoy(&headermutation.HeaderMutation{})
	if err != nil {
		return nil, err
	}
	return &hcm.HttpFilter{Name: extAuthzCredentialCleanupName, ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: config}}, nil
}

func extAuthzCredentialCleanupPerRouteConfig(headers []string) (*anypb.Any, error) {
	mutations := make([]*mutationrules.HeaderMutation, 0, len(headers))
	for _, header := range headers {
		mutations = append(mutations, &mutationrules.HeaderMutation{Action: &mutationrules.HeaderMutation_Remove{Remove: strings.ToLower(header)}})
	}
	return packEnvoy(&headermutation.HeaderMutationPerRoute{Mutations: &headermutation.Mutations{RequestMutations: mutations}})
}
