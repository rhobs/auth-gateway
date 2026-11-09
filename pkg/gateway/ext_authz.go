package gateway

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	mutationrules "github.com/envoyproxy/go-control-plane/envoy/config/common/mutation_rules/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	extauthz "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	headermutation "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/header_mutation/v3"
	setfilterstate "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"
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
	extAuthzAttributeFilterName   = "auth_gateway.ext_authz.attributes"
	extAuthzCredentialCleanupName = "auth_gateway.ext_authz.credentials"
)

func extAuthzFilterName(service string) string  { return extAuthzFilterPrefix + service }
func extAuthzClusterName(service string) string { return "ext-authz-" + service }

func cloneExtAuthzService(service gatewayapi.ExternalAuthorizationService) gatewayapi.ExternalAuthorizationService {
	service.Upstream = cloneUpstream(service.Upstream)
	service.Timeout = clonePointer(service.Timeout)
	service.RequestHeaders = slices.Clone(service.RequestHeaders)
	service.CredentialHeaders = slices.Clone(service.CredentialHeaders)
	return service
}

func withDefaultsExtAuthzService(service gatewayapi.ExternalAuthorizationService) gatewayapi.ExternalAuthorizationService {
	service.Upstream = withDefaultsUpstream(service.Upstream)
	service.Timeout = withDefaultDuration(service.Timeout, 300*time.Millisecond)
	return service
}

func cloneExternalAuthorization(value gatewayapi.ExternalAuthorization) gatewayapi.ExternalAuthorization {
	value.ResponseAttributes = maps.Clone(value.ResponseAttributes)
	for name, path := range value.ResponseAttributes {
		value.ResponseAttributes[name] = slices.Clone(path)
	}
	return value
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
		known[service.Name] = service
	}
	return known, nil
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
	if _, exists := known[selected.Service]; !exists {
		return fmt.Errorf("%s.authorization.ext_authz.service references unknown service %q", field, selected.Service)
	}
	for _, name := range slices.Sorted(maps.Keys(selected.ResponseAttributes)) {
		path := selected.ResponseAttributes[name]
		if !attributeNamePattern.MatchString(name) || len(path) == 0 || slices.Contains(path, "") {
			return fmt.Errorf("%s.authorization.ext_authz.response_attributes.%s must have a valid name and nonempty path", field, name)
		}
		for _, authenticator := range access.authenticators {
			if providesAttributeAuthenticator(authenticator, name) {
				return fmt.Errorf("%s.authorization.ext_authz.response_attributes.%s collides with authenticator %q", field, name, authenticator.Name)
			}
		}
	}
	return nil
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
		EnableDynamicMetadataIngestion: wrapperspb.Bool(true),
		MetadataContextNamespaces:      []string{jwtAuthnFilterName, apiKeyMetadataNamespace, mtlsMetadataNamespace},
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

func extAuthzAttributeFilter() (*hcm.HttpFilter, error) {
	config, err := packEnvoy(&setfilterstate.Config{})
	if err != nil {
		return nil, err
	}
	return &hcm.HttpFilter{Name: extAuthzAttributeFilterName, Disabled: true, ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: config}}, nil
}

func extAuthzAttributePerRouteConfig(attributes map[string][]string) (*anypb.Any, error) {
	config := &setfilterstate.Config{}
	for _, name := range slices.Sorted(maps.Keys(attributes)) {
		value, check := metadataStringPathExpression("envoy.filters.http.ext_authz", attributes[name])
		expression := "(" + check + " && " + value + " != \"\") ? " + value + " : \"\""
		config.OnRequestHeaders = append(config.OnRequestHeaders, filterStateValue(filterStateKey(name), expression))
	}
	packed, err := packEnvoy(config)
	if err != nil {
		return nil, err
	}
	return packEnvoy(&route.FilterConfig{Config: packed})
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
