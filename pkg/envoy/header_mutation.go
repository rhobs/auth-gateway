package envoy

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	mutationrules "github.com/envoyproxy/go-control-plane/envoy/config/common/mutation_rules/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	headermutation "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/header_mutation/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	configuration "github.com/rhobs/auth-gateway/pkg/config"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	credentialCleanupFilterName  = "auth_gateway.credentials"
	requestControlsFilterName    = "auth_gateway.request_controls"
	headerMutationFilterName     = "envoy.filters.http.header_mutation"
	mtlsPeerHeadersFilterName    = "auth_gateway.mtls.peer_headers"
	mtlsPendingCleanupFilterName = "auth_gateway.mtls.authentication_complete"
)

func toCredentialCleanupConfig(c configuration.ResolvedConfig) *headermutation.HeaderMutation {
	removed := map[string]struct{}{configuration.AuthorizationHeaderName: {}, configuration.ApiKeyClientHeader: {}}
	if c.UsesMTLS() {
		for _, name := range []string{configuration.MtlsPendingHeaderName, configuration.MtlsFingerprintHeaderName, configuration.MtlsURIHeaderName, configuration.MtlsDNSHeaderName} {
			removed[name] = struct{}{}
		}
	}
	if authenticator, exists := c.APIKeyAuthenticator(); exists {
		removed[strings.ToLower(authenticator.APIKey.Header)] = struct{}{}
	}
	for _, authenticator := range c.Authenticators {
		if authenticator.JWT != nil {
			removed[jwtVerifiedHeaderName(authenticator.Name)] = struct{}{}
		}
	}
	mutations := make([]*mutationrules.HeaderMutation, 0, len(removed))
	for _, name := range slices.Sorted(maps.Keys(removed)) {
		mutations = append(mutations, &mutationrules.HeaderMutation{Action: &mutationrules.HeaderMutation_Remove{Remove: name}})
	}
	return &headermutation.HeaderMutation{Mutations: &headermutation.Mutations{RequestMutations: mutations}}
}

// toCredentialCleanupFilter builds the Envoy filter that removes gateway credentials and JWT verification markers before requests reach upstreams.
func toCredentialCleanupFilter(c configuration.ResolvedConfig) (*hcm.HttpFilter, error) {
	cleanup, err := packEnvoy(toCredentialCleanupConfig(c))
	if err != nil {
		return nil, fmt.Errorf("encode credential cleanup filter: %w", err)
	}
	return &hcm.HttpFilter{Name: credentialCleanupFilterName, ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: cleanup}}, nil
}

func requestControlMutations(extra ...string) *headermutation.HeaderMutation {
	mutations := make([]*mutationrules.HeaderMutation, 0, len(configuration.RequestControlHeaders)+len(extra))
	for _, name := range append(slices.Clone(configuration.RequestControlHeaders), extra...) {
		mutations = append(mutations, &mutationrules.HeaderMutation{Action: &mutationrules.HeaderMutation_Remove{Remove: name}})
	}
	return &headermutation.HeaderMutation{Mutations: &headermutation.Mutations{RequestMutations: mutations}}
}

func requestHeaderMutationConfig(apis []gatewayapi.API) *headermutation.HeaderMutation {
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
	for _, name := range slices.Sorted(maps.Keys(managed)) {
		mutations = append(mutations, &mutationrules.HeaderMutation{Action: &mutationrules.HeaderMutation_Remove{Remove: name}})
	}
	return &headermutation.HeaderMutation{Mutations: &headermutation.Mutations{RequestMutations: mutations}}
}

func requestHeaderMutations(mappings []gatewayapi.RequestHeaderMapping) []*mutationrules.HeaderMutation {
	mutations := make([]*mutationrules.HeaderMutation, 0, len(mappings))
	for _, mapping := range mappings {
		mutations = append(mutations, &mutationrules.HeaderMutation{Action: &mutationrules.HeaderMutation_Append{Append: &core.HeaderValueOption{
			Header:       &core.HeaderValue{Key: mapping.Name, Value: "%FILTER_STATE(" + filterStateKey(mapping.FromAttribute) + ":PLAIN)%"},
			AppendAction: core.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		}}})
	}
	return mutations
}

func mtlsPeerHeadersFilter() (*hcm.HttpFilter, error) {
	values := []struct{ name, format string }{
		{configuration.MtlsPendingHeaderName, "true"},
		{configuration.MtlsFingerprintHeaderName, "%DOWNSTREAM_PEER_FINGERPRINT_256%"},
		{configuration.MtlsURIHeaderName, "%DOWNSTREAM_PEER_URI_SAN%"},
		{configuration.MtlsDNSHeaderName, "%DOWNSTREAM_PEER_DNS_SAN%"},
	}
	mutations := make([]*mutationrules.HeaderMutation, 0, len(values))
	for _, value := range values {
		mutations = append(mutations, &mutationrules.HeaderMutation{Action: &mutationrules.HeaderMutation_Append{Append: &core.HeaderValueOption{
			Header:       &core.HeaderValue{Key: value.name, Value: value.format},
			AppendAction: core.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		}}})
	}
	packed, err := packEnvoy(&headermutation.HeaderMutation{Mutations: &headermutation.Mutations{RequestMutations: mutations}})
	if err != nil {
		return nil, err
	}
	return &hcm.HttpFilter{Name: mtlsPeerHeadersFilterName, ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: packed}}, nil
}

func mtlsPendingCleanupFilter() (*hcm.HttpFilter, error) {
	// A denial before this filter is an authentication failure; successful
	// authentication reaches it before authorization runs.
	packed, err := packEnvoy(&headermutation.HeaderMutation{Mutations: &headermutation.Mutations{RequestMutations: []*mutationrules.HeaderMutation{{
		Action: &mutationrules.HeaderMutation_Remove{Remove: configuration.MtlsPendingHeaderName},
	}}}})
	if err != nil {
		return nil, err
	}
	return &hcm.HttpFilter{Name: mtlsPendingCleanupFilterName, ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: packed}}, nil
}

func requestControlHeaderFilter(c configuration.ResolvedConfig) (*hcm.HttpFilter, error) {
	var identityHeaders []string
	if c.UsesAPIKeys() {
		identityHeaders = append(identityHeaders, configuration.ApiKeyClientHeader)
	}
	for _, authenticator := range c.Authenticators {
		if authenticator.JWT != nil && c.AuthenticatorUsed(authenticator.Name) {
			identityHeaders = append(identityHeaders, jwtVerifiedHeaderName(authenticator.Name))
		}
	}
	if c.UsesMTLS() {
		identityHeaders = append(identityHeaders, configuration.MtlsPendingHeaderName, configuration.MtlsFingerprintHeaderName, configuration.MtlsURIHeaderName, configuration.MtlsDNSHeaderName)
	}
	controls, err := packEnvoy(requestControlMutations(identityHeaders...))
	if err != nil {
		return nil, fmt.Errorf("encode request-control header removal: %w", err)
	}
	return &hcm.HttpFilter{Name: requestControlsFilterName, ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: controls}}, nil
}

func requestHeaderHTTPFilter(apis []gatewayapi.API) (*hcm.HttpFilter, error) {
	headerMutationConfig, err := packEnvoy(requestHeaderMutationConfig(apis))
	if err != nil {
		return nil, fmt.Errorf("encode request header mutation filter: %w", err)
	}
	return &hcm.HttpFilter{Name: headerMutationFilterName, ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: headerMutationConfig}}, nil
}

func requestHeaderPerRouteConfig(mappings []gatewayapi.RequestHeaderMapping) (*anypb.Any, error) {
	return packEnvoy(&headermutation.HeaderMutationPerRoute{Mutations: &headermutation.Mutations{RequestMutations: requestHeaderMutations(mappings)}})
}
