package config

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	mutationrules "github.com/envoyproxy/go-control-plane/envoy/config/common/mutation_rules/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	headermutation "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/header_mutation/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	credentialCleanupFilterName  = "auth_gateway.credentials"
	requestControlsFilterName    = "auth_gateway.request_controls"
	headerMutationFilterName     = "envoy.filters.http.header_mutation"
	mtlsPeerHeadersFilterName    = "auth_gateway.mtls.peer_headers"
	mtlsPendingCleanupFilterName = "auth_gateway.mtls.authentication_complete"
)

var requestControlHeaders = []string{
	"x-envoy-original-path",
	"x-envoy-retry-on",
	"x-envoy-retry-grpc-on",
	"x-envoy-max-retries",
	"x-envoy-hedge-on-per-try-timeout",
	"x-envoy-upstream-rq-timeout-ms",
	"x-envoy-upstream-rq-per-try-timeout-ms",
	"x-envoy-expected-rq-timeout-ms",
	"x-envoy-upstream-alt-stat-name",
	"x-envoy-upstream-stream-duration-ms",
	"x-envoy-upstream-rq-timeout-alt-response",
	"x-envoy-retriable-status-codes",
	"x-envoy-retriable-header-names",
}

func toCredentialCleanupConfig(c effectiveConfig) *headermutation.HeaderMutation {
	removed := map[string]struct{}{authorizationHeaderName: {}, apiKeyClientHeader: {}}
	if c.usesMTLS() {
		for _, name := range []string{mtlsPendingHeaderName, mtlsFingerprintHeaderName, mtlsURIHeaderName, mtlsDNSHeaderName} {
			removed[name] = struct{}{}
		}
	}
	if authenticator, exists := c.apiKeyAuthenticator(); exists {
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
func toCredentialCleanupFilter(c effectiveConfig) (*hcm.HttpFilter, error) {
	cleanup, err := packEnvoy(toCredentialCleanupConfig(c))
	if err != nil {
		return nil, fmt.Errorf("encode credential cleanup filter: %w", err)
	}
	return &hcm.HttpFilter{Name: credentialCleanupFilterName, ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: cleanup}}, nil
}

func requestControlMutations(extra ...string) *headermutation.HeaderMutation {
	mutations := make([]*mutationrules.HeaderMutation, 0, len(requestControlHeaders)+len(extra))
	for _, name := range append(slices.Clone(requestControlHeaders), extra...) {
		mutations = append(mutations, &mutationrules.HeaderMutation{Action: &mutationrules.HeaderMutation_Remove{Remove: name}})
	}
	return &headermutation.HeaderMutation{Mutations: &headermutation.Mutations{RequestMutations: mutations}}
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
	for _, name := range slices.Sorted(maps.Keys(managed)) {
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

func mtlsPeerHeadersFilter() (*hcm.HttpFilter, error) {
	values := []struct{ name, format string }{
		{mtlsPendingHeaderName, "true"},
		{mtlsFingerprintHeaderName, "%DOWNSTREAM_PEER_FINGERPRINT_256%"},
		{mtlsURIHeaderName, "%DOWNSTREAM_PEER_URI_SAN%"},
		{mtlsDNSHeaderName, "%DOWNSTREAM_PEER_DNS_SAN%"},
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
		Action: &mutationrules.HeaderMutation_Remove{Remove: mtlsPendingHeaderName},
	}}}})
	if err != nil {
		return nil, err
	}
	return &hcm.HttpFilter{Name: mtlsPendingCleanupFilterName, ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: packed}}, nil
}

func requestControlHeaderFilter(c effectiveConfig) (*hcm.HttpFilter, error) {
	var identityHeaders []string
	if c.usesAPIKeys() {
		identityHeaders = append(identityHeaders, apiKeyClientHeader)
	}
	for _, authenticator := range c.Authenticators {
		if authenticator.JWT != nil && c.authenticatorUsed(authenticator.Name) {
			identityHeaders = append(identityHeaders, jwtVerifiedHeaderName(authenticator.Name))
		}
	}
	if c.usesMTLS() {
		identityHeaders = append(identityHeaders, mtlsPendingHeaderName, mtlsFingerprintHeaderName, mtlsURIHeaderName, mtlsDNSHeaderName)
	}
	controls, err := packEnvoy(requestControlMutations(identityHeaders...))
	if err != nil {
		return nil, fmt.Errorf("encode request-control header removal: %w", err)
	}
	return &hcm.HttpFilter{Name: requestControlsFilterName, ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: controls}}, nil
}

func requestHeaderHTTPFilter(apis []API) (*hcm.HttpFilter, error) {
	headerMutationConfig, err := packEnvoy(requestHeaderMutationConfig(apis))
	if err != nil {
		return nil, fmt.Errorf("encode request header mutation filter: %w", err)
	}
	return &hcm.HttpFilter{Name: headerMutationFilterName, ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: headerMutationConfig}}, nil
}

func requestHeaderPerRouteConfig(mappings []RequestHeaderMapping) (*anypb.Any, error) {
	return packEnvoy(&headermutation.HeaderMutationPerRoute{Mutations: &headermutation.Mutations{RequestMutations: requestHeaderMutations(mappings)}})
}
