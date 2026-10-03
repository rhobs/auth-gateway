package config

import (
	"slices"

	mutationrules "github.com/envoyproxy/go-control-plane/envoy/config/common/mutation_rules/v3"
	headermutation "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/header_mutation/v3"
)

const requestControlsFilterName = "auth_gateway.request_controls"

var requestControlHeaders = []string{
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

func isRequestControlHeader(name string) bool { return slices.Contains(requestControlHeaders, name) }

func requestControlMutations() *headermutation.HeaderMutation {
	mutations := make([]*mutationrules.HeaderMutation, 0, len(requestControlHeaders))
	for _, name := range requestControlHeaders {
		mutations = append(mutations, &mutationrules.HeaderMutation{Action: &mutationrules.HeaderMutation_Remove{Remove: name}})
	}
	return &headermutation.HeaderMutation{Mutations: &headermutation.Mutations{RequestMutations: mutations}}
}
