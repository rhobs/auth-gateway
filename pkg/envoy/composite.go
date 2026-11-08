package envoy

import (
	xdscore "github.com/cncf/xds/go/xds/core/v3"
	xdsmatcher "github.com/cncf/xds/go/xds/type/matcher/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	composite "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/composite/v3"
	"google.golang.org/protobuf/types/known/anypb"
)

const admissionCompositeFilterName = "envoy.filters.http.composite"

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
