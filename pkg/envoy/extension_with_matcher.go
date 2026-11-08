package envoy

import (
	"fmt"

	xdsmatcher "github.com/cncf/xds/go/xds/type/matcher/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	matching "github.com/envoyproxy/go-control-plane/envoy/extensions/common/matching/v3"
	configuration "github.com/rhobs/auth-gateway/pkg/config"
	"google.golang.org/protobuf/types/known/anypb"
)

func toAPIKeyPerRouteConfig(c configuration.ResolvedConfig, server configuration.ResolvedServer) (*anypb.Any, error) {
	config := &matching.ExtensionWithMatcherPerRoute{}
	if server.MixedAnyOf() {
		matcher, err := toAPIKeySkipMatcher(c, server)
		if err != nil {
			return nil, err
		}
		config.XdsMatcher = matcher
	}
	perRoute, err := packEnvoy(config)
	if err != nil {
		return nil, err
	}
	return packEnvoy(&route.FilterConfig{Config: perRoute})
}

func toAPIKeySkipMatcher(c configuration.ResolvedConfig, server configuration.ResolvedServer) (*xdsmatcher.Matcher, error) {
	action, err := apiKeySkipAction()
	if err != nil {
		return nil, err
	}
	var fields []*xdsmatcher.Matcher_MatcherList_FieldMatcher
	for _, authenticator := range server.Authenticators {
		if authenticator.JWT == nil {
			continue
		}
		input, err := requestHeaderMatcherInput(jwtVerifiedHeaderName(authenticator.Name))
		if err != nil {
			return nil, fmt.Errorf("encode JWT marker input: %w", err)
		}
		fields = append(fields, &xdsmatcher.Matcher_MatcherList_FieldMatcher{
			Predicate: &xdsmatcher.Matcher_MatcherList_Predicate{MatchType: &xdsmatcher.Matcher_MatcherList_Predicate_SinglePredicate_{SinglePredicate: &xdsmatcher.Matcher_MatcherList_Predicate_SinglePredicate{
				Input:   input,
				Matcher: &xdsmatcher.Matcher_MatcherList_Predicate_SinglePredicate_ValueMatch{ValueMatch: &xdsmatcher.StringMatcher{MatchPattern: &xdsmatcher.StringMatcher_Exact{Exact: authenticator.JWT.Issuer}}},
			}}},
			OnMatch: action,
		})
	}
	if server.UsesMTLS() {
		input, err := requestHeaderMatcherInput(configuration.MtlsFingerprintHeaderName)
		if err != nil {
			return nil, fmt.Errorf("encode mTLS marker input: %w", err)
		}
		fields = append(fields, &xdsmatcher.Matcher_MatcherList_FieldMatcher{
			Predicate: &xdsmatcher.Matcher_MatcherList_Predicate{MatchType: &xdsmatcher.Matcher_MatcherList_Predicate_SinglePredicate_{SinglePredicate: &xdsmatcher.Matcher_MatcherList_Predicate_SinglePredicate{
				Input: input,
				Matcher: &xdsmatcher.Matcher_MatcherList_Predicate_SinglePredicate_ValueMatch{ValueMatch: &xdsmatcher.StringMatcher{
					MatchPattern: &xdsmatcher.StringMatcher_SafeRegex{SafeRegex: &xdsmatcher.RegexMatcher{
						EngineType: &xdsmatcher.RegexMatcher_GoogleRe2{GoogleRe2: &xdsmatcher.RegexMatcher_GoogleRE2{}},
						Regex:      configuration.MtlsFingerprintPattern,
					}},
				}},
			}}},
			OnMatch: action,
		})
	}
	return &xdsmatcher.Matcher{MatcherType: &xdsmatcher.Matcher_MatcherList_{MatcherList: &xdsmatcher.Matcher_MatcherList{Matchers: fields}}}, nil
}

func extensionWithMatcherConfig(config *core.TypedExtensionConfig) (*anypb.Any, error) {
	return packEnvoy(&matching.ExtensionWithMatcher{ExtensionConfig: config})
}

func extensionWithMatcherTypeName() string {
	return string((&matching.ExtensionWithMatcher{}).ProtoReflect().Descriptor().FullName())
}
