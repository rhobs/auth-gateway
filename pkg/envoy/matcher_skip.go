package envoy

import (
	"fmt"

	xdscore "github.com/cncf/xds/go/xds/core/v3"
	xdsmatcher "github.com/cncf/xds/go/xds/type/matcher/v3"
	skip "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/common/matcher/action/v3"
)

func apiKeySkipAction() (*xdsmatcher.Matcher_OnMatch, error) {
	packedSkip, err := packEnvoy(&skip.SkipFilter{})
	if err != nil {
		return nil, fmt.Errorf("encode API-key skip action: %w", err)
	}
	return &xdsmatcher.Matcher_OnMatch{OnMatch: &xdsmatcher.Matcher_OnMatch_Action{Action: &xdscore.TypedExtensionConfig{Name: "skip", TypedConfig: packedSkip}}}, nil
}
