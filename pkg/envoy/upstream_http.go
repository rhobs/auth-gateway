package envoy

import (
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	upstreamhttp "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	configuration "github.com/rhobs/auth-gateway/pkg/config"
	"google.golang.org/protobuf/types/known/anypb"
)

func envoyHTTP2Options(h gatewayapi.HTTP2Options) *core.Http2ProtocolOptions {
	return &core.Http2ProtocolOptions{
		MaxConcurrentStreams:        optionalUint32(h.MaxConcurrentStreams),
		InitialStreamWindowSize:     optionalUint32(h.InitialStreamWindowSize),
		InitialConnectionWindowSize: optionalUint32(h.InitialConnectionWindowSize),
	}
}

const upstreamHTTPProtocolOptionsTypeURL = "envoy.extensions.upstreams.http.v3.HttpProtocolOptions"

func upstreamHTTPProtocolOptions(upstream gatewayapi.Upstream) (*anypb.Any, error) {
	protocol := &upstreamhttp.HttpProtocolOptions_ExplicitHttpConfig{ProtocolConfig: &upstreamhttp.HttpProtocolOptions_ExplicitHttpConfig_HttpProtocolOptions{HttpProtocolOptions: &core.Http1ProtocolOptions{}}}
	if upstream.HTTPProtocol == configuration.Http2Protocol {
		var http2 *core.Http2ProtocolOptions
		if upstream.HTTP2 != nil {
			http2 = envoyHTTP2Options(*upstream.HTTP2)
		}
		if http2 == nil {
			http2 = &core.Http2ProtocolOptions{}
		}
		protocol.ProtocolConfig = &upstreamhttp.HttpProtocolOptions_ExplicitHttpConfig_Http2ProtocolOptions{Http2ProtocolOptions: http2}
	}
	return packEnvoy(&upstreamhttp.HttpProtocolOptions{UpstreamProtocolOptions: &upstreamhttp.HttpProtocolOptions_ExplicitHttpConfig_{ExplicitHttpConfig: protocol}})
}
