package config

import (
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	upstreamhttp "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	"google.golang.org/protobuf/types/known/anypb"
)

const upstreamHTTPProtocolOptionsTypeURL = "envoy.extensions.upstreams.http.v3.HttpProtocolOptions"

func upstreamHTTPProtocolOptions(upstream Upstream) (*anypb.Any, error) {
	protocol := &upstreamhttp.HttpProtocolOptions_ExplicitHttpConfig{ProtocolConfig: &upstreamhttp.HttpProtocolOptions_ExplicitHttpConfig_HttpProtocolOptions{HttpProtocolOptions: &core.Http1ProtocolOptions{}}}
	if upstream.HTTPProtocol == http2Protocol {
		var http2 *core.Http2ProtocolOptions
		if upstream.HTTP2 != nil {
			http2 = upstream.HTTP2.envoy()
		}
		if http2 == nil {
			http2 = &core.Http2ProtocolOptions{}
		}
		protocol.ProtocolConfig = &upstreamhttp.HttpProtocolOptions_ExplicitHttpConfig_Http2ProtocolOptions{Http2ProtocolOptions: http2}
	}
	return packEnvoy(&upstreamhttp.HttpProtocolOptions{UpstreamProtocolOptions: &upstreamhttp.HttpProtocolOptions_ExplicitHttpConfig_{ExplicitHttpConfig: protocol}})
}
