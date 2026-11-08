package config

import (
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	upstreamhttp "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	"google.golang.org/protobuf/types/known/anypb"
)

const upstreamHTTPProtocolOptionsTypeURL = "envoy.extensions.upstreams.http.v3.HttpProtocolOptions"

func (h HTTP2Options) envoy() *core.Http2ProtocolOptions {
	return &core.Http2ProtocolOptions{
		MaxConcurrentStreams:        optionalUint32(h.MaxConcurrentStreams),
		InitialStreamWindowSize:     optionalUint32(h.InitialStreamWindowSize),
		InitialConnectionWindowSize: optionalUint32(h.InitialConnectionWindowSize),
	}
}

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
