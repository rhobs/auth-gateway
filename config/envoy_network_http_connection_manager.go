package config

import (
	"fmt"

	accesslog "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	httpConnectionManagerName = "envoy.filters.network.http_connection_manager"
	httpManagerStatPrefix     = "ingress"
)

func (c effectiveConfig) toHTTPFilterChain(hosts []indexedVirtualHost) (*listener.FilterChain, error) {
	manager, err := c.toHTTPManager(hosts)
	if err != nil {
		return nil, err
	}
	managerConfig, err := packEnvoy(manager)
	if err != nil {
		return nil, fmt.Errorf("encode HTTP connection manager: %w", err)
	}
	return &listener.FilterChain{Filters: []*listener.Filter{{
		Name:       httpConnectionManagerName,
		ConfigType: &listener.Filter_TypedConfig{TypedConfig: managerConfig},
	}}}, nil
}

func (c effectiveConfig) toHTTPManager(hosts []indexedVirtualHost) (*hcm.HttpConnectionManager, error) {
	accessLogs, err := errorAccessLogs()
	if err != nil {
		return nil, err
	}
	virtualHosts := routeVirtualHosts(hosts)
	protected := hasProtectedHosts(hosts)
	filters, err := c.toHTTPFilters(hosts, protected)
	if err != nil {
		return nil, err
	}
	tracing, err := c.Observability.Tracing.toEnvoyTracingConfig()
	if err != nil {
		return nil, err
	}
	var http2Options *core.Http2ProtocolOptions
	if c.Listener.HTTP2 != nil {
		http2Options = c.Listener.HTTP2.envoy()
	}
	manager := &hcm.HttpConnectionManager{
		StatPrefix:            httpManagerStatPrefix,
		CodecType:             hcm.HttpConnectionManager_AUTO,
		MaxRequestHeadersKb:   optionalUint32(c.Listener.MaxRequestHeadersKB),
		RequestHeadersTimeout: c.Listener.RequestHeadersTimeout.protobuf(),
		StreamIdleTimeout:     c.Listener.StreamIdleTimeout.protobuf(),
		StreamFlushTimeout:    c.Listener.StreamFlushTimeout.protobuf(),
		Http2ProtocolOptions:  http2Options,
		CommonHttpProtocolOptions: &core.HttpProtocolOptions{
			IdleTimeout:                  c.Listener.ConnectionIdleTimeout.protobuf(),
			MaxStreamDuration:            c.Listener.MaxStreamDuration.protobuf(),
			MaxHeadersCount:              optionalUint32(c.Listener.MaxRequestHeadersCount),
			HeadersWithUnderscoresAction: core.HttpProtocolOptions_REJECT_REQUEST,
		},
		RequestTimeout:               c.Listener.RequestTimeout.protobuf(),
		NormalizePath:                wrapperspb.Bool(true),
		PathWithEscapedSlashesAction: hcm.HttpConnectionManager_UNESCAPE_AND_FORWARD,
		Tracing:                      tracing,
		RouteSpecifier: &hcm.HttpConnectionManager_RouteConfig{RouteConfig: &route.RouteConfiguration{
			Name:                     ingestionListenerName,
			IgnorePortInHostMatching: true,
			VirtualHosts:             virtualHosts,
		}},
		AccessLog:   accessLogs,
		HttpFilters: filters,
	}
	for _, host := range hosts {
		if c.servers[host.serverIndex].usesMTLS() {
			manager.LocalReplyConfig = mtlsMissingCredentialReply()
			break
		}
	}
	return manager, nil
}

func mtlsMissingCredentialReply() *hcm.LocalReplyConfig {
	status := &accesslog.AccessLogFilter{FilterSpecifier: &accesslog.AccessLogFilter_StatusCodeFilter{StatusCodeFilter: &accesslog.StatusCodeFilter{
		Comparison: &accesslog.ComparisonFilter{Op: accesslog.ComparisonFilter_EQ, Value: &core.RuntimeUInt32{DefaultValue: 403}},
	}}}
	pending := &accesslog.AccessLogFilter{FilterSpecifier: &accesslog.AccessLogFilter_HeaderFilter{HeaderFilter: &accesslog.HeaderFilter{
		Header: mtlsHeaderPrincipal(mtlsPendingHeaderName, "true").GetHeader(),
	}}}
	return &hcm.LocalReplyConfig{Mappers: []*hcm.ResponseMapper{{
		Filter: &accesslog.AccessLogFilter{FilterSpecifier: &accesslog.AccessLogFilter_AndFilter{AndFilter: &accesslog.AndFilter{Filters: []*accesslog.AccessLogFilter{
			status,
			pending,
		}}}},
		StatusCode: wrapperspb.UInt32(401),
	}}}
}
