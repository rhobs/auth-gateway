package gateway

import (
	"fmt"
	"time"

	accesslog "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	envoyAdminAddress         = "127.0.0.1"
	envoyAdminPort            = 9901
	envoyListenerAddress      = "0.0.0.0"
	defaultListenerPort       = 8080
	ingestionListenerName     = "ingestion"
	httpConnectionManagerName = "envoy.filters.network.http_connection_manager"
	httpManagerStatPrefix     = "ingress"
)

func hasHTTPConfig(c gatewayapi.Config) bool {
	for _, server := range c.Servers {
		if server.TLSConfig == nil {
			return true
		}
	}
	return false
}

func hasHTTPSConfig(c gatewayapi.Config) bool {
	for _, server := range c.Servers {
		if server.TLSConfig != nil {
			return true
		}
	}
	return false
}

func withDefaultsListener(l gatewayapi.Listener) gatewayapi.Listener {
	l.Port = defaultValue(l.Port, defaultListenerPort)
	l.PerConnectionBufferLimitBytes = defaultValue(l.PerConnectionBufferLimitBytes, 1048576)
	l.MaxRequestHeadersKB = defaultValue(l.MaxRequestHeadersKB, 32)
	l.MaxRequestHeadersCount = defaultValue(l.MaxRequestHeadersCount, 100)
	l.RequestHeadersTimeout = withDefaultDuration(l.RequestHeadersTimeout, 5*time.Second)
	l.RequestTimeout = withDefaultDuration(l.RequestTimeout, 30*time.Second)
	l.ConnectionIdleTimeout = withDefaultDuration(l.ConnectionIdleTimeout, time.Minute)
	l.StreamIdleTimeout = withDefaultDuration(l.StreamIdleTimeout, time.Minute)
	l.MaxStreamDuration = withDefaultDuration(l.MaxStreamDuration, 30*time.Second)
	l.StreamFlushTimeout = withDefaultDuration(l.StreamFlushTimeout, 5*time.Second)
	l.TLSHandshakeTimeout = withDefaultDuration(l.TLSHandshakeTimeout, 5*time.Second)
	return l
}

func cloneListener(l gatewayapi.Listener) gatewayapi.Listener {
	l.Port = clonePointer(l.Port)
	l.PerConnectionBufferLimitBytes = clonePointer(l.PerConnectionBufferLimitBytes)
	l.MaxRequestHeadersKB = clonePointer(l.MaxRequestHeadersKB)
	l.MaxRequestHeadersCount = clonePointer(l.MaxRequestHeadersCount)
	l.RequestHeadersTimeout = clonePointer(l.RequestHeadersTimeout)
	l.RequestTimeout = clonePointer(l.RequestTimeout)
	l.ConnectionIdleTimeout = clonePointer(l.ConnectionIdleTimeout)
	l.StreamIdleTimeout = clonePointer(l.StreamIdleTimeout)
	l.MaxStreamDuration = clonePointer(l.MaxStreamDuration)
	l.StreamFlushTimeout = clonePointer(l.StreamFlushTimeout)
	l.TLSHandshakeTimeout = clonePointer(l.TLSHandshakeTimeout)
	l.HTTP2 = cloneConfigPointer(l.HTTP2, cloneHTTP2Options)
	return l
}

func validateListener(l gatewayapi.Listener, metricsEnabled, tracingEnabled bool) error {
	if *l.Port == 0 || *l.Port > 65535 {
		return fmt.Errorf("listener.port must be between 1 and 65535")
	}
	if err := validateObservabilityListenerPort(l.Port, metricsEnabled, tracingEnabled); err != nil {
		return err
	}
	for _, value := range []struct {
		Name  string
		Value *uint32
		Max   uint32
	}{
		{"per_connection_buffer_limit_bytes", l.PerConnectionBufferLimitBytes, ^uint32(0)},
		{"max_request_headers_kb", l.MaxRequestHeadersKB, 8192},
		{"max_request_headers_count", l.MaxRequestHeadersCount, ^uint32(0)},
	} {
		if *value.Value == 0 || *value.Value > value.Max {
			return fmt.Errorf("listener.%s must be between 1 and %d", value.Name, value.Max)
		}
	}
	for _, value := range []struct {
		Name  string
		Value *gatewayapi.Duration
	}{
		{"request_headers_timeout", l.RequestHeadersTimeout}, {"request_timeout", l.RequestTimeout},
		{"connection_idle_timeout", l.ConnectionIdleTimeout}, {"stream_idle_timeout", l.StreamIdleTimeout},
		{maxStreamDurationFieldName, l.MaxStreamDuration}, {"stream_flush_timeout", l.StreamFlushTimeout},
		{"tls_handshake_timeout", l.TLSHandshakeTimeout},
	} {
		if err := validateDuration("listener."+value.Name, value.Value, false); err != nil {
			return err
		}
	}
	if *l.RequestHeadersTimeout > *l.RequestTimeout {
		return fmt.Errorf("listener.request_headers_timeout (%s) must not exceed listener.request_timeout (%s)", l.RequestHeadersTimeout, l.RequestTimeout)
	}
	if l.HTTP2 != nil {
		return validateHTTP2Options(*l.HTTP2, "listener.http2")
	}
	return nil
}

func validateObservabilityListenerPort(port *uint32, metricsEnabled, tracingEnabled bool) error {
	if *port == envoyAdminPort {
		return fmt.Errorf(listenerPortConflictErrorFormat, envoyAdminPort, defaultOTelMetricsPort)
	}
	if metricsEnabled && *port == defaultOTelMetricsPort {
		return fmt.Errorf(listenerPortConflictErrorFormat, envoyAdminPort, defaultOTelMetricsPort)
	}
	if tracingEnabled && *port == defaultOTelTracePort {
		return fmt.Errorf("listener.port must not conflict with the OTLP trace collector port %d", defaultOTelTracePort)
	}
	return nil
}

func toHTTPFilterChain(c resolvedConfig, hosts []indexedVirtualHost) (*listener.FilterChain, error) {
	manager, err := toHTTPManager(c, hosts)
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

func toHTTPManager(c resolvedConfig, hosts []indexedVirtualHost) (*hcm.HttpConnectionManager, error) {
	accessLogs, err := errorAccessLogs()
	if err != nil {
		return nil, err
	}
	virtualHosts := routeVirtualHosts(hosts)
	protected := hasProtectedHosts(hosts)
	filters, err := toHTTPFilters(c, hosts, protected)
	if err != nil {
		return nil, err
	}
	tracing, err := tracingConfig(c.Observability.Tracing)
	if err != nil {
		return nil, err
	}
	var http2Options *core.Http2ProtocolOptions
	if c.Listener.HTTP2 != nil {
		http2Options = envoyHTTP2Options(*c.Listener.HTTP2)
	}
	manager := &hcm.HttpConnectionManager{
		StatPrefix:            httpManagerStatPrefix,
		CodecType:             hcm.HttpConnectionManager_AUTO,
		MaxRequestHeadersKb:   optionalUint32(c.Listener.MaxRequestHeadersKB),
		RequestHeadersTimeout: protobufDuration(c.Listener.RequestHeadersTimeout),
		StreamIdleTimeout:     protobufDuration(c.Listener.StreamIdleTimeout),
		StreamFlushTimeout:    protobufDuration(c.Listener.StreamFlushTimeout),
		Http2ProtocolOptions:  http2Options,
		CommonHttpProtocolOptions: &core.HttpProtocolOptions{
			IdleTimeout:                  protobufDuration(c.Listener.ConnectionIdleTimeout),
			MaxStreamDuration:            protobufDuration(c.Listener.MaxStreamDuration),
			MaxHeadersCount:              optionalUint32(c.Listener.MaxRequestHeadersCount),
			HeadersWithUnderscoresAction: core.HttpProtocolOptions_REJECT_REQUEST,
		},
		RequestTimeout:               protobufDuration(c.Listener.RequestTimeout),
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

func generateFilterChains(c resolvedConfig) ([]*listener.FilterChain, error) {
	var filterChains []*listener.FilterChain
	var httpHosts []indexedVirtualHost
	for i, server := range c.servers {
		host, err := serverVirtualHost(c, i, server)
		if err != nil {
			return nil, err
		}
		indexedHost := indexedVirtualHost{serverIndex: i, host: host}
		if server.TLSConfig == nil {
			httpHosts = append(httpHosts, indexedHost)
			continue
		}
		chain, err := toHTTPFilterChain(c, []indexedVirtualHost{indexedHost})
		if err != nil {
			return nil, fmt.Errorf("servers[%d]: %w", i, err)
		}
		chain.FilterChainMatch = &listener.FilterChainMatch{TransportProtocol: "tls", ServerNames: []string{server.Hostname}}
		chain.TransportSocket, err = serverTLSTransportSocket(i, server.mtls.MTLS, server.usesMTLS() && requiresClientCertificate(*server.Server))
		if err != nil {
			return nil, fmt.Errorf("servers[%d] downstream TLS context: %w", i, err)
		}
		chain.TransportSocketConnectTimeout = protobufDuration(c.Listener.TLSHandshakeTimeout)
		filterChains = append(filterChains, chain)
	}
	if len(httpHosts) > 0 {
		chain, err := toHTTPFilterChain(c, httpHosts)
		if err != nil {
			return nil, err
		}
		if hasHTTPSConfig(c.Config) {
			chain.FilterChainMatch = &listener.FilterChainMatch{TransportProtocol: "raw_buffer"}
		}
		filterChains = append([]*listener.FilterChain{chain}, filterChains...)
	}
	return filterChains, nil
}
