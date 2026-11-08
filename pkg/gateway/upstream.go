package gateway

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	upstreamhttp "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	defaultCircuitBreakerMaxConnections     = 1024
	defaultCircuitBreakerMaxPendingRequests = 1024
	defaultCircuitBreakerMaxRequests        = 1024
	defaultCircuitBreakerMaxRetries         = 0
	http1Protocol                           = "http1"
	http2Protocol                           = "http2"
	envoyTraceClusterName                   = "otel-traces"
	upstreamHTTPProtocolOptionsTypeURL      = "envoy.extensions.upstreams.http.v3.HttpProtocolOptions"
)

func validHost(value string) bool {
	return net.ParseIP(value) != nil || validDNSHost(value)
}

func cloneHTTP2Options(h gatewayapi.HTTP2Options) gatewayapi.HTTP2Options {
	h.MaxConcurrentStreams = clonePointer(h.MaxConcurrentStreams)
	h.InitialStreamWindowSize = clonePointer(h.InitialStreamWindowSize)
	h.InitialConnectionWindowSize = clonePointer(h.InitialConnectionWindowSize)
	return h
}

func validateHTTP2Options(h gatewayapi.HTTP2Options, name string) error {
	for _, value := range []struct {
		Name  string
		Value *uint32
		Min   uint32
	}{
		{"max_concurrent_streams", h.MaxConcurrentStreams, 1},
		{"initial_stream_window_size", h.InitialStreamWindowSize, 65535},
		{"initial_connection_window_size", h.InitialConnectionWindowSize, 65535},
	} {
		if value.Value != nil && (*value.Value < value.Min || *value.Value > 2147483647) {
			return fmt.Errorf("%s.%s must be between %d and 2147483647", name, value.Name, value.Min)
		}
	}
	return nil
}

func jwksClusterName(name string) string { return "jwks-" + name }

func cloneCircuitBreakerConfig(c *gatewayapi.CircuitBreakerConfig) gatewayapi.CircuitBreakerConfig {
	cloned := *c
	cloned.MaxConnections = clonePointer(c.MaxConnections)
	cloned.MaxPendingRequests = clonePointer(c.MaxPendingRequests)
	cloned.MaxRequests = clonePointer(c.MaxRequests)
	cloned.MaxRetries = clonePointer(c.MaxRetries)
	return cloned
}

func withDefaultsCircuitBreakerConfig(c *gatewayapi.CircuitBreakerConfig) *gatewayapi.CircuitBreakerConfig {
	if c == nil {
		c = &gatewayapi.CircuitBreakerConfig{}
	}
	return &gatewayapi.CircuitBreakerConfig{
		MaxConnections:     defaultValue(c.MaxConnections, defaultCircuitBreakerMaxConnections),
		MaxPendingRequests: defaultValue(c.MaxPendingRequests, defaultCircuitBreakerMaxPendingRequests),
		MaxRequests:        defaultValue(c.MaxRequests, defaultCircuitBreakerMaxRequests),
		MaxRetries:         defaultValue(c.MaxRetries, defaultCircuitBreakerMaxRetries),
	}
}

func withDefaultsUpstream(u gatewayapi.Upstream) gatewayapi.Upstream {
	u.ConnectTimeout = withDefaultDuration(u.ConnectTimeout, 5*time.Second)
	u.PerConnectionBufferLimitBytes = defaultValue(u.PerConnectionBufferLimitBytes, 1048576)
	if u.HTTPProtocol == "" {
		u.HTTPProtocol = http1Protocol
	}
	return u
}

func cloneUpstream(u gatewayapi.Upstream) gatewayapi.Upstream {
	u.ConnectTimeout = clonePointer(u.ConnectTimeout)
	u.PerConnectionBufferLimitBytes = clonePointer(u.PerConnectionBufferLimitBytes)
	u.HTTP2 = cloneConfigPointer(u.HTTP2, cloneHTTP2Options)
	u.TLSConfig = cloneConfigPointer(u.TLSConfig, cloneUpstreamTLS)
	return u
}

func cloneUpstreamTLS(t gatewayapi.UpstreamTLS) gatewayapi.UpstreamTLS {
	t.TrustedCA = cloneConfigPointer(t.TrustedCA, cloneTrustedCA)
	return t
}

func validateUpstream(u gatewayapi.Upstream, name string, kubernetes bool) error {
	if err := validateDuration(name+".connect_timeout", u.ConnectTimeout, false); err != nil {
		return err
	}
	if *u.PerConnectionBufferLimitBytes == 0 {
		return fmt.Errorf("%s.per_connection_buffer_limit_bytes must be positive", name)
	}
	if u.HTTPProtocol != http1Protocol && u.HTTPProtocol != http2Protocol {
		return fmt.Errorf("%s.http_protocol must be http1 or http2", name)
	}
	if u.HTTP2 != nil && u.HTTPProtocol != http2Protocol {
		return fmt.Errorf("%s.http2 requires http_protocol: http2", name)
	}
	if u.HTTP2 != nil {
		if err := validateHTTP2Options(*u.HTTP2, name+".http2"); err != nil {
			return err
		}
	}
	if u.TLSConfig != nil {
		if u.TLSConfig.ServerName != "" && !validDNSHost(u.TLSConfig.ServerName) {
			return fmt.Errorf("%s.tls_config.server_name must be an exact DNS hostname", name)
		}
		return validateTrustedCA(name+".tls_config.trusted_ca", u.TLSConfig.TrustedCA, kubernetes)
	}
	return nil
}

func apiClusterName(apiName string) string { return "api-" + apiName }

func jwksClusters(c resolvedConfig) ([]*cluster.Cluster, error) {
	var clusters []*cluster.Cluster
	for _, authenticator := range c.Authenticators {
		if authenticator.JWT == nil || !c.authenticatorUsed(authenticator.Name) {
			continue
		}
		parsed, err := url.Parse(authenticator.JWT.JWKS.URI)
		if err != nil {
			return nil, fmt.Errorf("authenticators.%s.jwt.jwks.uri: %w", authenticator.Name, err)
		}
		port := uint32(443)
		if parsed.Port() != "" {
			value, err := strconv.ParseUint(parsed.Port(), 10, 32)
			if err != nil {
				return nil, fmt.Errorf("authenticators.%s.jwt.jwks.uri port: %w", authenticator.Name, err)
			}
			port = uint32(value)
		}
		name := jwksClusterName(authenticator.Name)
		tlsSocket, err := verifiedTLS(strings.ToLower(parsed.Hostname()), authenticator.JWT.JWKS.TrustedCA, nil)
		if err != nil {
			return nil, fmt.Errorf("authenticators.%s JWKS TLS: %w", authenticator.Name, err)
		}
		clusters = append(clusters, &cluster.Cluster{
			Name: name, ConnectTimeout: protobufDuration(authenticator.JWT.JWKS.ConnectTimeout),
			CircuitBreakers:      circuitBreakers(authenticator.JWT.JWKS.CircuitBreakers),
			DnsLookupFamily:      jwksDNSLookupFamilyToEnvoy(authenticator.JWT.JWKS.DNSLookupFamily),
			ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_STRICT_DNS},
			LoadAssignment:       &endpoint.ClusterLoadAssignment{ClusterName: name, Endpoints: []*endpoint.LocalityLbEndpoints{{LbEndpoints: []*endpoint.LbEndpoint{{HostIdentifier: &endpoint.LbEndpoint_Endpoint{Endpoint: &endpoint.Endpoint{Address: socket(parsed.Hostname(), port)}}}}}}},
			TransportSocket:      tlsSocket,
		})
	}
	return clusters, nil
}

func jwksDNSLookupFamilyToEnvoy(value string) cluster.Cluster_DnsLookupFamily {
	switch value {
	case jwksDNSLookupFamilyAuto:
		return cluster.Cluster_AUTO
	case jwksDNSLookupFamilyV4Only, "":
		return cluster.Cluster_V4_ONLY
	case jwksDNSLookupFamilyV6Only:
		return cluster.Cluster_V6_ONLY
	case jwksDNSLookupFamilyV4Preferred:
		return cluster.Cluster_V4_PREFERRED
	case jwksDNSLookupFamilyAll:
		return cluster.Cluster_ALL
	default:
		return cluster.Cluster_V4_ONLY
	}
}

func apiClusters(apis []gatewayapi.API) ([]*cluster.Cluster, error) {
	clusters := make([]*cluster.Cluster, 0, len(apis))
	for _, api := range apis {
		name := apiClusterName(api.Name)
		options, err := upstreamHTTPProtocolOptions(api.Upstream)
		if err != nil {
			return nil, fmt.Errorf("API %q upstream protocol: %w", api.Name, err)
		}
		upstream := &cluster.Cluster{
			Name:                          name,
			ConnectTimeout:                protobufDuration(api.Upstream.ConnectTimeout),
			ClusterDiscoveryType:          &cluster.Cluster_Type{Type: cluster.Cluster_STRICT_DNS},
			PerConnectionBufferLimitBytes: optionalUint32(api.Upstream.PerConnectionBufferLimitBytes),
			TypedExtensionProtocolOptions: map[string]*anypb.Any{upstreamHTTPProtocolOptionsTypeURL: options},
			CircuitBreakers:               circuitBreakers(api.CircuitBreakers),
			LoadAssignment: &endpoint.ClusterLoadAssignment{
				ClusterName: name,
				Endpoints: []*endpoint.LocalityLbEndpoints{{
					LbEndpoints: []*endpoint.LbEndpoint{{
						HostIdentifier: &endpoint.LbEndpoint_Endpoint{Endpoint: &endpoint.Endpoint{
							Address: socket(api.Upstream.Address, api.Upstream.Port),
						}},
					}},
				}},
			},
		}
		if tls := api.Upstream.TLSConfig; tls != nil {
			identity := tls.ServerName
			if identity == "" {
				identity = api.Upstream.Address
			}
			alpn := []string{googleHTTP11ALPN}
			if api.Upstream.HTTPProtocol == http2Protocol {
				alpn = []string{"h2"}
			}
			upstream.TransportSocket, err = verifiedTLS(identity, tls.TrustedCA, alpn)
			if err != nil {
				return nil, fmt.Errorf("API %q upstream TLS: %w", api.Name, err)
			}
		}
		clusters = append(clusters, upstream)
	}
	return clusters, nil
}

func otelTraceCluster() (*cluster.Cluster, error) {
	protocolOptions, err := upstreamHTTPProtocolOptions(gatewayapi.Upstream{HTTPProtocol: http2Protocol})
	if err != nil {
		return nil, fmt.Errorf("encode OTLP upstream HTTP/2 options: %w", err)
	}
	return &cluster.Cluster{
		Name:                          envoyTraceClusterName,
		ConnectTimeout:                durationpb.New(5 * time.Second),
		ClusterDiscoveryType:          &cluster.Cluster_Type{Type: cluster.Cluster_STATIC},
		TypedExtensionProtocolOptions: map[string]*anypb.Any{upstreamHTTPProtocolOptionsTypeURL: protocolOptions},
		LoadAssignment: &endpoint.ClusterLoadAssignment{
			ClusterName: envoyTraceClusterName,
			Endpoints: []*endpoint.LocalityLbEndpoints{{
				LbEndpoints: []*endpoint.LbEndpoint{{
					HostIdentifier: &endpoint.LbEndpoint_Endpoint{Endpoint: &endpoint.Endpoint{
						Address: socket(defaultOTelTraceReceiverAddress, defaultOTelTracePort),
					}},
				}},
			}},
		},
	}, nil
}

func circuitBreakers(c *gatewayapi.CircuitBreakerConfig) *cluster.CircuitBreakers {
	return &cluster.CircuitBreakers{Thresholds: []*cluster.CircuitBreakers_Thresholds{{
		Priority:           core.RoutingPriority_DEFAULT,
		MaxConnections:     wrapperspb.UInt32(*c.MaxConnections),
		MaxPendingRequests: wrapperspb.UInt32(*c.MaxPendingRequests),
		MaxRequests:        wrapperspb.UInt32(*c.MaxRequests),
		MaxRetries:         wrapperspb.UInt32(*c.MaxRetries),
	}}}
}

func envoyHTTP2Options(h gatewayapi.HTTP2Options) *core.Http2ProtocolOptions {
	return &core.Http2ProtocolOptions{
		MaxConcurrentStreams:        optionalUint32(h.MaxConcurrentStreams),
		InitialStreamWindowSize:     optionalUint32(h.InitialStreamWindowSize),
		InitialConnectionWindowSize: optionalUint32(h.InitialConnectionWindowSize),
	}
}

func upstreamHTTPProtocolOptions(upstream gatewayapi.Upstream) (*anypb.Any, error) {
	protocol := &upstreamhttp.HttpProtocolOptions_ExplicitHttpConfig{ProtocolConfig: &upstreamhttp.HttpProtocolOptions_ExplicitHttpConfig_HttpProtocolOptions{HttpProtocolOptions: &core.Http1ProtocolOptions{}}}
	if upstream.HTTPProtocol == http2Protocol {
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
