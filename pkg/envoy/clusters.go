package envoy

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	configuration "github.com/rhobs/auth-gateway/pkg/config"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const envoyTraceClusterName = "otel-traces"

func apiClusterName(apiName string) string { return "api-" + apiName }

func jwksClusters(c configuration.ResolvedConfig) ([]*cluster.Cluster, error) {
	var clusters []*cluster.Cluster
	for _, authenticator := range c.Authenticators {
		if authenticator.JWT == nil || !c.AuthenticatorUsed(authenticator.Name) {
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
		name := configuration.JwksClusterName(authenticator.Name)
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
	case configuration.JwksDNSLookupFamilyAuto:
		return cluster.Cluster_AUTO
	case configuration.JwksDNSLookupFamilyV4Only, "":
		return cluster.Cluster_V4_ONLY
	case configuration.JwksDNSLookupFamilyV6Only:
		return cluster.Cluster_V6_ONLY
	case configuration.JwksDNSLookupFamilyV4Preferred:
		return cluster.Cluster_V4_PREFERRED
	case configuration.JwksDNSLookupFamilyAll:
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
			alpn := []string{configuration.GoogleHTTP11ALPN}
			if api.Upstream.HTTPProtocol == configuration.Http2Protocol {
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
	protocolOptions, err := upstreamHTTPProtocolOptions(gatewayapi.Upstream{HTTPProtocol: configuration.Http2Protocol})
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
						Address: socket(configuration.DefaultOTelTraceReceiverAddress, configuration.DefaultOTelTracePort),
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
