package config

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
)

const envoyTraceClusterName = "otel-traces"

func jwksClusterName(name string) string { return "jwks-" + name }

func jwksClusters(c effectiveConfig) ([]*cluster.Cluster, error) {
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
			Name: name, ConnectTimeout: authenticator.JWT.JWKS.ConnectTimeout.protobuf(),
			CircuitBreakers:      authenticator.JWT.JWKS.CircuitBreakers.toCircuitBreakers(),
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

func apiClusterName(apiName string) string { return "api-" + apiName }

func apiClusters(apis []API) ([]*cluster.Cluster, error) {
	clusters := make([]*cluster.Cluster, 0, len(apis))
	for _, api := range apis {
		name := apiClusterName(api.Name)
		options, err := upstreamHTTPProtocolOptions(api.Upstream)
		if err != nil {
			return nil, fmt.Errorf("API %q upstream protocol: %w", api.Name, err)
		}
		upstream := &cluster.Cluster{
			Name:                          name,
			ConnectTimeout:                api.Upstream.ConnectTimeout.protobuf(),
			ClusterDiscoveryType:          &cluster.Cluster_Type{Type: cluster.Cluster_STRICT_DNS},
			PerConnectionBufferLimitBytes: optionalUint32(api.Upstream.PerConnectionBufferLimitBytes),
			TypedExtensionProtocolOptions: map[string]*anypb.Any{upstreamHTTPProtocolOptionsTypeURL: options},
			CircuitBreakers:               api.CircuitBreakers.toCircuitBreakers(),
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
	protocolOptions, err := upstreamHTTPProtocolOptions(Upstream{HTTPProtocol: http2Protocol})
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
