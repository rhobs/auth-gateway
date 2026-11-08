package envoy

import (
	"fmt"

	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	configuration "github.com/rhobs/auth-gateway/pkg/config"
)

func generateFilterChains(c configuration.ResolvedConfig) ([]*listener.FilterChain, error) {
	var filterChains []*listener.FilterChain
	var httpHosts []indexedVirtualHost
	for i, server := range c.ResolvedServers {
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
		chain.TransportSocket, err = serverTLSTransportSocket(i, server.Mtls.MTLS, server.UsesMTLS() && configuration.RequiresClientCertificate(*server.Server))
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
		if configuration.HasHTTPSConfig(c.Config) {
			chain.FilterChainMatch = &listener.FilterChainMatch{TransportProtocol: "raw_buffer"}
		}
		filterChains = append([]*listener.FilterChain{chain}, filterChains...)
	}
	return filterChains, nil
}
