package config

import (
	"fmt"
	"time"

	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
)

const (
	DefaultCircuitBreakerMaxConnections     = 1024
	DefaultCircuitBreakerMaxPendingRequests = 1024
	DefaultCircuitBreakerMaxRequests        = 1024
	DefaultCircuitBreakerMaxRetries         = 0
	Http1Protocol                           = "http1"
	Http2Protocol                           = "http2"
)

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
		MaxConnections:     defaultValue(c.MaxConnections, DefaultCircuitBreakerMaxConnections),
		MaxPendingRequests: defaultValue(c.MaxPendingRequests, DefaultCircuitBreakerMaxPendingRequests),
		MaxRequests:        defaultValue(c.MaxRequests, DefaultCircuitBreakerMaxRequests),
		MaxRetries:         defaultValue(c.MaxRetries, DefaultCircuitBreakerMaxRetries),
	}
}

func withDefaultsUpstream(u gatewayapi.Upstream) gatewayapi.Upstream {
	u.ConnectTimeout = withDefaultDuration(u.ConnectTimeout, 5*time.Second)
	u.PerConnectionBufferLimitBytes = defaultValue(u.PerConnectionBufferLimitBytes, 1048576)
	if u.HTTPProtocol == "" {
		u.HTTPProtocol = Http1Protocol
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
	if u.HTTPProtocol != Http1Protocol && u.HTTPProtocol != Http2Protocol {
		return fmt.Errorf("%s.http_protocol must be http1 or http2", name)
	}
	if u.HTTP2 != nil && u.HTTPProtocol != Http2Protocol {
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
