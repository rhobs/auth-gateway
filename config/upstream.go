package config

import (
	"fmt"
	"time"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	defaultCircuitBreakerMaxConnections     = 1024
	defaultCircuitBreakerMaxPendingRequests = 1024
	defaultCircuitBreakerMaxRequests        = 1024
	defaultCircuitBreakerMaxRetries         = 0
	http1Protocol                           = "http1"
	http2Protocol                           = "http2"
)

// CircuitBreakerConfig describes Envoy circuit breaker thresholds for an upstream cluster.
type CircuitBreakerConfig struct {
	MaxConnections     *uint32 `yaml:"max_connections,omitempty"`
	MaxPendingRequests *uint32 `yaml:"max_pending_requests,omitempty"`
	MaxRequests        *uint32 `yaml:"max_requests,omitempty"`
	MaxRetries         *uint32 `yaml:"max_retries,omitempty"`
}

// Upstream describes the service that receives routed requests.
type Upstream struct {
	Address                       string        `yaml:"address"`
	Port                          uint32        `yaml:"port"`
	ConnectTimeout                *Duration     `yaml:"connect_timeout,omitempty"`
	PerConnectionBufferLimitBytes *uint32       `yaml:"per_connection_buffer_limit_bytes,omitempty"`
	HTTPProtocol                  string        `yaml:"http_protocol,omitempty"`
	HTTP2                         *HTTP2Options `yaml:"http2,omitempty"`
	TLSConfig                     *UpstreamTLS  `yaml:"tls_config,omitempty"`
}

// UpstreamTLS enables server-authenticated TLS with a DNS or IP verification identity.
type UpstreamTLS struct {
	ServerName string     `yaml:"server_name,omitempty"`
	TrustedCA  *TrustedCA `yaml:"trusted_ca,omitempty"`
}

func (c *CircuitBreakerConfig) clone() CircuitBreakerConfig {
	cloned := *c
	cloned.MaxConnections = clonePointer(c.MaxConnections)
	cloned.MaxPendingRequests = clonePointer(c.MaxPendingRequests)
	cloned.MaxRequests = clonePointer(c.MaxRequests)
	cloned.MaxRetries = clonePointer(c.MaxRetries)
	return cloned
}

func (c *CircuitBreakerConfig) withDefaults() *CircuitBreakerConfig {
	if c == nil {
		c = &CircuitBreakerConfig{}
	}
	return &CircuitBreakerConfig{
		MaxConnections:     defaultValue(c.MaxConnections, defaultCircuitBreakerMaxConnections),
		MaxPendingRequests: defaultValue(c.MaxPendingRequests, defaultCircuitBreakerMaxPendingRequests),
		MaxRequests:        defaultValue(c.MaxRequests, defaultCircuitBreakerMaxRequests),
		MaxRetries:         defaultValue(c.MaxRetries, defaultCircuitBreakerMaxRetries),
	}
}

func (u Upstream) withDefaults() Upstream {
	u.ConnectTimeout = u.ConnectTimeout.withDefault(5 * time.Second)
	u.PerConnectionBufferLimitBytes = defaultValue(u.PerConnectionBufferLimitBytes, 1048576)
	if u.HTTPProtocol == "" {
		u.HTTPProtocol = http1Protocol
	}
	return u
}

func (u Upstream) clone() Upstream {
	u.ConnectTimeout = clonePointer(u.ConnectTimeout)
	u.PerConnectionBufferLimitBytes = clonePointer(u.PerConnectionBufferLimitBytes)
	u.HTTP2 = cloneConfigPointer(u.HTTP2)
	u.TLSConfig = cloneConfigPointer(u.TLSConfig)
	return u
}

func (t UpstreamTLS) clone() UpstreamTLS {
	t.TrustedCA = cloneConfigPointer(t.TrustedCA)
	return t
}

func (u Upstream) validate(name string, kubernetes bool) error {
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
		if err := u.HTTP2.validate(name + ".http2"); err != nil {
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

func (c *CircuitBreakerConfig) toCircuitBreakers() *cluster.CircuitBreakers {
	return &cluster.CircuitBreakers{Thresholds: []*cluster.CircuitBreakers_Thresholds{{
		Priority:           core.RoutingPriority_DEFAULT,
		MaxConnections:     wrapperspb.UInt32(*c.MaxConnections),
		MaxPendingRequests: wrapperspb.UInt32(*c.MaxPendingRequests),
		MaxRequests:        wrapperspb.UInt32(*c.MaxRequests),
		MaxRetries:         wrapperspb.UInt32(*c.MaxRetries),
	}}}
}
