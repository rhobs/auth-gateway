package config

import (
	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

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

func (c *CircuitBreakerConfig) toCircuitBreakers() *cluster.CircuitBreakers {
	return &cluster.CircuitBreakers{Thresholds: []*cluster.CircuitBreakers_Thresholds{{
		Priority:           core.RoutingPriority_DEFAULT,
		MaxConnections:     wrapperspb.UInt32(*c.MaxConnections),
		MaxPendingRequests: wrapperspb.UInt32(*c.MaxPendingRequests),
		MaxRequests:        wrapperspb.UInt32(*c.MaxRequests),
		MaxRetries:         wrapperspb.UInt32(*c.MaxRetries),
	}}}
}
