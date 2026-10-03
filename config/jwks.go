package config

import (
	"fmt"
	"time"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// JWKSConfig controls on-demand key fetching for one JWT authenticator.
type JWKSConfig struct {
	URI             string                `yaml:"uri"`
	CacheDuration   *Duration             `yaml:"cache_duration,omitempty"`
	FetchTimeout    *Duration             `yaml:"fetch_timeout,omitempty"`
	ConnectTimeout  *Duration             `yaml:"connect_timeout,omitempty"`
	TrustedCA       *TrustedCA            `yaml:"trusted_ca,omitempty"`
	CircuitBreakers *CircuitBreakerConfig `yaml:"circuit_breakers,omitempty"`
}

func (j JWKSConfig) withDefaults() JWKSConfig {
	j.CacheDuration = defaultDuration(j.CacheDuration, 5*time.Minute)
	j.FetchTimeout = defaultDuration(j.FetchTimeout, 5*time.Second)
	j.ConnectTimeout = defaultDuration(j.ConnectTimeout, 5*time.Second)
	j.TrustedCA = cloneTrustedCA(j.TrustedCA)
	j.CircuitBreakers = defaultCircuitBreakers(j.CircuitBreakers)
	return j
}

func (j JWKSConfig) validate(name string, kubernetes bool) error {
	for _, setting := range []struct {
		name  string
		value *Duration
	}{
		{"cache_duration", j.CacheDuration}, {"fetch_timeout", j.FetchTimeout}, {"connect_timeout", j.ConnectTimeout},
	} {
		if err := validateDuration(name+"."+setting.name, setting.value, false); err != nil {
			return err
		}
	}
	if *j.ConnectTimeout > *j.FetchTimeout {
		return fmt.Errorf("%s.connect_timeout (%s) must not exceed %s.fetch_timeout (%s)", name, j.ConnectTimeout, name, j.FetchTimeout)
	}
	return validateTrustedCA(name+".trusted_ca", j.TrustedCA, kubernetes)
}

func defaultCircuitBreakers(c *CircuitBreakerConfig) *CircuitBreakerConfig {
	if c == nil {
		c = &CircuitBreakerConfig{}
	}
	return &CircuitBreakerConfig{
		MaxConnections:     defaultUint32(c.MaxConnections, defaultCircuitBreakerMaxConnections),
		MaxPendingRequests: defaultUint32(c.MaxPendingRequests, defaultCircuitBreakerMaxPendingRequests),
		MaxRequests:        defaultUint32(c.MaxRequests, defaultCircuitBreakerMaxRequests),
		MaxRetries:         defaultUint32(c.MaxRetries, defaultCircuitBreakerMaxRetries),
	}
}

func envoyCircuitBreakers(c *CircuitBreakerConfig) *cluster.CircuitBreakers {
	return &cluster.CircuitBreakers{Thresholds: []*cluster.CircuitBreakers_Thresholds{{
		Priority:           core.RoutingPriority_DEFAULT,
		MaxConnections:     wrapperspb.UInt32(*c.MaxConnections),
		MaxPendingRequests: wrapperspb.UInt32(*c.MaxPendingRequests),
		MaxRequests:        wrapperspb.UInt32(*c.MaxRequests),
		MaxRetries:         wrapperspb.UInt32(*c.MaxRetries),
	}}}
}
