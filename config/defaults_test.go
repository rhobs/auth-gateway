package config

import (
	"reflect"
	"testing"
	"time"
)

// The auth example leaves default-valued settings commented out.
func TestAuthExampleAppliesAllDefaults(t *testing.T) {
	c := loadAuthExample(t)
	if c.Node != (EnvoyNode{ID: "auth-gateway", Cluster: "auth-gateway"}) {
		t.Fatalf("node defaults = %#v", c.Node)
	}
	wantListener := Listener{
		Port: new(uint32(8080)), PerConnectionBufferLimitBytes: new(uint32(1048576)),
		MaxRequestHeadersKB: new(uint32(32)), MaxRequestHeadersCount: new(uint32(100)),
		RequestHeadersTimeout: duration(5 * time.Second), RequestTimeout: duration(30 * time.Second),
		ConnectionIdleTimeout: duration(60 * time.Second), StreamIdleTimeout: duration(60 * time.Second),
		MaxStreamDuration: duration(30 * time.Second), StreamFlushTimeout: duration(5 * time.Second),
		TLSHandshakeTimeout: duration(5 * time.Second),
	}
	if !reflect.DeepEqual(c.Listener, wantListener) {
		t.Fatalf("listener defaults = %#v, want %#v", c.Listener, wantListener)
	}
	if c.Overload != nil {
		t.Fatal("overload must be opt-in")
	}
	wantBreakers := &CircuitBreakerConfig{MaxConnections: new(uint32(1024)), MaxPendingRequests: new(uint32(1024)), MaxRequests: new(uint32(1024)), MaxRetries: new(uint32(0))}
	for _, a := range c.Authenticators {
		want := JWKSConfig{URI: a.JWT.JWKS.URI, CacheDuration: duration(5 * time.Minute), FetchTimeout: duration(5 * time.Second), ConnectTimeout: duration(5 * time.Second), CircuitBreakers: wantBreakers}
		if !reflect.DeepEqual(a.JWT.JWKS, want) {
			t.Fatalf("%s JWKS defaults = %#v, want %#v", a.Name, a.JWT.JWKS, want)
		}
	}
	for _, api := range c.APIs {
		want := Upstream{Address: api.Upstream.Address, Port: api.Upstream.Port, ConnectTimeout: duration(5 * time.Second), PerConnectionBufferLimitBytes: new(uint32(1048576)), HTTPProtocol: "http1"}
		if !reflect.DeepEqual(api.Upstream, want) {
			t.Fatalf("%s upstream defaults = %#v, want %#v", api.Name, api.Upstream, want)
		}
		if !reflect.DeepEqual(api.CircuitBreakers, wantBreakers) {
			t.Fatalf("%s circuit breaker defaults = %#v", api.Name, api.CircuitBreakers)
		}
		if api.Timeouts != nil {
			t.Fatalf("example %s must inherit default API timeouts", api.Name)
		}
		for _, r := range api.Routes {
			if r.Timeouts != nil {
				t.Fatal("example must inherit default route timeouts")
			}
		}
	}
	wantKubernetes := &Kubernetes{
		Name: "auth-gateway", Namespace: "observability", Image: c.Kubernetes.Image,
		OTelCollectorImage: "otel/opentelemetry-collector-contrib:0.135.0", Replicas: new(int32(2)), ServicePort: new(int32(80)), HTTPSServicePort: new(int32(443)),
		Resources: KubernetesResourceRequirements{Requests: map[string]string{"cpu": "50m", "memory": "64Mi"}, Limits: map[string]string{"cpu": "1", "memory": "256Mi"}},
		Metrics:   KubernetesMetrics{ScrapeInterval: duration(30 * time.Second), ScrapeTimeout: duration(10 * time.Second), Resources: KubernetesResourceRequirements{Requests: map[string]string{"cpu": "20m", "memory": "64Mi"}, Limits: map[string]string{"memory": "256Mi"}}},
	}
	if !reflect.DeepEqual(c.Kubernetes, wantKubernetes) {
		t.Fatalf("Kubernetes defaults = %#v, want %#v", c.Kubernetes, wantKubernetes)
	}
	wantTLS := &ServerTLS{Secret: "write-gateway-tls", Certificate: "/etc/write-gateway-tls/tls.crt", PrivateKey: "/etc/write-gateway-tls/tls.key"}
	if !reflect.DeepEqual(c.Servers[1].TLSConfig, wantTLS) {
		t.Fatalf("server TLS defaults = %#v", c.Servers[1].TLSConfig)
	}
	resolved, err := resolveConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	wantTimers := &RouteTimeouts{ResponseTimeout: duration(30 * time.Second), IdleTimeout: duration(60 * time.Second), MaxStreamDuration: duration(30 * time.Second)}
	for _, api := range resolved.APIs {
		for _, r := range api.Routes {
			if !reflect.DeepEqual(r.Timeouts, wantTimers) {
				t.Fatalf("%s effective timeouts = %#v", api.Name, r.Timeouts)
			}
		}
	}
	if _, err := GenerateKubernetes(c); err != nil {
		t.Fatalf("generate defaulted example: %v", err)
	}
}

func TestOptInOverloadDefaults(t *testing.T) {
	c := loadAuthExample(t)
	c.Overload = &OverloadConfig{MaxHeapBytes: 201326592, MaxDownstreamConnections: 2048}
	resolved, err := resolveConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	want := &OverloadConfig{MaxHeapBytes: 201326592, MaxDownstreamConnections: 2048, HeapShrinkThreshold: new(0.90), RequestRejectThreshold: new(0.95)}
	if !reflect.DeepEqual(resolved.Overload, want) || c.Overload.HeapShrinkThreshold != nil || c.Overload.RequestRejectThreshold != nil {
		t.Fatalf("overload defaults = %#v, input = %#v", resolved.Overload, c.Overload)
	}
}
