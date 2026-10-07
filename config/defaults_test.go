package config

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
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
		if a.JWT == nil {
			continue
		}
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

func TestServerTLSDefaults(t *testing.T) {
	tests := []struct {
		name        string
		tls         ServerTLS
		certificate string
		privateKey  string
	}{
		{name: "file only", certificate: defaultServerTLSCertificate, privateKey: defaultServerTLSPrivateKey},
		{name: "named Secret", tls: ServerTLS{Secret: "other-tls"}, certificate: "/etc/other-tls/tls.crt", privateKey: "/etc/other-tls/tls.key"},
		{name: "explicit paths", tls: ServerTLS{Secret: "other-tls", Certificate: "/certs/server.pem", PrivateKey: "/certs/key.pem"}, certificate: "/certs/server.pem", privateKey: "/certs/key.pem"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := loadConfigCase(t, "public-routing")
			c.Kubernetes = nil
			c.Servers[0].TLSConfig = &test.tls
			defaulted := c.withDefaults()
			if err := defaulted.Validate(); err != nil {
				t.Fatal(err)
			}
			got := defaulted.Servers[0].TLSConfig
			if got.Certificate != test.certificate || got.PrivateKey != test.privateKey {
				t.Fatalf("TLS paths = %s, %s, want %s, %s", got.Certificate, got.PrivateKey, test.certificate, test.privateKey)
			}
		})
	}
}

func TestDefaultsCloneInputs(t *testing.T) {
	t.Run("route slices and pointers", func(t *testing.T) {
		c := loadConfigCase(t, "public-routing")
		methods := c.APIs[0].Routes[0].Methods[0]
		c.Kubernetes.Replicas = nil
		defaulted := c.withDefaults()
		defaulted.APIs[0].Routes[0].Methods[0] = "changed"
		*defaulted.Kubernetes.Replicas = 1
		if c.APIs[0].Routes[0].Methods[0] != methods || c.Kubernetes.Replicas != nil {
			t.Fatal("defaulting aliases route slices or pointers")
		}
	})

	t.Run("authentication maps and slices", func(t *testing.T) {
		c := loadAuthExample(t)
		defaulted := c.withDefaults()
		defaulted.Authenticators[0].JWT.Audiences[0] = "changed"
		defaulted.Authenticators[0].Attributes["tenant_id"].ClaimPath[0] = "changed"
		keySource := defaulted.Authenticators[2].Attributes["tenant_id"]
		*keySource.Credential = false
		headerSource := defaulted.Authenticators[2].Attributes["requested_tenant"]
		*headerSource.Header = "changed"
		defaulted.Processing[0].Attributes["tenant_id"].Mappings["client-123"] = "changed"
		defaulted.AuthorizationPolicies[0].Grants[0].APIs[0] = "changed"
		defaulted.AuthorizationPolicies[0].Grants[0].Attributes["tenant_id"][0] = "changed"
		defaulted.Servers[0].Authentication.AnyOf[0] = "changed"
		defaulted.Servers[0].Authorization.AnyOf[0] = "changed"
		defaulted.APIs[0].Routes[0].Processing.RequestHeaders[0].Name = "changed"
		defaulted.APIs[0].Metrics.Labels["tenant"] = "writer_id"
		defaulted.RequestMetrics.Name = "changed_requests_total"

		if c.Authenticators[0].JWT.Audiences[0] == "changed" ||
			c.Authenticators[0].Attributes["tenant_id"].ClaimPath[0] == "changed" ||
			!*c.Authenticators[2].Attributes["tenant_id"].Credential ||
			*c.Authenticators[2].Attributes["requested_tenant"].Header == "changed" ||
			c.Processing[0].Attributes["tenant_id"].Mappings["client-123"] == "changed" ||
			c.AuthorizationPolicies[0].Grants[0].APIs[0] == "changed" ||
			c.AuthorizationPolicies[0].Grants[0].Attributes["tenant_id"][0] == "changed" ||
			c.Servers[0].Authentication.AnyOf[0] == "changed" ||
			c.Servers[0].Authorization.AnyOf[0] == "changed" ||
			c.APIs[0].Routes[0].Processing.RequestHeaders[0].Name == "changed" ||
			c.APIs[0].Metrics.Labels["tenant"] == "writer_id" ||
			c.RequestMetrics.Name == "changed_requests_total" {
			t.Fatal("defaulting aliases authentication configuration")
		}
	})

	t.Run("JWKS references and timeout pointers", func(t *testing.T) {
		c := loadConfigCase(t, "jwt-auth-multiple-issuers")
		c.Authenticators[0].JWT.JWKS.TrustedCA = &TrustedCA{ConfigMap: &CAConfigMap{Name: "issuer-ca", Key: "roots.pem"}}
		c.Authenticators[0].JWT.JWKS.CacheDuration = duration(15 * time.Second)
		c.Authenticators[0].JWT.JWKS.CircuitBreakers = &CircuitBreakerConfig{MaxConnections: new(uint32(3))}
		defaulted := c.withDefaults()
		defaulted.Authenticators[0].JWT.JWKS.TrustedCA.ConfigMap.Key = "changed"
		*defaulted.Authenticators[0].JWT.JWKS.CacheDuration = Duration(time.Minute)
		*defaulted.Authenticators[0].JWT.JWKS.CircuitBreakers.MaxConnections = 99
		jwks := c.Authenticators[0].JWT.JWKS
		if jwks.TrustedCA.ConfigMap.Key != "roots.pem" || *jwks.CacheDuration != Duration(15*time.Second) || *jwks.CircuitBreakers.MaxConnections != 3 {
			t.Fatal("defaulting aliases JWKS references or timeout pointers")
		}
	})

	t.Run("server fields", func(t *testing.T) {
		c := loadConfigCase(t, "public-routing")
		c.Servers[0].TLSConfig = &ServerTLS{Secret: "server-tls"}
		defaulted := c.withDefaults()
		if c.Servers[0].TLSConfig.Certificate != "" || c.Servers[0].TLSConfig.PrivateKey != "" || c.Kubernetes.HTTPSServicePort != nil {
			t.Fatal("defaulting changed the input TLS configuration")
		}
		if *defaulted.Kubernetes.HTTPSServicePort != defaultHTTPSServicePort {
			t.Fatal("HTTPS Service port was not defaulted")
		}
		defaulted.Servers[0].APIs[0] = "other"
		defaulted.Servers[0].TLSConfig.Secret = "other-tls"
		if c.Servers[0].APIs[0] != "metrics" || c.Servers[0].TLSConfig.Secret != "server-tls" {
			t.Fatal("defaulting aliases server fields")
		}
	})

	t.Run("resource maps and optional pointers", func(t *testing.T) {
		c := loadConfigCase(t, "public-routing")
		c.Overload = &OverloadConfig{MaxHeapBytes: 128 << 20, MaxDownstreamConnections: 1, HeapShrinkThreshold: new(0.7)}
		c.Kubernetes.EnvoyConcurrency = new(uint32(2))
		c.Kubernetes.Resources.Limits = map[string]string{}
		c.Kubernetes.Metrics.Resources = KubernetesResourceRequirements{Requests: map[string]string{"cpu": "5m"}, Limits: map[string]string{}}
		defaulted := c.withDefaults()
		if len(defaulted.Kubernetes.Resources.Limits) != 0 || len(defaulted.Kubernetes.Metrics.Resources.Limits) != 0 || !reflect.DeepEqual(defaulted.Kubernetes.Metrics.Resources.Requests, map[string]string{"cpu": "5m"}) {
			t.Fatal("resource defaults merged into supplied maps")
		}
		*defaulted.Overload.HeapShrinkThreshold = 0.2
		*defaulted.Kubernetes.EnvoyConcurrency = 3
		*defaulted.Kubernetes.Metrics.ScrapeInterval = Duration(time.Second)
		defaulted.Kubernetes.Metrics.Resources.Requests["cpu"] = "10m"
		defaulted.Kubernetes.Resources.Limits["memory"] = "512Mi"
		if *c.Overload.HeapShrinkThreshold != 0.7 || *c.Kubernetes.EnvoyConcurrency != 2 || *c.Kubernetes.Metrics.ScrapeInterval != Duration(30*time.Second) || c.Kubernetes.Metrics.Resources.Requests["cpu"] != "5m" || len(c.Kubernetes.Resources.Limits) != 0 {
			t.Fatal("defaulting aliases resource maps or optional pointers")
		}
	})
}

func TestPublicOperationsPreserveConfiguration(t *testing.T) {
	c := loadAuthExample(t)
	before, err := yaml.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(c); err != nil {
		t.Fatal(err)
	}
	resources, err := GenerateKubernetes(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resources.YAML(); err != nil {
		t.Fatal(err)
	}
	after, err := yaml.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("validation or generation mutated the caller's configuration")
	}
}

func TestKubernetesYAMLOptions(t *testing.T) {
	defaults := []struct {
		name string
		file string
	}{
		{name: "metrics omitted", file: "public-routing/config.yaml"},
		{name: "metrics null", file: "kubernetes-options/metrics-null.yaml"},
		{name: "metrics empty", file: "kubernetes-options/metrics-empty.yaml"},
		{name: "nested nulls", file: "kubernetes-options/nested-null.yaml"},
	}
	for _, test := range defaults {
		t.Run(test.name, func(t *testing.T) {
			c := loadTestConfig(t, readFixture(t, test.file), test.name)
			metrics := c.Kubernetes.Metrics
			if c.Overload != nil || c.Kubernetes.EnvoyConcurrency != nil || *metrics.ScrapeInterval != Duration(30*time.Second) || *metrics.ScrapeTimeout != Duration(10*time.Second) || !reflect.DeepEqual(metrics.Resources.Requests, map[string]string{"cpu": "20m", "memory": "64Mi"}) || !reflect.DeepEqual(metrics.Resources.Limits, map[string]string{"memory": "256Mi"}) {
				t.Fatalf("defaulted Kubernetes settings = %#v", c.Kubernetes)
			}
		})
	}

	c := loadTestConfig(t, readFixture(t, "kubernetes-options/empty-resource-maps.yaml"), "empty resource maps")
	if c.Kubernetes.Resources.Requests == nil || c.Kubernetes.Resources.Limits == nil ||
		len(c.Kubernetes.Resources.Requests) != 0 || len(c.Kubernetes.Resources.Limits) != 0 ||
		c.Kubernetes.Metrics.Resources.Limits == nil || len(c.Kubernetes.Metrics.Resources.Limits) != 0 ||
		!reflect.DeepEqual(c.Kubernetes.Metrics.Resources.Requests, map[string]string{"cpu": "5m"}) {
		t.Fatal("supplied empty resource maps were merged with defaults")
	}
	if _, err := Load(strings.NewReader(readFixture(t, "kubernetes-options/overload-empty.yaml"))); err == nil || !strings.Contains(err.Error(), "overload.max_heap_bytes") {
		t.Fatalf("empty overload accepted: %v", err)
	}
}
