package config

import (
	"strings"
	"testing"
	"time"

	yaml "go.yaml.in/yaml/v3"
)

func TestLoadRejectsInvalidYAML(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "unknown field", input: "version: 1\nunknown: true\n", want: "field unknown not found"},
		{name: "top-level processing", input: "version: 1\nprocessing: []\n", want: "field processing not found"},
		{name: "top-level admission control", input: "version: 1\nadmission_control: {}\n", want: "field admission_control not found"},
		{name: "duplicate field", input: "version: 1\nversion: 1\n", want: "already defined"},
		{name: "multiple documents", input: "version: 1\n---\nversion: 1\n", want: "expected exactly one YAML document"},
		{name: "invalid syntax", input: "version: [\n", want: "did not find expected node content"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Load(strings.NewReader(test.input)); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Load error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestValidateRejectsInvalidConfiguration(t *testing.T) {
	exampleConfig := readFixture(t, "public-routing/config.yaml")
	tests := []struct {
		name string
		want string
		edit func(*Config)
	}{
		{name: "unsupported version", want: "version must", edit: func(c *Config) { c.Version = 2 }},
		{name: "invalid listener port", want: "listener.port", edit: func(c *Config) { c.Listener.Port = new(uint32(65536)) }},
		{name: "no APIs", want: "at least one API", edit: func(c *Config) { c.APIs = nil }},
		{name: "invalid API name", want: "apis[0].name", edit: func(c *Config) { c.APIs[0].Name = "Metrics" }},
		{name: "duplicate API name", want: "duplicate API name", edit: func(c *Config) { c.APIs = append(c.APIs, c.APIs[0]) }},
		{name: "duplicate route", want: "servers[0].apis: duplicate API route", edit: func(c *Config) {
			api := c.APIs[0]
			api.Name = "metrics-copy"
			c.APIs = append(c.APIs, api)
			c.Servers[0].APIs = append(c.Servers[0].APIs, api.Name)
		}},
		{name: "no routes", want: "apis[0].routes", edit: func(c *Config) { c.APIs[0].Routes = nil }},
		{name: "lowercase method", want: "apis[0].routes[0].methods", edit: func(c *Config) { c.APIs[0].Routes[0].Methods = []string{"post"} }},
		{name: "invalid method", want: "apis[0].routes[0].methods", edit: func(c *Config) { c.APIs[0].Routes[0].Methods = []string{"POST /metrics"} }},
		{name: "relative path", want: "apis[0].routes[0].path.exact", edit: func(c *Config) { c.APIs[0].Routes[0].Path.Exact = "metrics/write" }},
		{name: "path traversal", want: "apis[0].routes[0].path.exact", edit: func(c *Config) { c.APIs[0].Routes[0].Path.Exact = "/metrics/../admin" }},
		{name: "path query", want: "apis[0].routes[0].path.exact", edit: func(c *Config) { c.APIs[0].Routes[0].Path.Exact = "/metrics?tenant=one" }},
		{name: "invalid upstream", want: "apis[0].upstream.address", edit: func(c *Config) { c.APIs[0].Upstream.Address = "bad_host" }},
		{name: "invalid port", want: "apis[0].upstream.port", edit: func(c *Config) { c.APIs[0].Upstream.Port = 65536 }},
		{name: "invalid rewrite path", want: "apis[0].routes[0].rewrite.path", edit: func(c *Config) { c.APIs[0].Routes[0].Rewrite.Path = "/api/%invalid" }},
		{name: "empty image", want: "kubernetes.image", edit: func(c *Config) { c.Kubernetes.Image = " " }},
		{name: "negative replicas", want: "kubernetes.replicas", edit: func(c *Config) { c.Kubernetes.Replicas = new(int32(-1)) }},
		{name: "invalid service port", want: "kubernetes.service_port", edit: func(c *Config) { c.Kubernetes.ServicePort = new(int32(65536)) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := loadTestConfig(t, exampleConfig, "valid baseline")
			test.edit(&config)
			if err := config.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validation error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestTuningValidationAndOptionalZeros(t *testing.T) {
	tests := []struct {
		field string
		edit  func(*Config)
	}{
		{"listener.port", func(c *Config) { c.Listener.Port = new(uint32(0)) }},
		{"listener.port", func(c *Config) { c.Listener.Port = new(uint32(9901)) }},
		{"listener.max_request_headers_kb", func(c *Config) { c.Listener.MaxRequestHeadersKB = new(uint32(8193)) }},
		{"listener.max_request_headers_count", func(c *Config) { c.Listener.MaxRequestHeadersCount = new(uint32(0)) }},
		{"listener.request_headers_timeout", func(c *Config) { c.Listener.RequestTimeout = duration(time.Second) }},
		{"listener.http2.max_concurrent_streams", func(c *Config) { c.Listener.HTTP2 = &HTTP2Options{MaxConcurrentStreams: new(uint32(0))} }},
		{"listener.http2.initial_stream_window_size", func(c *Config) { c.Listener.HTTP2 = &HTTP2Options{InitialStreamWindowSize: new(uint32(65534))} }},
		{"listener.http2.initial_connection_window_size", func(c *Config) {
			c.Listener.HTTP2 = &HTTP2Options{InitialConnectionWindowSize: new(uint32(2147483648))}
		}},
		{"apis[0].upstream.connect_timeout", func(c *Config) { c.APIs[0].Upstream.ConnectTimeout = duration(0) }},
		{"apis[0].upstream.per_connection_buffer_limit_bytes", func(c *Config) { c.APIs[0].Upstream.PerConnectionBufferLimitBytes = new(uint32(0)) }},
		{"apis[0].upstream.http_protocol", func(c *Config) { c.APIs[0].Upstream.HTTPProtocol = "auto" }},
		{"apis[0].upstream.http2", func(c *Config) { c.APIs[0].Upstream.HTTP2 = &HTTP2Options{} }},
		{"apis[0].upstream.tls_config.server_name", func(c *Config) { c.APIs[0].Upstream.TLSConfig = &UpstreamTLS{ServerName: "*.example.test"} }},
		{"apis[0].timeouts.idle_timeout", func(c *Config) { c.APIs[0].Timeouts = &RouteTimeouts{IdleTimeout: duration(0)} }},
		{"apis[0].routes[0].timeouts.response_timeout", func(c *Config) {
			c.APIs[0].Routes[0].Timeouts = &RouteTimeouts{ResponseTimeout: duration(31 * time.Second)}
		}},
		{"kubernetes.service_port", func(c *Config) { c.Kubernetes.ServicePort = new(int32(0)) }},
	}
	for _, tt := range tests {
		c := loadConfigCase(t, "public-routing")
		tt.edit(&c)
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), tt.field) {
			t.Errorf("%s: %v", tt.field, err)
		}
	}
	input := readFixture(t, "public-routing/config.yaml")
	for _, value := range []string{"null", "8080"} {
		c, err := Load(strings.NewReader(input + "\nlistener: {port: " + value + ", http2: {}}\n"))
		if err != nil || *c.Listener.Port != 8080 || c.Listener.HTTP2 == nil {
			t.Fatalf("null/empty options: %v", err)
		}
	}
}

func TestConfigurationDefaults(t *testing.T) {
	c := loadTestConfig(t, readFixture(t, "defaults.yaml"), "defaults fixture")
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
	assertConfigDiff(t, "listener defaults", wantListener, c.Listener)
	if c.Overload != nil {
		t.Fatal("overload must be opt-in")
	}
	wantBreakers := &CircuitBreakerConfig{MaxConnections: new(uint32(1024)), MaxPendingRequests: new(uint32(1024)), MaxRequests: new(uint32(1024)), MaxRetries: new(uint32(0))}
	for _, a := range c.Authenticators {
		if a.JWT == nil {
			continue
		}
		want := JWKSConfig{URI: a.JWT.JWKS.URI, DNSLookupFamily: jwksDNSLookupFamilyV4Only, CacheDuration: duration(5 * time.Minute), FetchTimeout: duration(5 * time.Second), ConnectTimeout: duration(5 * time.Second), CircuitBreakers: wantBreakers}
		assertConfigDiff(t, a.Name+" JWKS defaults", want, a.JWT.JWKS)
	}
	for _, api := range c.APIs {
		want := Upstream{Address: api.Upstream.Address, Port: api.Upstream.Port, ConnectTimeout: duration(5 * time.Second), PerConnectionBufferLimitBytes: new(uint32(1048576)), HTTPProtocol: "http1"}
		assertConfigDiff(t, api.Name+" upstream defaults", want, api.Upstream)
		assertConfigDiff(t, api.Name+" circuit breaker defaults", wantBreakers, api.CircuitBreakers)
		if api.Timeouts != nil {
			t.Fatalf("default fixture API %s must inherit API timeouts", api.Name)
		}
		for _, r := range api.Routes {
			if r.Timeouts != nil {
				t.Fatal("default fixture must inherit route timeouts")
			}
		}
	}
	wantKubernetesResources := KubernetesResourceRequirements{
		Requests: map[string]string{"cpu": "50m", "memory": "64Mi"},
		Limits:   map[string]string{"cpu": "1", "memory": "256Mi"},
	}
	type kubernetesDefaults struct {
		Name             string
		Namespace        string
		Replicas         *int32
		ServicePort      *int32
		HTTPSServicePort *int32
		EnvoyConcurrency *uint32
		Resources        KubernetesResourceRequirements
	}
	gotKubernetes := kubernetesDefaults{
		Name:             c.Kubernetes.Name,
		Namespace:        c.Kubernetes.Namespace,
		Replicas:         c.Kubernetes.Replicas,
		ServicePort:      c.Kubernetes.ServicePort,
		HTTPSServicePort: c.Kubernetes.HTTPSServicePort,
		EnvoyConcurrency: c.Kubernetes.EnvoyConcurrency,
		Resources:        c.Kubernetes.Resources,
	}
	wantKubernetes := kubernetesDefaults{
		Name: "auth-gateway", Namespace: "observability",
		Replicas: new(int32(2)), ServicePort: new(int32(80)), HTTPSServicePort: new(int32(443)),
		Resources: wantKubernetesResources,
	}
	assertConfigDiff(t, "Kubernetes defaults", wantKubernetes, gotKubernetes)
	wantTLS := &ServerTLS{Secret: "gateway-tls", Certificate: "/etc/gateway-tls/tls.crt", PrivateKey: "/etc/gateway-tls/tls.key"}
	assertConfigDiff(t, "server TLS defaults", wantTLS, c.Servers[0].TLSConfig)
	resolved, err := resolveConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	wantTimers := &RouteTimeouts{ResponseTimeout: duration(30 * time.Second), IdleTimeout: duration(60 * time.Second), MaxStreamDuration: duration(30 * time.Second)}
	for _, api := range resolved.APIs {
		for _, r := range api.Routes {
			assertConfigDiff(t, api.Name+" effective timeouts", wantTimers, r.Timeouts)
		}
	}
	if _, err := GenerateKubernetes(c); err != nil {
		t.Fatalf("generate defaulted resources: %v", err)
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
		c := loadAuthValidationFixture(t)
		defaulted := c.withDefaults()
		defaulted.Authenticators[0].JWT.Audiences[0] = "changed"
		defaulted.Authenticators[0].Attributes["tenant_id"].ClaimPath[0] = "changed"
		keySource := defaulted.Authenticators[2].Attributes["tenant_id"]
		*keySource.Credential = false
		headerSource := defaulted.Authenticators[2].Attributes["requested_tenant"]
		*headerSource.Header = "changed"
		defaulted.AuthorizationPolicies[0].Grants[0].APIs[0] = "changed"
		defaulted.AuthorizationPolicies[0].Grants[0].Attributes["tenant_id"][0] = "changed"
		defaulted.Servers[0].Authentication.AnyOf[0] = "changed"
		defaulted.Servers[0].Authorization.AnyOf[0] = "changed"
		defaulted.APIs[0].Routes[0].Processing.RequestHeaders[0].Name = "changed"

		if c.Authenticators[0].JWT.Audiences[0] == "changed" ||
			c.Authenticators[0].Attributes["tenant_id"].ClaimPath[0] == "changed" ||
			!*c.Authenticators[2].Attributes["tenant_id"].Credential ||
			*c.Authenticators[2].Attributes["requested_tenant"].Header == "changed" ||
			c.AuthorizationPolicies[0].Grants[0].APIs[0] == "changed" ||
			c.AuthorizationPolicies[0].Grants[0].Attributes["tenant_id"][0] == "changed" ||
			c.Servers[0].Authentication.AnyOf[0] == "changed" ||
			c.Servers[0].Authorization.AnyOf[0] == "changed" ||
			c.APIs[0].Routes[0].Processing.RequestHeaders[0].Name == "changed" {
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
		defaulted := c.withDefaults()
		if len(defaulted.Kubernetes.Resources.Limits) != 0 {
			t.Fatal("resource defaults merged into supplied maps")
		}
		*defaulted.Overload.HeapShrinkThreshold = 0.2
		*defaulted.Kubernetes.EnvoyConcurrency = 3
		defaulted.Kubernetes.Resources.Limits["memory"] = "512Mi"
		if *c.Overload.HeapShrinkThreshold != 0.7 || *c.Kubernetes.EnvoyConcurrency != 2 || len(c.Kubernetes.Resources.Limits) != 0 {
			t.Fatal("defaulting aliases resource maps or optional pointers")
		}
	})
}

func TestPublicOperationsPreserveConfiguration(t *testing.T) {
	c := loadAuthValidationFixture(t)
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
