package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readFixture(t testing.TB, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %q: %v", name, err)
	}
	return string(data)
}

func TestLoadAppliesDefaults(t *testing.T) {
	config, err := Load(strings.NewReader(readFixture(t, "tls.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	if config.Node.ID != defaultNodeID || config.Node.Cluster != defaultNodeCluster {
		t.Fatalf("node defaults = %#v", config.Node)
	}
	if config.Listener.Port != defaultListenerPort {
		t.Fatalf("listener port default = %d, want %d", config.Listener.Port, defaultListenerPort)
	}

	breakers := config.APIs[0].CircuitBreakers
	if breakers == nil {
		t.Fatal("circuit breaker defaults are missing")
	}
	if breakers.MaxConnections == nil || *breakers.MaxConnections != defaultCircuitBreakerMaxConnections ||
		breakers.MaxPendingRequests == nil || *breakers.MaxPendingRequests != defaultCircuitBreakerMaxPendingRequests ||
		breakers.MaxRequests == nil || *breakers.MaxRequests != defaultCircuitBreakerMaxRequests ||
		breakers.MaxRetries == nil || *breakers.MaxRetries != defaultCircuitBreakerMaxRetries {
		t.Fatalf("circuit breaker defaults = %#v", breakers)
	}

	tls := config.Servers[1].TLSConfig
	if tls == nil || tls.Certificate != defaultServerTLSCertificate || tls.PrivateKey != defaultServerTLSPrivateKey {
		t.Fatalf("TLS defaults = %#v", tls)
	}

	if config.Kubernetes.Replicas == nil || *config.Kubernetes.Replicas != defaultKubernetesReplicas ||
		config.Kubernetes.ServicePort != defaultServicePort ||
		config.Kubernetes.HTTPSServicePort != defaultHTTPSServicePort ||
		config.Kubernetes.OTelCollectorImage != defaultOTelCollectorImage {
		t.Fatalf("Kubernetes defaults = %#v", config.Kubernetes)
	}
	requests := config.Kubernetes.Resources.Requests
	if len(requests) != 2 || requests["cpu"] != defaultKubernetesCPURequest ||
		requests["memory"] != defaultKubernetesMemoryRequest {
		t.Fatalf("Kubernetes resource request defaults = %#v", requests)
	}
	limits := config.Kubernetes.Resources.Limits
	if len(limits) != 2 || limits["cpu"] != defaultKubernetesCPULimit ||
		limits["memory"] != defaultKubernetesMemoryLimit {
		t.Fatalf("Kubernetes resource limit defaults = %#v", limits)
	}
}

func TestLoadRejectsMissingRouteMethods(t *testing.T) {
	input := `version: 1
servers:
  - hostname: auth.example.com
    apis: [metrics]
apis:
  - name: metrics
    upstream:
      address: thanos-receive
      port: 19291
    routes:
      - path:
          exact: /metrics/api/v1/receive
`
	if _, err := Load(strings.NewReader(input)); err == nil || !strings.Contains(err.Error(), ".methods") {
		t.Fatalf("Load error = %v, want a missing route methods error", err)
	}
}

func TestLoadRejectsInvalidYAML(t *testing.T) {
	tests := map[string]string{
		"unknown field":      "unknown: true\n",
		"duplicate field":    "version: 1\nversion: 1\n",
		"multiple documents": "version: 1\n---\nversion: 1\n",
		"invalid syntax":     "version: [\n",
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(strings.NewReader(input)); err == nil {
				t.Fatal("Load accepted invalid YAML")
			}
		})
	}
}

func TestValidateRejectsInvalidConfiguration(t *testing.T) {
	exampleConfig := readFixture(t, "example.yaml")
	tests := map[string]func(*Config){
		"unsupported version": func(c *Config) { c.Version = 2 },
		"invalid listener port": func(c *Config) {
			c.Listener.Port = 65536
		},
		"no APIs":          func(c *Config) { c.APIs = nil },
		"invalid API name": func(c *Config) { c.APIs[0].Name = "Metrics" },
		"duplicate API name": func(c *Config) {
			c.APIs = append(c.APIs, c.APIs[0])
		},
		"duplicate route": func(c *Config) {
			api := c.APIs[0]
			api.Name = "metrics-copy"
			c.APIs = append(c.APIs, api)
			c.Servers[0].APIs = append(c.Servers[0].APIs, api.Name)
		},
		"no routes":        func(c *Config) { c.APIs[0].Routes = nil },
		"lowercase method": func(c *Config) { c.APIs[0].Routes[0].Methods = []string{"post"} },
		"invalid method":   func(c *Config) { c.APIs[0].Routes[0].Methods = []string{"POST /metrics"} },
		"relative path": func(c *Config) {
			c.APIs[0].Routes[0].Path.Exact = "metrics/write"
		},
		"path traversal": func(c *Config) {
			c.APIs[0].Routes[0].Path.Exact = "/metrics/../admin"
		},
		"path query": func(c *Config) {
			c.APIs[0].Routes[0].Path.Exact = "/metrics?tenant=one"
		},
		"invalid upstream": func(c *Config) { c.APIs[0].Upstream.Address = "bad_host" },
		"invalid port":     func(c *Config) { c.APIs[0].Upstream.Port = 65536 },
		"invalid rewrite path": func(c *Config) {
			c.APIs[0].Routes[0].Rewrite.Path = "/api/%invalid"
		},
		"empty image":       func(c *Config) { c.Kubernetes.Image = " " },
		"negative replicas": func(c *Config) { c.Kubernetes.Replicas = new(int32(-1)) },
		"invalid service port": func(c *Config) {
			c.Kubernetes.ServicePort = 65536
		},
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			config, err := Load(strings.NewReader(exampleConfig))
			if err != nil {
				t.Fatal(err)
			}
			change(&config)
			if err := config.Validate(); err == nil {
				t.Fatal("Validate accepted invalid configuration")
			}
		})
	}
}

func TestValidateRejectsInvalidRouteConfiguration(t *testing.T) {
	routeListConfig := readFixture(t, "route-list.yaml")
	tests := map[string]func(*Config){
		"multiple path matchers": func(c *Config) {
			c.APIs[0].Routes[0].Path.Prefix = "/metrics/"
		},
		"invalid path regex": func(c *Config) {
			c.APIs[0].Routes[0].Path.Regex = "["
		},
		"duplicate method": func(c *Config) {
			c.APIs[0].Routes[0].Methods = []string{"GET", "GET"}
		},
		"missing path matcher": func(c *Config) {
			c.APIs[0].Routes[0].Path = PathMatch{}
		},
		"multiple rewrite types": func(c *Config) {
			c.APIs[0].Routes[0].Rewrite = &PathRewrite{Path: "/query", Prefix: "/api/"}
		},
		"duplicate route": func(c *Config) {
			c.APIs[0].Routes = append(c.APIs[0].Routes, c.APIs[0].Routes[0])
		},
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			config, err := Load(strings.NewReader(routeListConfig))
			if err != nil {
				t.Fatal(err)
			}
			change(&config)
			if err := config.Validate(); err == nil {
				t.Fatal("Validate accepted invalid route configuration")
			}
		})
	}
}

func TestValidateServers(t *testing.T) {
	newConfig := func() Config {
		config, err := Load(strings.NewReader(readFixture(t, "example.yaml")))
		if err != nil {
			t.Fatal(err)
		}
		config.Kubernetes = nil
		config.Servers = []Server{
			{Hostname: "auth.example.com", APIs: []string{"metrics"}},
			{Hostname: "tls.example.com", TLSConfig: &ServerTLS{}, APIs: []string{"metrics"}},
		}
		return config
	}

	if err := newConfig().Validate(); err != nil {
		t.Fatalf("valid HTTP and HTTPS servers rejected: %v", err)
	}
	tests := map[string]func(*Config){
		"no servers":        func(c *Config) { c.Servers = nil },
		"empty servers":     func(c *Config) { c.Servers = []Server{} },
		"missing hostname":  func(c *Config) { c.Servers[0].Hostname = "" },
		"invalid hostname":  func(c *Config) { c.Servers[0].Hostname = "https://auth.example.com" },
		"wildcard hostname": func(c *Config) { c.Servers[0].Hostname = "*.example.com" },
		"IP hostname":       func(c *Config) { c.Servers[0].Hostname = "127.0.0.1" },
		"duplicate host within one protocol": func(c *Config) {
			c.Servers = append(c.Servers, c.Servers[0])
		},
		"host cannot use both protocols": func(c *Config) {
			c.Servers[1].Hostname = c.Servers[0].Hostname
		},
		"unknown API":       func(c *Config) { c.Servers[0].APIs = []string{"unknown"} },
		"duplicate binding": func(c *Config) { c.Servers[0].APIs = []string{"metrics", "metrics"} },
		"certificate paths share a directory": func(c *Config) {
			c.Servers[1].TLSConfig.Certificate = "/etc/certs/tls.crt"
			c.Servers[1].TLSConfig.PrivateKey = "/etc/keys/tls.key"
		},
		"relative certificate path": func(c *Config) {
			c.Servers[1].TLSConfig.Certificate = "tls.crt"
		},
		"identical certificate and key": func(c *Config) {
			c.Servers[1].TLSConfig.Certificate = "/etc/certs/tls.crt"
			c.Servers[1].TLSConfig.PrivateKey = "/etc/certs/tls.crt"
		},
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			config := newConfig()
			change(&config)
			if err := config.Validate(); err == nil {
				t.Fatal("Validate accepted an invalid server configuration")
			}
		})
	}
}

func TestRootExampleGeneratesKubernetes(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "config.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	config, err := Load(strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateKubernetes(config); err != nil {
		t.Fatal(err)
	}
}

func TestDefaultsDoNotMutateInput(t *testing.T) {
	config, err := Load(strings.NewReader(readFixture(t, "example.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	config.APIs[0].Routes[0].Methods = nil
	config.Kubernetes.Replicas = nil
	defaulted := config.withDefaults()
	if config.APIs[0].Routes[0].Methods != nil || config.Kubernetes.Replicas != nil {
		t.Fatal("applying defaults mutated the caller's configuration")
	}
	if len(defaulted.APIs[0].Routes[0].Methods) != 0 {
		t.Fatal("withDefaults supplied a method for a route without any")
	}
	if defaulted.Kubernetes.Replicas == nil || *defaulted.Kubernetes.Replicas != 2 {
		t.Fatal("Kubernetes defaults were not applied to the returned configuration")
	}
}
