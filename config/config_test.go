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
	config, err := Load(strings.NewReader(readFixture(t, "example.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	if config.Listener.Address != defaultListenerAddr || config.Listener.Port != defaultListenerPort {
		t.Fatalf("listener defaults = %s:%d", config.Listener.Address, config.Listener.Port)
	}
	if got := strings.Join(config.APIs[0].Routes[0].Methods, ","); got != "POST" {
		t.Fatalf("route methods = %q, want POST", got)
	}
	if got := config.APIs[0].Routes[0].Rewrite.Path; got != "/api/v1/receive" {
		t.Fatalf("rewrite path = %q", got)
	}
	if config.Kubernetes.ServicePort != defaultServicePort ||
		config.Kubernetes.Replicas == nil || *config.Kubernetes.Replicas != 2 ||
		config.Kubernetes.OTelCollectorImage != defaultOTelCollectorImage {
		t.Fatalf("Kubernetes defaults = %#v", config.Kubernetes)
	}
}

func TestLoadRejectsMissingRouteMethods(t *testing.T) {
	input := strings.Replace(readFixture(t, "route-list.yaml"), "      - methods: [GET, POST]\n", "      -\n", 1)
	if _, err := Load(strings.NewReader(input)); err == nil {
		t.Fatal("Load accepted a route with no methods")
	}
}

func TestLoadRejectsInvalidYAML(t *testing.T) {
	exampleConfig := readFixture(t, "example.yaml")
	tests := map[string]string{
		"unknown field":      exampleConfig + "unknown: true\n",
		"duplicate field":    strings.Replace(exampleConfig, "version: 1", "version: 1\nversion: 1", 1),
		"multiple documents": exampleConfig + "---\nversion: 1\n",
		"invalid syntax":     "version: [\n",
		"legacy API method":  strings.Replace(exampleConfig, "    routes:\n", "    method: POST\n    routes:\n", 1),
		"legacy API path":    strings.Replace(exampleConfig, "    routes:\n", "    path: /metrics/api/v1/receive\n    routes:\n", 1),
		"legacy upstream path": strings.Replace(
			exampleConfig,
			"      port: 19291\n",
			"      port: 19291\n      path: /api/v1/receive\n",
			1,
		),
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(strings.NewReader(input)); err == nil {
				t.Fatal("Load accepted invalid YAML")
			}
		})
	}
	if _, err := Load(nil); err == nil {
		t.Fatal("Load accepted a nil reader")
	}
}

func TestValidateRejectsInvalidConfiguration(t *testing.T) {
	exampleConfig := readFixture(t, "example.yaml")
	negativeReplicas := int32(-1)
	tests := map[string]func(*Config){
		"unsupported version": func(c *Config) { c.Version = 2 },
		"invalid listener":    func(c *Config) { c.Listener.Address = "gateway.invalid" },
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
		"invalid Kube name": func(c *Config) { c.Kubernetes.Name = "bad_name" },
		"long Kube name":    func(c *Config) { c.Kubernetes.Name = strings.Repeat("a", 57) },
		"invalid namespace": func(c *Config) { c.Kubernetes.Namespace = "Bad" },
		"empty image":       func(c *Config) { c.Kubernetes.Image = " " },
		"negative replicas": func(c *Config) { c.Kubernetes.Replicas = &negativeReplicas },
		"invalid service port": func(c *Config) {
			c.Kubernetes.ServicePort = 65536
		},
		"non-wildcard Kube listener": func(c *Config) {
			c.Listener.Address = "127.0.0.1"
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
