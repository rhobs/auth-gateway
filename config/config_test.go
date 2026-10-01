package config

import (
	"strings"
	"testing"
)

const exampleConfig = `version: 1
apis:
  - name: metrics
    path: /metrics/api/v1/receive
    upstream:
      address: thanos-receive
      port: 19291
      path: /api/v1/receive
kubernetes:
  name: auth-gateway
  namespace: observability
  image: envoyproxy/envoy:v1.39.1
`

func TestLoadAppliesDefaults(t *testing.T) {
	config, err := Load(strings.NewReader(exampleConfig))
	if err != nil {
		t.Fatal(err)
	}
	if config.Listener.Address != defaultListenerAddr || config.Listener.Port != defaultListenerPort {
		t.Fatalf("listener defaults = %s:%d", config.Listener.Address, config.Listener.Port)
	}
	if config.APIs[0].Method != "POST" {
		t.Fatalf("API method default = %q, want POST", config.APIs[0].Method)
	}
	if got := config.APIs[0].Upstream.Path; got != "/api/v1/receive" {
		t.Fatalf("upstream path = %q", got)
	}
	if config.Kubernetes.ServicePort != defaultServicePort || config.Kubernetes.Replicas == nil || *config.Kubernetes.Replicas != 2 {
		t.Fatalf("Kubernetes defaults = %#v", config.Kubernetes)
	}

	withoutUpstreamPath := strings.Replace(exampleConfig, "      path: /api/v1/receive\n", "", 1)
	config, err = Load(strings.NewReader(withoutUpstreamPath))
	if err != nil {
		t.Fatal(err)
	}
	if got := config.APIs[0].Upstream.Path; got != config.APIs[0].Path {
		t.Fatalf("default upstream path = %q, want %q", got, config.APIs[0].Path)
	}
}

func TestLoadRejectsInvalidYAML(t *testing.T) {
	tests := map[string]string{
		"unknown field":      exampleConfig + "unknown: true\n",
		"duplicate field":    strings.Replace(exampleConfig, "version: 1", "version: 1\nversion: 1", 1),
		"multiple documents": exampleConfig + "---\nversion: 1\n",
		"invalid syntax":     "version: [\n",
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
			c.APIs[1].Path = "/another/path"
		},
		"duplicate route": func(c *Config) {
			c.APIs = append(c.APIs, c.APIs[0])
			c.APIs[1].Name = "metrics-copy"
		},
		"lowercase method": func(c *Config) { c.APIs[0].Method = "post" },
		"invalid method":   func(c *Config) { c.APIs[0].Method = "POST /metrics" },
		"relative path":    func(c *Config) { c.APIs[0].Path = "metrics/write" },
		"path traversal":   func(c *Config) { c.APIs[0].Path = "/metrics/../admin" },
		"path query":       func(c *Config) { c.APIs[0].Path = "/metrics?tenant=one" },
		"invalid upstream": func(c *Config) { c.APIs[0].Upstream.Address = "bad_host" },
		"invalid port":     func(c *Config) { c.APIs[0].Upstream.Port = 65536 },
		"invalid upstream path": func(c *Config) {
			c.APIs[0].Upstream.Path = "/api/%invalid"
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

func TestDefaultsDoNotMutateInput(t *testing.T) {
	config, err := Load(strings.NewReader(exampleConfig))
	if err != nil {
		t.Fatal(err)
	}
	config.APIs[0].Method = ""
	config.APIs[0].Upstream.Path = ""
	config.Kubernetes.Replicas = nil
	defaulted := config.withDefaults()
	if config.APIs[0].Method != "" || config.APIs[0].Upstream.Path != "" || config.Kubernetes.Replicas != nil {
		t.Fatal("applying defaults mutated the caller's configuration")
	}
	if defaulted.APIs[0].Method != "POST" || defaulted.APIs[0].Upstream.Path != defaulted.APIs[0].Path ||
		defaulted.Kubernetes.Replicas == nil || *defaulted.Kubernetes.Replicas != 2 {
		t.Fatal("defaults were not applied to the returned configuration")
	}
}
