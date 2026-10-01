// Package config provides the consumer-facing configuration API for auth-gateway.
package config

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"
	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	configVersion       = 1
	defaultListenerAddr = "0.0.0.0"
	defaultListenerPort = 8080
	defaultServicePort  = 80
)

var (
	apiNamePattern = regexp.MustCompile("^[a-z][a-z0-9-]{0,52}$")
	dnsNamePattern = regexp.MustCompile("^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$")
)

// Config describes listener, API routes, upstreams, and optional Kubernetes output.
type Config struct {
	Version    int         `yaml:"version"`
	Listener   Listener    `yaml:"listener"`
	APIs       []API       `yaml:"apis"`
	Kubernetes *Kubernetes `yaml:"kubernetes,omitempty"`
}

// Listener describes the HTTP address used by Envoy.
type Listener struct {
	Address string `yaml:"address,omitempty"`
	Port    uint32 `yaml:"port,omitempty"`
}

// API describes one named write route and its upstream.
type API struct {
	Name     string   `yaml:"name"`
	Method   string   `yaml:"method,omitempty"`
	Path     string   `yaml:"path"`
	Upstream Upstream `yaml:"upstream"`
}

// Upstream describes the service and path that receive a routed request.
type Upstream struct {
	Address string `yaml:"address"`
	Port    uint32 `yaml:"port"`
	Path    string `yaml:"path,omitempty"`
}

// Kubernetes contains the settings needed to generate a Deployment and Service.
type Kubernetes struct {
	Name        string `yaml:"name"`
	Namespace   string `yaml:"namespace"`
	Image       string `yaml:"image"`
	Replicas    *int32 `yaml:"replicas,omitempty"`
	ServicePort int32  `yaml:"service_port,omitempty"`
}

// Load decodes one strict YAML document and applies defaults before validation.
func Load(r io.Reader) (Config, error) {
	if r == nil {
		return Config{}, fmt.Errorf("read gateway configuration: input is nil")
	}

	var c Config
	decoder := yaml.NewDecoder(r)
	decoder.KnownFields(true)
	if err := decoder.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("read gateway configuration: %w", err)
	}

	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return Config{}, fmt.Errorf("read gateway configuration: expected exactly one YAML document")
	} else if err != io.EOF {
		return Config{}, fmt.Errorf("read gateway configuration: %w", err)
	}

	c = c.withDefaults()
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// Validate checks the public configuration contract.
func (c Config) Validate() error {
	c = c.withDefaults()
	if c.Version != configVersion {
		return fmt.Errorf("version must be %d", configVersion)
	}
	if net.ParseIP(c.Listener.Address) == nil {
		return fmt.Errorf("listener.address must be an IP address")
	}
	if c.Listener.Port == 0 || c.Listener.Port > 65535 {
		return fmt.Errorf("listener.port must be between 1 and 65535")
	}
	if len(c.APIs) == 0 {
		return fmt.Errorf("at least one API must be configured")
	}

	names := make(map[string]struct{}, len(c.APIs))
	routes := make(map[string]struct{}, len(c.APIs))
	for i, api := range c.APIs {
		name := fmt.Sprintf("apis[%d]", i)
		if !apiNamePattern.MatchString(api.Name) {
			return fmt.Errorf("%s.name must start with a lowercase letter and contain only lowercase letters, numbers, or hyphens", name)
		}
		if _, exists := names[api.Name]; exists {
			return fmt.Errorf("duplicate API name %q", api.Name)
		}
		names[api.Name] = struct{}{}

		if !validMethod(api.Method) {
			return fmt.Errorf("%s.method must be a valid uppercase HTTP method", name)
		}
		if err := validatePath(name+".path", api.Path); err != nil {
			return err
		}
		routeKey := api.Method + "\x00" + api.Path
		if _, exists := routes[routeKey]; exists {
			return fmt.Errorf("duplicate API route %s %s", api.Method, api.Path)
		}
		routes[routeKey] = struct{}{}

		if !validHost(api.Upstream.Address) {
			return fmt.Errorf("%s.upstream.address must be an IP address or DNS name", name)
		}
		if api.Upstream.Port == 0 || api.Upstream.Port > 65535 {
			return fmt.Errorf("%s.upstream.port must be between 1 and 65535", name)
		}
		if err := validatePath(name+".upstream.path", api.Upstream.Path); err != nil {
			return err
		}
	}

	if c.Kubernetes != nil {
		if problems := validation.IsDNS1123Label(c.Kubernetes.Name); len(problems) > 0 || len(c.Kubernetes.Name) > 56 {
			return fmt.Errorf("kubernetes.name must be a DNS label of at most 56 characters")
		}
		if problems := validation.IsDNS1123Label(c.Kubernetes.Namespace); len(problems) > 0 {
			return fmt.Errorf("kubernetes.namespace must be a DNS label")
		}
		if strings.TrimSpace(c.Kubernetes.Image) == "" || strings.ContainsAny(c.Kubernetes.Image, " \t\r\n") {
			return fmt.Errorf("kubernetes.image must be an image reference")
		}
		if c.Kubernetes.Replicas != nil && *c.Kubernetes.Replicas < 0 {
			return fmt.Errorf("kubernetes.replicas must not be negative")
		}
		if c.Kubernetes.ServicePort < 1 || c.Kubernetes.ServicePort > 65535 {
			return fmt.Errorf("kubernetes.service_port must be between 1 and 65535")
		}
		if !net.ParseIP(c.Listener.Address).IsUnspecified() {
			return fmt.Errorf("Kubernetes requires a wildcard listener address (0.0.0.0 or ::)")
		}
	}

	return nil
}

func (c Config) withDefaults() Config {
	if c.Listener.Address == "" {
		c.Listener.Address = defaultListenerAddr
	}
	if c.Listener.Port == 0 {
		c.Listener.Port = defaultListenerPort
	}
	if c.APIs != nil {
		apis := make([]API, len(c.APIs))
		copy(apis, c.APIs)
		c.APIs = apis
	}
	for i := range c.APIs {
		if c.APIs[i].Method == "" {
			c.APIs[i].Method = http.MethodPost
		}
		if c.APIs[i].Upstream.Path == "" {
			c.APIs[i].Upstream.Path = c.APIs[i].Path
		}
	}
	if c.Kubernetes != nil {
		kubernetes := *c.Kubernetes
		c.Kubernetes = &kubernetes
		if kubernetes.Replicas == nil {
			defaultReplicas := int32(2)
			c.Kubernetes.Replicas = &defaultReplicas
		} else {
			replicas := *kubernetes.Replicas
			c.Kubernetes.Replicas = &replicas
		}
		if c.Kubernetes.ServicePort == 0 {
			c.Kubernetes.ServicePort = defaultServicePort
		}
	}
	return c
}

func validMethod(method string) bool {
	if method == "" || strings.ToUpper(method) != method {
		return false
	}
	for _, char := range method {
		if char <= 0x20 || char >= 0x7f || strings.ContainsRune("()<>@,;:\\\"/[]?={}", char) {
			return false
		}
	}
	return true
}

func validatePath(name, value string) error {
	if value == "" || !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") ||
		strings.ContainsAny(value, "?#\\\r\n") || path.Clean(value) != value {
		return fmt.Errorf("%s must be a clean absolute path without a query or fragment", name)
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.IsAbs() {
		return fmt.Errorf("%s must be a valid request path", name)
	}
	return nil
}

func validHost(value string) bool {
	if net.ParseIP(value) != nil {
		return true
	}
	if value == "" || len(value) > 253 || !dnsNamePattern.MatchString(value) {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) > 63 {
			return false
		}
	}
	return true
}
