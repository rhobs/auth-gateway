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
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	configVersion                           = 1
	envoyAdminAddress                       = "127.0.0.1"
	envoyAdminPort                          = 9901
	defaultListenerAddr                     = "0.0.0.0"
	defaultListenerPort                     = 8080
	defaultServicePort                      = 80
	defaultOTelCollectorImage               = "otel/opentelemetry-collector-contrib:0.135.0"
	defaultOTelMetricsPort                  = 8889
	defaultKubernetesCPURequest             = "50m"
	defaultKubernetesMemoryRequest          = "64Mi"
	defaultKubernetesCPULimit               = "1"
	defaultKubernetesMemoryLimit            = "256Mi"
	defaultNodeID                           = "auth-gateway"
	defaultNodeCluster                      = "auth-gateway"
	defaultCircuitBreakerMaxConnections     = 1024
	defaultCircuitBreakerMaxPendingRequests = 1024
	defaultCircuitBreakerMaxRequests        = 1024
	defaultCircuitBreakerMaxRetries         = 0
)

var (
	apiNamePattern = regexp.MustCompile("^[a-z][a-z0-9-]{0,52}$")
	dnsNamePattern = regexp.MustCompile("^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$")
)

// Config describes Envoy node metadata, listener, API routes, upstreams, and optional Kubernetes output.
type Config struct {
	Version    int         `yaml:"version"`
	Node       EnvoyNode   `yaml:"node,omitempty"`
	Listener   Listener    `yaml:"listener"`
	APIs       []API       `yaml:"apis"`
	Kubernetes *Kubernetes `yaml:"kubernetes,omitempty"`
}

// EnvoyNode describes the identity and logical cluster of this Envoy instance.
type EnvoyNode struct {
	ID      string `yaml:"id,omitempty"`
	Cluster string `yaml:"cluster,omitempty"`
}

// Listener describes the HTTP address used by Envoy.
type Listener struct {
	Address string `yaml:"address,omitempty"`
	Port    uint32 `yaml:"port,omitempty"`
}

// API describes one upstream and its routes.
type API struct {
	Name            string                `yaml:"name"`
	Routes          []Route               `yaml:"routes"`
	Upstream        Upstream              `yaml:"upstream"`
	CircuitBreakers *CircuitBreakerConfig `yaml:"circuit_breakers,omitempty"`
}

// CircuitBreakerConfig describes Envoy circuit breaker thresholds for an API's upstream cluster.
type CircuitBreakerConfig struct {
	MaxConnections     *uint32 `yaml:"max_connections,omitempty"`
	MaxPendingRequests *uint32 `yaml:"max_pending_requests,omitempty"`
	MaxRequests        *uint32 `yaml:"max_requests,omitempty"`
	MaxRetries         *uint32 `yaml:"max_retries,omitempty"`
}

// Route describes the required methods and path matcher, plus an optional rewrite.
type Route struct {
	Methods []string     `yaml:"methods"`
	Path    PathMatch    `yaml:"path"`
	Rewrite *PathRewrite `yaml:"rewrite,omitempty"`
}

// PathMatch selects one exact path, path prefix, or safe regular expression.
type PathMatch struct {
	Exact  string `yaml:"exact,omitempty"`
	Prefix string `yaml:"prefix,omitempty"`
	Regex  string `yaml:"regex,omitempty"`
}

// PathRewrite optionally replaces a path, prefix, or regex match.
type PathRewrite struct {
	Path   string        `yaml:"path,omitempty"`
	Prefix string        `yaml:"prefix,omitempty"`
	Regex  *RegexRewrite `yaml:"regex,omitempty"`
}

// RegexRewrite replaces matches in the request path using RE2 capture groups.
type RegexRewrite struct {
	Pattern      string `yaml:"pattern"`
	Substitution string `yaml:"substitution"`
}

// Upstream describes the service that receives routed requests.
type Upstream struct {
	Address string `yaml:"address"`
	Port    uint32 `yaml:"port"`
}

// Kubernetes contains the settings needed to generate a Deployment and Service.
type Kubernetes struct {
	Name      string `yaml:"name"`
	Namespace string `yaml:"namespace"`
	Image     string `yaml:"image"`
	// OTelCollectorImage defaults to the OpenTelemetry Collector Contrib image used by the PoC.
	OTelCollectorImage string                         `yaml:"otel_collector_image,omitempty"`
	Replicas           *int32                         `yaml:"replicas,omitempty"`
	ServicePort        int32                          `yaml:"service_port,omitempty"`
	Resources          KubernetesResourceRequirements `yaml:"resources,omitempty"`
}

// KubernetesResourceRequirements configures resources for the Envoy container.
// Values use Kubernetes resource quantity notation.
type KubernetesResourceRequirements struct {
	Requests map[string]string `yaml:"requests,omitempty"`
	Limits   map[string]string `yaml:"limits,omitempty"`
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
	if strings.TrimSpace(c.Node.ID) == "" {
		return fmt.Errorf("node.id must not be empty")
	}
	if strings.TrimSpace(c.Node.Cluster) == "" {
		return fmt.Errorf("node.cluster must not be empty")
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

		if !validHost(api.Upstream.Address) {
			return fmt.Errorf("%s.upstream.address must be an IP address or DNS name", name)
		}
		if api.Upstream.Port == 0 || api.Upstream.Port > 65535 {
			return fmt.Errorf("%s.upstream.port must be between 1 and 65535", name)
		}

		if len(api.Routes) == 0 {
			return fmt.Errorf("%s.routes must contain at least one route", name)
		}
		for routeIndex, route := range api.Routes {
			routeName := fmt.Sprintf("%s.routes[%d]", name, routeIndex)
			if err := validatePathMatch(routeName+".path", route.Path); err != nil {
				return err
			}
			if err := validatePathRewrite(routeName+".rewrite", route.Rewrite); err != nil {
				return err
			}
			if len(route.Methods) == 0 {
				return fmt.Errorf("%s.methods must contain at least one supported HTTP method", routeName)
			}

			seenMethods := make(map[string]struct{}, len(route.Methods))
			for _, method := range route.Methods {
				if !validMethod(method) {
					return fmt.Errorf("%s.methods must contain supported HTTP methods", routeName)
				}
				if _, exists := seenMethods[method]; exists {
					return fmt.Errorf("%s.methods contains duplicate method %q", routeName, method)
				}
				seenMethods[method] = struct{}{}
				if err := addRouteKey(routes, route.Path, method); err != nil {
					return err
				}
			}
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
		if strings.TrimSpace(c.Kubernetes.OTelCollectorImage) == "" || strings.ContainsAny(c.Kubernetes.OTelCollectorImage, " \t\r\n") {
			return fmt.Errorf("kubernetes.otel_collector_image must be an image reference")
		}
		if c.Kubernetes.Replicas != nil && *c.Kubernetes.Replicas < 0 {
			return fmt.Errorf("kubernetes.replicas must not be negative")
		}
		if c.Kubernetes.ServicePort < 1 || c.Kubernetes.ServicePort > 65535 {
			return fmt.Errorf("kubernetes.service_port must be between 1 and 65535")
		}
		if err := validateKubernetesResourceRequirements(c.Kubernetes.Resources); err != nil {
			return err
		}
		if !net.ParseIP(c.Listener.Address).IsUnspecified() {
			return fmt.Errorf("kubernetes requires a wildcard listener address (0.0.0.0 or ::)")
		}
	}

	return nil
}

func validateKubernetesResourceRequirements(requirements KubernetesResourceRequirements) error {
	for _, list := range []struct {
		name   string
		values map[string]string
	}{
		{name: "requests", values: requirements.Requests},
		{name: "limits", values: requirements.Limits},
	} {
		for name, value := range list.values {
			if problems := validation.IsQualifiedName(name); len(problems) > 0 {
				return fmt.Errorf("kubernetes.resources.%s contains invalid resource name %q", list.name, name)
			}
			quantity, err := resource.ParseQuantity(value)
			if err != nil {
				return fmt.Errorf("kubernetes.resources.%s.%s must be a valid Kubernetes resource quantity: %w", list.name, name, err)
			}
			if quantity.Cmp(resource.Quantity{}) < 0 {
				return fmt.Errorf("kubernetes.resources.%s.%s must not be negative", list.name, name)
			}
		}
	}
	return nil
}

func (c Config) withDefaults() Config {
	if c.Node.ID == "" {
		c.Node.ID = defaultNodeID
	}
	if c.Node.Cluster == "" {
		c.Node.Cluster = defaultNodeCluster
	}
	if c.Listener.Address == "" {
		c.Listener.Address = defaultListenerAddr
	}
	if c.Listener.Port == 0 {
		c.Listener.Port = defaultListenerPort
	}
	if c.APIs != nil {
		apis := make([]API, len(c.APIs))
		for i, api := range c.APIs {
			apis[i] = api
			if api.Routes != nil {
				apis[i].Routes = make([]Route, len(api.Routes))
				for j, route := range api.Routes {
					apis[i].Routes[j] = route
					apis[i].Routes[j].Methods = append([]string(nil), route.Methods...)
					if route.Rewrite != nil {
						rewrite := *route.Rewrite
						if route.Rewrite.Regex != nil {
							regexRewrite := *route.Rewrite.Regex
							rewrite.Regex = &regexRewrite
						}
						apis[i].Routes[j].Rewrite = &rewrite
					}
				}
			}
		}
		c.APIs = apis
	}
	for i := range c.APIs {
		circuitBreakers := c.APIs[i].CircuitBreakers
		if circuitBreakers == nil {
			circuitBreakers = &CircuitBreakerConfig{}
		}
		c.APIs[i].CircuitBreakers = &CircuitBreakerConfig{
			MaxConnections:     defaultUint32(circuitBreakers.MaxConnections, defaultCircuitBreakerMaxConnections),
			MaxPendingRequests: defaultUint32(circuitBreakers.MaxPendingRequests, defaultCircuitBreakerMaxPendingRequests),
			MaxRequests:        defaultUint32(circuitBreakers.MaxRequests, defaultCircuitBreakerMaxRequests),
			MaxRetries:         defaultUint32(circuitBreakers.MaxRetries, defaultCircuitBreakerMaxRetries),
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
		if c.Kubernetes.OTelCollectorImage == "" {
			c.Kubernetes.OTelCollectorImage = defaultOTelCollectorImage
		}
		resources := kubernetes.Resources
		resources.Requests = copyResourcesOrDefault(resources.Requests, map[string]string{
			"cpu":    defaultKubernetesCPURequest,
			"memory": defaultKubernetesMemoryRequest,
		})
		resources.Limits = copyResourcesOrDefault(resources.Limits, map[string]string{
			"cpu":    defaultKubernetesCPULimit,
			"memory": defaultKubernetesMemoryLimit,
		})
		c.Kubernetes.Resources = resources
	}
	return c
}

func copyResourcesOrDefault(values, defaults map[string]string) map[string]string {
	if values == nil {
		values = defaults
	}
	copy := make(map[string]string, len(values))
	for name, value := range values {
		copy[name] = value
	}
	return copy
}

func defaultUint32(value *uint32, fallback uint32) *uint32 {
	if value == nil {
		return &fallback
	}
	copy := *value
	return &copy
}

func addRouteKey(routes map[string]struct{}, path PathMatch, method string) error {
	key := pathMatchKey(path) + "\x00" + method
	if _, exists := routes[key]; exists {
		return fmt.Errorf("duplicate API route for method %s and path matcher %q", method, pathMatchValue(path))
	}
	routes[key] = struct{}{}
	return nil
}

func pathMatchKey(path PathMatch) string {
	switch {
	case path.Exact != "":
		return "exact\x00" + path.Exact
	case path.Prefix != "":
		return "prefix\x00" + path.Prefix
	default:
		return "regex\x00" + path.Regex
	}
}

func pathMatchValue(path PathMatch) string {
	switch {
	case path.Exact != "":
		return path.Exact
	case path.Prefix != "":
		return path.Prefix
	default:
		return path.Regex
	}
}

func validatePathMatch(name string, path PathMatch) error {
	count := 0
	if path.Exact != "" {
		count++
		if err := validatePath(name+".exact", path.Exact); err != nil {
			return err
		}
	}
	if path.Prefix != "" {
		count++
		if err := validatePathPrefix(name+".prefix", path.Prefix); err != nil {
			return err
		}
	}
	if path.Regex != "" {
		count++
		if _, err := regexp.Compile(path.Regex); err != nil {
			return fmt.Errorf("%s.regex must be a valid RE2 expression: %w", name, err)
		}
	}
	if count != 1 {
		return fmt.Errorf("%s must set exactly one of exact, prefix, or regex", name)
	}
	return nil
}

func validatePathRewrite(name string, rewrite *PathRewrite) error {
	if rewrite == nil {
		return nil
	}

	count := 0
	if rewrite.Path != "" {
		count++
		if err := validatePath(name+".path", rewrite.Path); err != nil {
			return err
		}
	}
	if rewrite.Prefix != "" {
		count++
		if err := validatePathPrefix(name+".prefix", rewrite.Prefix); err != nil {
			return err
		}
	}
	if rewrite.Regex != nil {
		count++
		if rewrite.Regex.Pattern == "" {
			return fmt.Errorf("%s.regex.pattern must not be empty", name)
		}
		if _, err := regexp.Compile(rewrite.Regex.Pattern); err != nil {
			return fmt.Errorf("%s.regex.pattern must be a valid RE2 expression: %w", name, err)
		}
		if strings.ContainsAny(rewrite.Regex.Substitution, "?#\r\n") {
			return fmt.Errorf("%s.regex.substitution must not contain a query, fragment, or newline", name)
		}
	}
	if count != 1 {
		return fmt.Errorf("%s must set exactly one of path, prefix, or regex", name)
	}
	return nil
}

func validMethod(method string) bool {
	switch method {
	case http.MethodConnect,
		http.MethodDelete,
		http.MethodGet,
		http.MethodHead,
		http.MethodOptions,
		http.MethodPatch,
		http.MethodPost,
		http.MethodPut,
		http.MethodTrace:
		return true
	default:
		return false
	}
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

func validatePathPrefix(name, value string) error {
	if value == "" {
		return fmt.Errorf("%s must not be empty", name)
	}
	if strings.HasPrefix(value, "//") {
		return fmt.Errorf("%s must be an absolute path prefix", name)
	}
	cleanable := value
	if value != "/" && strings.HasSuffix(value, "/") {
		cleanable = strings.TrimSuffix(value, "/")
	}
	return validatePath(name, cleanable)
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
