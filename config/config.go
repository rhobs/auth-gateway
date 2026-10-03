// Package config provides the consumer-facing configuration API for auth-gateway.
package config

import (
	"bytes"
	"errors"
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
	configVersion                           = 1
	envoyAdminAddress                       = "127.0.0.1"
	envoyAdminPort                          = 9901
	envoyListenerAddress                    = "0.0.0.0"
	defaultListenerPort                     = 8080
	defaultServicePort                      = 80
	defaultHTTPSServicePort                 = 443
	defaultServerTLSCertificate             = "/etc/auth-gateway-tls/tls.crt"
	defaultServerTLSPrivateKey              = "/etc/auth-gateway-tls/tls.key"
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

const defaultKubernetesReplicas int32 = 2

var apiNamePattern = regexp.MustCompile("^[a-z][a-z0-9-]{0,52}$")

// Config describes Envoy metadata, authentication, authorization, API routes, upstreams, and optional Kubernetes output.
type Config struct {
	Version               int                   `yaml:"version"`
	Node                  EnvoyNode             `yaml:"node,omitempty"`
	Listener              Listener              `yaml:"listener"`
	Overload              *OverloadConfig       `yaml:"overload,omitempty"`
	Authenticators        []Authenticator       `yaml:"authenticators,omitempty"`
	AuthorizationPolicies []AuthorizationPolicy `yaml:"authorization_policies,omitempty"`
	Processing            []Processor           `yaml:"processing,omitempty"`
	Servers               []Server              `yaml:"servers"`
	APIs                  []API                 `yaml:"apis"`
	Kubernetes            *Kubernetes           `yaml:"kubernetes,omitempty"`
}

// EnvoyNode describes the identity and logical cluster of this Envoy instance.
type EnvoyNode struct {
	ID      string `yaml:"id,omitempty"`
	Cluster string `yaml:"cluster,omitempty"`
}

// Listener describes the socket shared by the configured servers.
type Listener struct {
	Port                          *uint32       `yaml:"port,omitempty"`
	PerConnectionBufferLimitBytes *uint32       `yaml:"per_connection_buffer_limit_bytes,omitempty"`
	MaxRequestHeadersKB           *uint32       `yaml:"max_request_headers_kb,omitempty"`
	MaxRequestHeadersCount        *uint32       `yaml:"max_request_headers_count,omitempty"`
	RequestHeadersTimeout         *Duration     `yaml:"request_headers_timeout,omitempty"`
	RequestTimeout                *Duration     `yaml:"request_timeout,omitempty"`
	ConnectionIdleTimeout         *Duration     `yaml:"connection_idle_timeout,omitempty"`
	StreamIdleTimeout             *Duration     `yaml:"stream_idle_timeout,omitempty"`
	MaxStreamDuration             *Duration     `yaml:"max_stream_duration,omitempty"`
	StreamFlushTimeout            *Duration     `yaml:"stream_flush_timeout,omitempty"`
	TLSHandshakeTimeout           *Duration     `yaml:"tls_handshake_timeout,omitempty"`
	HTTP2                         *HTTP2Options `yaml:"http2,omitempty"`
}

// API describes one upstream and its routes.
type API struct {
	Name            string                `yaml:"name"`
	Routes          []Route               `yaml:"routes"`
	Upstream        Upstream              `yaml:"upstream"`
	CircuitBreakers *CircuitBreakerConfig `yaml:"circuit_breakers,omitempty"`
	Timeouts        *RouteTimeouts        `yaml:"timeouts,omitempty"`
}

// CircuitBreakerConfig describes Envoy circuit breaker thresholds for an API's upstream cluster.
type CircuitBreakerConfig struct {
	MaxConnections     *uint32 `yaml:"max_connections,omitempty"`
	MaxPendingRequests *uint32 `yaml:"max_pending_requests,omitempty"`
	MaxRequests        *uint32 `yaml:"max_requests,omitempty"`
	MaxRetries         *uint32 `yaml:"max_retries,omitempty"`
}

// Route describes the required methods and path matcher, plus optional rewrite and processing.
type Route struct {
	Methods    []string         `yaml:"methods"`
	Path       PathMatch        `yaml:"path"`
	Rewrite    *PathRewrite     `yaml:"rewrite,omitempty"`
	Processing *RouteProcessing `yaml:"processing,omitempty"`
	Timeouts   *RouteTimeouts   `yaml:"timeouts,omitempty"`
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
	Address                       string        `yaml:"address"`
	Port                          uint32        `yaml:"port"`
	ConnectTimeout                *Duration     `yaml:"connect_timeout,omitempty"`
	PerConnectionBufferLimitBytes *uint32       `yaml:"per_connection_buffer_limit_bytes,omitempty"`
	HTTPProtocol                  string        `yaml:"http_protocol,omitempty"`
	HTTP2                         *HTTP2Options `yaml:"http2,omitempty"`
	TLSConfig                     *UpstreamTLS  `yaml:"tls_config,omitempty"`
}

// Kubernetes contains the settings needed to generate a Deployment and Service.
type Kubernetes struct {
	Name      string `yaml:"name"`
	Namespace string `yaml:"namespace"`
	Image     string `yaml:"image"`
	// OTelCollectorImage defaults to the OpenTelemetry Collector Contrib image used by the PoC.
	OTelCollectorImage string                         `yaml:"otel_collector_image,omitempty"`
	Replicas           *int32                         `yaml:"replicas,omitempty"`
	ServicePort        *int32                         `yaml:"service_port,omitempty"`
	HTTPSServicePort   *int32                         `yaml:"https_service_port,omitempty"`
	Resources          KubernetesResourceRequirements `yaml:"resources,omitempty"`
	EnvoyConcurrency   *uint32                        `yaml:"envoy_concurrency,omitempty"`
	Metrics            KubernetesMetrics              `yaml:"metrics,omitempty"`
}

// KubernetesResourceRequirements configures resources for a container.
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

	data, err := io.ReadAll(r)
	if err != nil {
		return Config{}, fmt.Errorf("read gateway configuration: %w", err)
	}
	var c Config
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&c); err != nil {
		var durationError *durationYAMLError
		if errors.As(err, &durationError) {
			var document yaml.Node
			if yaml.Unmarshal(data, &document) == nil {
				if field := yamlPathAtPosition(&document, durationError.line, durationError.column, ""); field != "" {
					return Config{}, fmt.Errorf("%s: %w", field, err)
				}
			}
		}
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
	_, err := resolveConfig(c)
	return err
}

func (c Config) validate() error {
	if c.Version != configVersion {
		return fmt.Errorf("version must be %d", configVersion)
	}
	if strings.TrimSpace(c.Node.ID) == "" {
		return fmt.Errorf("node.id must not be empty")
	}
	if strings.TrimSpace(c.Node.Cluster) == "" {
		return fmt.Errorf("node.cluster must not be empty")
	}
	if err := c.Listener.validate(c.Kubernetes != nil); err != nil {
		return err
	}
	if len(c.APIs) == 0 {
		return fmt.Errorf("at least one API must be configured")
	}

	names := make(map[string]API, len(c.APIs))
	for i, api := range c.APIs {
		name := fmt.Sprintf("apis[%d]", i)
		if !apiNamePattern.MatchString(api.Name) {
			return fmt.Errorf("%s.name must start with a lowercase letter and contain only lowercase letters, numbers, or hyphens", name)
		}
		if _, exists := names[api.Name]; exists {
			return fmt.Errorf("duplicate API name %q", api.Name)
		}
		names[api.Name] = api

		if !validHost(api.Upstream.Address) {
			return fmt.Errorf("%s.upstream.address must be an IP address or DNS name", name)
		}
		if api.Upstream.Port == 0 || api.Upstream.Port > 65535 {
			return fmt.Errorf("%s.upstream.port must be between 1 and 65535", name)
		}
		if err := api.Upstream.validate(name+".upstream", c.Kubernetes != nil); err != nil {
			return err
		}
		if err := validateRouteTimeouts(name+".timeouts", api.Timeouts); err != nil {
			return err
		}

		if len(api.Routes) == 0 {
			return fmt.Errorf("%s.routes must contain at least one route", name)
		}
		routes := make(map[string]struct{}, len(api.Routes))
		for routeIndex, route := range api.Routes {
			routeName := fmt.Sprintf("%s.routes[%d]", name, routeIndex)
			if err := validateRouteTimeouts(routeName+".timeouts", route.Timeouts); err != nil {
				return err
			}
			if err := validateRouteProcessing(routeName+".processing", route.Processing); err != nil {
				return err
			}
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

	if err := c.validateServers(names); err != nil {
		return err
	}
	if err := c.validateProcessing(); err != nil {
		return err
	}
	if err := c.validateAuthentication(names); err != nil {
		return err
	}

	if c.Kubernetes != nil {
		if strings.TrimSpace(c.Kubernetes.Image) == "" || strings.ContainsAny(c.Kubernetes.Image, " \t\r\n") {
			return fmt.Errorf("kubernetes.image must be an image reference")
		}
		if strings.TrimSpace(c.Kubernetes.OTelCollectorImage) == "" || strings.ContainsAny(c.Kubernetes.OTelCollectorImage, " \t\r\n") {
			return fmt.Errorf("kubernetes.otel_collector_image must be an image reference")
		}
		if c.Kubernetes.Replicas != nil && *c.Kubernetes.Replicas < 0 {
			return fmt.Errorf("kubernetes.replicas must not be negative")
		}
		if *c.Kubernetes.ServicePort < 1 || *c.Kubernetes.ServicePort > 65535 {
			if c.hasHTTP() {
				return fmt.Errorf("kubernetes.service_port must be between 1 and 65535")
			}
		}
		if c.hasHTTP() && *c.Kubernetes.ServicePort == defaultOTelMetricsPort {
			return fmt.Errorf("kubernetes.service_port must not conflict with the metrics port")
		}
		if c.hasHTTPS() {
			if err := c.validateTLSMounts(); err != nil {
				return err
			}
			if *c.Kubernetes.HTTPSServicePort < 1 || *c.Kubernetes.HTTPSServicePort > 65535 {
				return fmt.Errorf("kubernetes.https_service_port must be between 1 and 65535")
			}
			if *c.Kubernetes.HTTPSServicePort == defaultOTelMetricsPort {
				return fmt.Errorf("kubernetes.https_service_port must not conflict with the metrics port")
			}
			if c.hasHTTP() && *c.Kubernetes.HTTPSServicePort == *c.Kubernetes.ServicePort {
				return fmt.Errorf("kubernetes.service_port and kubernetes.https_service_port must differ")
			}
		} else if c.Kubernetes.HTTPSServicePort != nil {
			return fmt.Errorf("kubernetes.https_service_port requires an HTTPS server")
		}
		if c.Kubernetes.EnvoyConcurrency != nil && *c.Kubernetes.EnvoyConcurrency == 0 {
			return fmt.Errorf("kubernetes.envoy_concurrency must be positive")
		}
		if err := validateKubernetesResourceRequirements("kubernetes.resources", c.Kubernetes.Resources); err != nil {
			return err
		}
		if err := c.Kubernetes.Metrics.validate(); err != nil {
			return err
		}
	}

	return c.Overload.validate(c.Kubernetes)
}

func (c Config) withDefaults() Config {
	c.Authenticators = cloneAuthenticators(c.Authenticators)
	c.AuthorizationPolicies = cloneAuthorizationPolicies(c.AuthorizationPolicies)
	c.Processing = cloneProcessors(c.Processing)
	if c.Node.ID == "" {
		c.Node.ID = defaultNodeID
	}
	if c.Node.Cluster == "" {
		c.Node.Cluster = defaultNodeCluster
	}
	c.Listener = c.Listener.withDefaults()
	c.Overload = c.Overload.withDefaults()
	if c.Servers != nil {
		servers := make([]Server, len(c.Servers))
		for i, server := range c.Servers {
			servers[i] = server
			servers[i].APIs = append([]string(nil), server.APIs...)
			servers[i].Authentication = cloneAuthentication(server.Authentication)
			servers[i].Authorization = cloneAuthorization(server.Authorization)
			if server.TLSConfig != nil {
				tlsConfig := server.TLSConfig.withDefaults()
				servers[i].TLSConfig = &tlsConfig
			}
		}
		c.Servers = servers
	}
	if c.APIs != nil {
		apis := make([]API, len(c.APIs))
		for i, api := range c.APIs {
			apis[i] = api
			apis[i].Upstream = api.Upstream.withDefaults()
			apis[i].Timeouts = cloneRouteTimeouts(api.Timeouts)
			if api.Routes != nil {
				apis[i].Routes = make([]Route, len(api.Routes))
				for j, route := range api.Routes {
					apis[i].Routes[j] = route
					apis[i].Routes[j].Timeouts = cloneRouteTimeouts(route.Timeouts)
					apis[i].Routes[j].Methods = append([]string(nil), route.Methods...)
					if route.Processing != nil {
						processing := *route.Processing
						processing.RequestHeaders = append([]RequestHeaderMapping(nil), route.Processing.RequestHeaders...)
						apis[i].Routes[j].Processing = &processing
					}
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
		c.APIs[i].CircuitBreakers = defaultCircuitBreakers(c.APIs[i].CircuitBreakers)
	}
	if c.Kubernetes != nil {
		kubernetes := *c.Kubernetes
		c.Kubernetes = &kubernetes
		if kubernetes.Replicas == nil {
			defaultReplicas := defaultKubernetesReplicas
			c.Kubernetes.Replicas = &defaultReplicas
		} else {
			replicas := *kubernetes.Replicas
			c.Kubernetes.Replicas = &replicas
		}
		c.Kubernetes.ServicePort = defaultValue(kubernetes.ServicePort, int32(defaultServicePort))
		c.Kubernetes.HTTPSServicePort = clonePointer(kubernetes.HTTPSServicePort)
		if c.hasHTTPS() {
			c.Kubernetes.HTTPSServicePort = defaultValue(kubernetes.HTTPSServicePort, int32(defaultHTTPSServicePort))
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
		c.Kubernetes.EnvoyConcurrency = clonePointer(kubernetes.EnvoyConcurrency)
		c.Kubernetes.Metrics = kubernetes.Metrics.withDefaults()
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
	return net.ParseIP(value) != nil || validDNSHost(value)
}

func validDNSHost(value string) bool {
	return net.ParseIP(value) == nil && len(validation.IsDNS1123Subdomain(value)) == 0
}
