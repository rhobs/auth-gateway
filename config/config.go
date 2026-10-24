// Package config loads and validates auth-gateway YAML, then generates Envoy
// files or Kubernetes resources.
//
// Start with Load for YAML, or Config.Validate for a Config built in Go.
// Use Generate for file-based Envoy output, GenerateOTelCollectorConfig for
// the collector file, or GenerateKubernetes for Kubernetes resources.
// LoadAPIKeyCredentials and APIKeySecret build the external API-key Secret separately.
//
// Callers should treat error text as diagnostic only, without matching
// on it or relying on errors.Is or errors.As to classify failures.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	mutationrules "github.com/envoyproxy/go-control-plane/envoy/config/common/mutation_rules/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	overload "github.com/envoyproxy/go-control-plane/envoy/config/overload/v3"
	headermutation "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/header_mutation/v3"
	connections "github.com/envoyproxy/go-control-plane/envoy/extensions/resource_monitors/downstream_connections/v3"
	heap "github.com/envoyproxy/go-control-plane/envoy/extensions/resource_monitors/fixed_heap/v3"
	"go.yaml.in/yaml/v3"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
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
	imageWhitespaceCharacters               = " \t\r\n"
	invalidControlCharacters                = "\r\n\x00"
	authenticatorFieldPathFormat            = "authenticators[%d]"
	serverFieldPathFormat                   = "servers[%d]"
	maxStreamDurationFieldName              = "max_stream_duration"
	http1Protocol                           = "http1"
	http2Protocol                           = "http2"
	httpsProtocolToken                      = "https"
	kubernetesCPUResourceName               = "cpu"
	kubernetesMemoryResourceName            = "memory"
	caCertificateFilename                   = "ca.crt"
	tlsCertificateSecretKey                 = "tls.crt"
	tlsPrivateKeySecretKey                  = "tls.key"
)

const defaultKubernetesReplicas int32 = 2

var apiNamePattern = regexp.MustCompile("^[a-z][a-z0-9-]{0,52}$")

func validateGatewayName(fieldPath, value string) error {
	if !apiNamePattern.MatchString(value) {
		return fmt.Errorf("%s.name must start with a lowercase letter and contain only lowercase letters, numbers, or hyphens", fieldPath)
	}
	return nil
}

// Load decodes one strict YAML document, applies defaults, and validates it.
// API and route timeout overrides stay as supplied, including omitted values.
// Validation checks their effective values; generation resolves them on a copy.
// On failure, Load returns the zero Config and a non-nil error.
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
	if _, err := validateDefaultedConfig(c, false); err != nil {
		return Config{}, err
	}
	return c, nil
}

// Validate checks whether c follows the public configuration contract.
// Use it when building a Config in Go instead of loading YAML with Load.
func (c Config) Validate() error {
	_, err := validateDefaultedConfig(c.withDefaults(), false)
	return err
}

func (c Config) validateBaseSettings(metricsEnabled, tracingEnabled bool) error {
	if c.Version != configVersion {
		return fmt.Errorf("version must be %d", configVersion)
	}
	if strings.TrimSpace(c.Node.ID) == "" {
		return fmt.Errorf("node.id must not be empty")
	}
	if strings.TrimSpace(c.Node.Cluster) == "" {
		return fmt.Errorf("node.cluster must not be empty")
	}
	if err := c.Listener.validate(metricsEnabled, tracingEnabled); err != nil {
		return err
	}
	if err := c.Observability.Metrics.validate(); err != nil {
		return err
	}
	if err := c.Observability.Tracing.validate(); err != nil {
		return err
	}
	return nil
}

func (c Config) validateAPIs() (map[string]API, error) {
	if len(c.APIs) == 0 {
		return nil, fmt.Errorf("at least one API must be configured")
	}
	names := make(map[string]API, len(c.APIs))
	for i, api := range c.APIs {
		name := fmt.Sprintf("apis[%d]", i)
		if err := validateGatewayName(name, api.Name); err != nil {
			return nil, err
		}
		if _, exists := names[api.Name]; exists {
			return nil, fmt.Errorf("duplicate API name %q", api.Name)
		}
		names[api.Name] = api
		if err := validateAPI(name, api, c.Kubernetes != nil); err != nil {
			return nil, err
		}
	}
	return names, nil
}

func validateAPI(name string, api API, hasKubernetes bool) error {
	if !validHost(api.Upstream.Address) {
		return fmt.Errorf("%s.upstream.address must be an IP address or DNS name", name)
	}
	if api.Upstream.Port == 0 || api.Upstream.Port > 65535 {
		return fmt.Errorf("%s.upstream.port must be between 1 and 65535", name)
	}
	if err := api.Upstream.validate(name+".upstream", hasKubernetes); err != nil {
		return err
	}
	if err := validateRouteTimeouts(name+".timeouts", api.Timeouts); err != nil {
		return err
	}
	if err := validateAPIMetrics(name+".metrics", api.Metrics); err != nil {
		return err
	}
	if api.AdmissionControl != nil {
		if err := api.AdmissionControl.validate(name + ".admission_control"); err != nil {
			return err
		}
	}
	if api.FaultInjection != nil {
		if err := api.FaultInjection.validate(name + ".fault_injection"); err != nil {
			return err
		}
	}
	if len(api.Routes) == 0 {
		return fmt.Errorf("%s.routes must contain at least one route", name)
	}
	routes := make(map[string]struct{}, len(api.Routes))
	for routeIndex, route := range api.Routes {
		routeName := fmt.Sprintf("%s.routes[%d]", name, routeIndex)
		if err := validateAPIRoute(routeName, route, routes); err != nil {
			return err
		}
	}
	return nil
}

func validateAPIRoute(name string, route Route, routes map[string]struct{}) error {
	if err := validateRouteTimeouts(name+".timeouts", route.Timeouts); err != nil {
		return err
	}
	if err := validateRouteProcessing(name+".processing", route.Processing); err != nil {
		return err
	}
	if err := validatePathMatch(name+".path", route.Path); err != nil {
		return err
	}
	if err := validatePathRewrite(name+".rewrite", route.Rewrite); err != nil {
		return err
	}
	if len(route.Methods) == 0 {
		return fmt.Errorf("%s.methods must contain at least one supported HTTP method", name)
	}
	seenMethods := make(map[string]struct{}, len(route.Methods))
	for _, method := range route.Methods {
		if !validMethod(method) {
			return fmt.Errorf("%s.methods must contain supported HTTP methods", name)
		}
		if _, exists := seenMethods[method]; exists {
			return fmt.Errorf("%s.methods contains duplicate method %q", name, method)
		}
		seenMethods[method] = struct{}{}
		if err := addRouteKey(routes, route.Path, method); err != nil {
			return err
		}
	}
	return nil
}

func (c Config) validateKubernetes(metricsEnabled, tracingEnabled bool) error {
	k := c.Kubernetes
	if strings.TrimSpace(k.Image) == "" || strings.ContainsAny(k.Image, imageWhitespaceCharacters) {
		return fmt.Errorf("kubernetes.image must be an image reference")
	}
	if err := validateOTelCollectorImage(k.OTelCollectorImage, metricsEnabled || tracingEnabled); err != nil {
		return err
	}
	if k.Replicas != nil && *k.Replicas < 0 {
		return fmt.Errorf("kubernetes.replicas must not be negative")
	}
	if err := c.validateKubernetesServicePorts(metricsEnabled); err != nil {
		return err
	}
	if k.EnvoyConcurrency != nil && *k.EnvoyConcurrency == 0 {
		return fmt.Errorf("kubernetes.envoy_concurrency must be positive")
	}
	if err := validateKubernetesResourceRequirements(kubernetesResourcesFieldPath, k.Resources); err != nil {
		return err
	}
	return k.Metrics.validate()
}

func (c Config) validateKubernetesServicePorts(metricsEnabled bool) error {
	k := c.Kubernetes
	if *k.ServicePort < 1 || *k.ServicePort > 65535 {
		if c.hasHTTP() {
			return fmt.Errorf("kubernetes.service_port must be between 1 and 65535")
		}
	}
	if c.hasHTTP() {
		if err := validateOTelMetricsServicePort("service_port", *k.ServicePort, metricsEnabled); err != nil {
			return err
		}
	}
	if c.hasHTTPS() {
		if err := c.validateTLSMounts(); err != nil {
			return err
		}
		if *k.HTTPSServicePort < 1 || *k.HTTPSServicePort > 65535 {
			return fmt.Errorf("kubernetes.https_service_port must be between 1 and 65535")
		}
		if err := validateOTelMetricsServicePort("https_service_port", *k.HTTPSServicePort, metricsEnabled); err != nil {
			return err
		}
		if c.hasHTTP() && *k.HTTPSServicePort == *k.ServicePort {
			return fmt.Errorf("kubernetes.service_port and kubernetes.https_service_port must differ")
		}
	} else if k.HTTPSServicePort != nil {
		return fmt.Errorf("kubernetes.https_service_port requires an HTTPS server")
	}
	return nil
}

func (c Config) withDefaults() Config {
	c = c.clone()
	for i := range c.Authenticators {
		c.Authenticators[i] = c.Authenticators[i].withDefaults()
	}
	if c.Node.ID == "" {
		c.Node.ID = defaultNodeID
	}
	if c.Node.Cluster == "" {
		c.Node.Cluster = defaultNodeCluster
	}
	c.Listener = c.Listener.withDefaults()
	if c.Overload != nil {
		overload := c.Overload.withDefaults()
		c.Overload = &overload
	}
	c.Observability = c.Observability.withDefaults(c.Node.Cluster)
	for i := range c.Servers {
		if c.Servers[i].TLSConfig != nil {
			tlsConfig := c.Servers[i].TLSConfig.withDefaults()
			c.Servers[i].TLSConfig = &tlsConfig
		}
	}
	for i := range c.APIs {
		c.APIs[i].Upstream = c.APIs[i].Upstream.withDefaults()
	}
	for i := range c.APIs {
		c.APIs[i].CircuitBreakers = c.APIs[i].CircuitBreakers.withDefaults()
	}
	if c.Kubernetes != nil {
		kubernetes := c.Kubernetes.withDefaults(c.hasHTTPS())
		c.Kubernetes = &kubernetes
	}
	return c
}

func (a APIKeyAuthenticator) withDefaults() APIKeyAuthenticator {
	if a.Header == "" {
		a.Header = defaultAPIKeyHeader
	}
	return a
}

func (authenticator Authenticator) withDefaults() Authenticator {
	if authenticator.JWT != nil {
		authenticator.JWT.JWKS = authenticator.JWT.JWKS.withDefaults()
	}
	if authenticator.APIKey != nil {
		apiKey := authenticator.APIKey.withDefaults()
		authenticator.APIKey = &apiKey
	}
	return authenticator
}

func (j JWKSConfig) withDefaults() JWKSConfig {
	if j.DNSLookupFamily == "" {
		j.DNSLookupFamily = jwksDNSLookupFamilyV4Only
	}
	j.CacheDuration = j.CacheDuration.withDefault(5 * time.Minute)
	j.FetchTimeout = j.FetchTimeout.withDefault(5 * time.Second)
	j.ConnectTimeout = j.ConnectTimeout.withDefault(5 * time.Second)
	j.TrustedCA = cloneConfigPointer(j.TrustedCA)
	j.CircuitBreakers = j.CircuitBreakers.withDefaults()
	return j
}

// CircuitBreakerConfig describes Envoy circuit breaker thresholds for an upstream cluster.
type CircuitBreakerConfig struct {
	MaxConnections     *uint32 `yaml:"max_connections,omitempty"`
	MaxPendingRequests *uint32 `yaml:"max_pending_requests,omitempty"`
	MaxRequests        *uint32 `yaml:"max_requests,omitempty"`
	MaxRetries         *uint32 `yaml:"max_retries,omitempty"`
}

func (c *CircuitBreakerConfig) clone() CircuitBreakerConfig {
	cloned := *c
	cloned.MaxConnections = clonePointer(c.MaxConnections)
	cloned.MaxPendingRequests = clonePointer(c.MaxPendingRequests)
	cloned.MaxRequests = clonePointer(c.MaxRequests)
	cloned.MaxRetries = clonePointer(c.MaxRetries)
	return cloned
}

func (c *CircuitBreakerConfig) withDefaults() *CircuitBreakerConfig {
	if c == nil {
		c = &CircuitBreakerConfig{}
	}
	return &CircuitBreakerConfig{
		MaxConnections:     defaultValue(c.MaxConnections, defaultCircuitBreakerMaxConnections),
		MaxPendingRequests: defaultValue(c.MaxPendingRequests, defaultCircuitBreakerMaxPendingRequests),
		MaxRequests:        defaultValue(c.MaxRequests, defaultCircuitBreakerMaxRequests),
		MaxRetries:         defaultValue(c.MaxRetries, defaultCircuitBreakerMaxRetries),
	}
}

func (c *CircuitBreakerConfig) toCircuitBreakers() *cluster.CircuitBreakers {
	return &cluster.CircuitBreakers{Thresholds: []*cluster.CircuitBreakers_Thresholds{{
		Priority:           core.RoutingPriority_DEFAULT,
		MaxConnections:     wrapperspb.UInt32(*c.MaxConnections),
		MaxPendingRequests: wrapperspb.UInt32(*c.MaxPendingRequests),
		MaxRequests:        wrapperspb.UInt32(*c.MaxRequests),
		MaxRetries:         wrapperspb.UInt32(*c.MaxRetries),
	}}}
}

func (l Listener) withDefaults() Listener {
	l.Port = defaultValue(l.Port, defaultListenerPort)
	l.PerConnectionBufferLimitBytes = defaultValue(l.PerConnectionBufferLimitBytes, 1048576)
	l.MaxRequestHeadersKB = defaultValue(l.MaxRequestHeadersKB, 32)
	l.MaxRequestHeadersCount = defaultValue(l.MaxRequestHeadersCount, 100)
	l.RequestHeadersTimeout = l.RequestHeadersTimeout.withDefault(5 * time.Second)
	l.RequestTimeout = l.RequestTimeout.withDefault(30 * time.Second)
	l.ConnectionIdleTimeout = l.ConnectionIdleTimeout.withDefault(time.Minute)
	l.StreamIdleTimeout = l.StreamIdleTimeout.withDefault(time.Minute)
	l.MaxStreamDuration = l.MaxStreamDuration.withDefault(30 * time.Second)
	l.StreamFlushTimeout = l.StreamFlushTimeout.withDefault(5 * time.Second)
	l.TLSHandshakeTimeout = l.TLSHandshakeTimeout.withDefault(5 * time.Second)
	return l
}

func (u Upstream) withDefaults() Upstream {
	u.ConnectTimeout = u.ConnectTimeout.withDefault(5 * time.Second)
	u.PerConnectionBufferLimitBytes = defaultValue(u.PerConnectionBufferLimitBytes, 1048576)
	if u.HTTPProtocol == "" {
		u.HTTPProtocol = http1Protocol
	}
	return u
}

func (o OverloadConfig) withDefaults() OverloadConfig {
	o.HeapShrinkThreshold = defaultValue(o.HeapShrinkThreshold, 0.90)
	o.RequestRejectThreshold = defaultValue(o.RequestRejectThreshold, 0.95)
	return o
}

func (k Kubernetes) withDefaults(hasHTTPS bool) Kubernetes {
	if k.Image == "" {
		k.Image = DefaultEnvoyImage
	}
	k.Replicas = defaultValue(k.Replicas, defaultKubernetesReplicas)
	k.ServicePort = defaultValue(k.ServicePort, int32(defaultServicePort))
	if hasHTTPS {
		k.HTTPSServicePort = defaultValue(k.HTTPSServicePort, int32(defaultHTTPSServicePort))
	}
	if k.OTelCollectorImage == "" {
		k.OTelCollectorImage = DefaultOTelCollectorImage
	}
	k.Metrics = k.Metrics.withDefaults()
	k.Resources.Requests = copyResourcesOrDefault(k.Resources.Requests, map[string]string{
		kubernetesCPUResourceName:    defaultKubernetesCPURequest,
		kubernetesMemoryResourceName: defaultKubernetesMemoryRequest,
	})
	k.Resources.Limits = copyResourcesOrDefault(k.Resources.Limits, map[string]string{
		kubernetesCPUResourceName:    defaultKubernetesCPULimit,
		kubernetesMemoryResourceName: defaultKubernetesMemoryLimit,
	})
	return k
}

const serverTLSSecretDirectory = "/etc"

func (s ServerTLS) withDefaults() ServerTLS {
	certificate, privateKey := defaultServerTLSCertificate, defaultServerTLSPrivateKey
	if s.Secret != "" {
		certificate = path.Join(serverTLSSecretDirectory, s.Secret, tlsCertificateSecretKey)
		privateKey = path.Join(serverTLSSecretDirectory, s.Secret, tlsPrivateKeySecretKey)
	}
	if s.Certificate == "" {
		s.Certificate = certificate
	}
	if s.PrivateKey == "" {
		s.PrivateKey = privateKey
	}
	return s
}

func (c Config) validateServers(apis map[string]API) ([]resolvedServer, error) {
	if len(c.Servers) == 0 {
		return nil, fmt.Errorf("servers must contain at least one server")
	}
	servers := make([]resolvedServer, len(c.Servers))
	hosts := make(map[string]int, len(c.Servers))
	for i, server := range c.Servers {
		name := fmt.Sprintf(serverFieldPathFormat, i)
		if !validDNSHost(server.Hostname) {
			return nil, fmt.Errorf("%s.hostname must be an exact DNS hostname", name)
		}
		if previous, exists := hosts[server.Hostname]; exists {
			return nil, fmt.Errorf("%s.hostname %q is already used by servers[%d]", name, server.Hostname, previous)
		}
		hosts[server.Hostname] = i
		if server.TLSConfig != nil {
			if err := validateServerTLS(name+".tls_config", *server.TLSConfig); err != nil {
				return nil, err
			}
		}
		bound, err := server.boundAPIs(apis)
		if err != nil {
			return nil, fmt.Errorf("%s.apis: %w", name, err)
		}
		routes := make(map[string]struct{})
		for _, api := range bound {
			for _, route := range api.Routes {
				for _, method := range route.Methods {
					if err := addRouteKey(routes, route.Path, method); err != nil {
						return nil, fmt.Errorf("%s.apis: %w", name, err)
					}
				}
			}
		}
		servers[i] = resolvedServer{Server: &c.Servers[i], apis: bound}
	}
	return servers, nil
}

func (c Config) tlsMounts() []serverTLSMount {
	var mounts []serverTLSMount
	seen := make(map[ServerTLS]struct{})
	for i, server := range c.Servers {
		if server.TLSConfig == nil {
			continue
		}
		binding := *server.TLSConfig
		if _, exists := seen[binding]; exists {
			continue
		}
		seen[binding] = struct{}{}
		mounts = append(mounts, serverTLSMount{serverIndex: i, config: binding})
	}
	return mounts
}

func (c Config) validateTLSMounts() error {
	mounts := c.tlsMounts()
	for i, mount := range mounts {
		name := fmt.Sprintf("servers[%d].tls_config", mount.serverIndex)
		if mount.config.Secret == "" {
			return fmt.Errorf("%s.secret is required when generating Kubernetes resources", name)
		}
		directory := path.Dir(mount.config.Certificate)
		for _, reserved := range []string{configDirectory, collectorConfigDirectory, caDirectory} {
			if directoriesOverlap(directory, reserved) {
				return fmt.Errorf("%s certificate directory %q overlaps configuration directory %q", name, directory, reserved)
			}
		}
		for _, previous := range mounts[:i] {
			if directoriesOverlap(directory, path.Dir(previous.config.Certificate)) {
				return fmt.Errorf("%s certificate directory overlaps servers[%d].tls_config", name, previous.serverIndex)
			}
		}
	}
	return nil
}

func (c Config) hasHTTP() bool {
	for _, server := range c.Servers {
		if server.TLSConfig == nil {
			return true
		}
	}
	return false
}

func (c Config) hasHTTPS() bool {
	for _, server := range c.Servers {
		if server.TLSConfig != nil {
			return true
		}
	}
	return false
}

func (c Config) validateAuthenticators() (map[string]Authenticator, string, error) {
	authenticators := make(map[string]Authenticator, len(c.Authenticators))
	apiKeyCount := 0
	apiKeyHeader := ""
	for i, authenticator := range c.Authenticators {
		name := fmt.Sprintf(authenticatorFieldPathFormat, i)
		if err := validateGatewayName(name, authenticator.Name); err != nil {
			return nil, "", err
		}
		if _, exists := authenticators[authenticator.Name]; exists {
			return nil, "", fmt.Errorf("duplicate authenticator name %q", authenticator.Name)
		}
		types := 0
		for _, present := range []bool{authenticator.JWT != nil, authenticator.APIKey != nil, authenticator.MTLS != nil} {
			if present {
				types++
			}
		}
		if types != 1 {
			return nil, "", fmt.Errorf("%s must set exactly one of jwt, api_key, or mtls", name)
		}
		if authenticator.JWT != nil {
			if err := validateJWTAuthenticator(name+".jwt", *authenticator.JWT); err != nil {
				return nil, "", err
			}
			if err := authenticator.JWT.JWKS.validate(name+".jwt.jwks", c.Kubernetes != nil); err != nil {
				return nil, "", err
			}
		} else if authenticator.APIKey != nil {
			apiKeyCount++
			if apiKeyCount > 1 {
				return nil, "", fmt.Errorf("%s.api_key: only one API-key authenticator is supported", name)
			}
			if err := validateAPIKeyAuthenticator(name+".api_key", *authenticator.APIKey, c.Kubernetes != nil); err != nil {
				return nil, "", err
			}
			apiKeyHeader = authenticator.APIKey.Header
		} else {
			if authenticator.MTLS.TrustedCA == nil {
				return nil, "", fmt.Errorf("%s.mtls.trusted_ca is required", name)
			}
			if err := validateTrustedCA(name+".mtls.trusted_ca", authenticator.MTLS.TrustedCA, c.Kubernetes != nil); err != nil {
				return nil, "", err
			}
		}
		authenticators[authenticator.Name] = authenticator
	}
	return authenticators, apiKeyHeader, nil
}

func (c Config) validateAuthenticatorAttributes(apiKeyHeader string) error {
	for i, authenticator := range c.Authenticators {
		if err := validateAuthenticatorAttributes(fmt.Sprintf(authenticatorFieldPathFormat, i), authenticator, apiKeyHeader); err != nil {
			return err
		}
	}
	return nil
}

func (c Config) validateAPIKeyHeaderUse(apiKeyHeader string) error {
	for i, api := range c.APIs {
		for j, route := range api.Routes {
			if route.Processing == nil {
				continue
			}
			for k, header := range route.Processing.RequestHeaders {
				if strings.EqualFold(header.Name, apiKeyHeader) {
					return fmt.Errorf("apis[%d].routes[%d].processing.request_headers[%d].name is reserved for API-key credentials", i, j, k)
				}
			}
		}
	}
	return nil
}

func (c Config) validateAuthorizationPolicies() (map[string]AuthorizationPolicy, error) {
	policies := make(map[string]AuthorizationPolicy, len(c.AuthorizationPolicies))
	for i, policy := range c.AuthorizationPolicies {
		name := fmt.Sprintf("authorization_policies[%d]", i)
		if err := validateGatewayName(name, policy.Name); err != nil {
			return nil, err
		}
		if _, exists := policies[policy.Name]; exists {
			return nil, fmt.Errorf("duplicate authorization policy name %q", policy.Name)
		}
		policies[policy.Name] = policy
	}
	return policies, nil
}

func (c Config) validateAuthorizationPolicyGrants(apis map[string]API, authenticators map[string]Authenticator) error {
	for i, policy := range c.AuthorizationPolicies {
		for j, grant := range policy.Grants {
			name := fmt.Sprintf("authorization_policies[%d].grants[%d]", i, j)
			if err := validateAuthorizationGrant(name, grant, apis, authenticators); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateAuthorizationGrant(name string, grant AuthorizationGrant, apis map[string]API, authenticators map[string]Authenticator) error {
	authenticator, exists := authenticators[grant.Authenticator]
	if !exists {
		return fmt.Errorf("%s.authenticator references unknown authenticator %q", name, grant.Authenticator)
	}
	if len(grant.APIs) == 0 {
		return fmt.Errorf("%s.apis must contain at least one API", name)
	}
	if err := validateUniqueReferences(name+".apis", grant.APIs, apis); err != nil {
		return err
	}
	if len(grant.Attributes) == 0 && authenticator.MTLS == nil {
		return fmt.Errorf("%s.attributes must contain at least one attribute allowlist", name)
	}
	for _, attribute := range slices.Sorted(maps.Keys(grant.Attributes)) {
		if err := validateGrantAttribute(name, grant.Authenticator, attribute, grant.Attributes[attribute], authenticator); err != nil {
			return err
		}
	}
	return nil
}

func validateGrantAttribute(name, authenticatorName, attribute string, values []string, authenticator Authenticator) error {
	if !attributeNamePattern.MatchString(attribute) {
		return fmt.Errorf(attributeNameValidationErrorFormat, name, attribute)
	}
	if !authenticator.providesAttribute(attribute) {
		return fmt.Errorf("%s.attributes references attribute %q not provided by authenticator %q", name, attribute, authenticatorName)
	}
	if len(values) == 0 {
		return fmt.Errorf("%s.attributes.%s must contain at least one allowed value", name, attribute)
	}
	seenValues := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" || strings.TrimSpace(value) != value {
			return fmt.Errorf("%s.attributes.%s values must not be empty or have surrounding whitespace", name, attribute)
		}
		if _, exists := seenValues[value]; exists {
			return fmt.Errorf("%s.attributes.%s contains duplicate value %q", name, attribute, value)
		}
		seenValues[value] = struct{}{}
	}
	return nil
}

func (c Config) hasAuthenticationConfig() bool {
	if len(c.Authenticators) != 0 || len(c.AuthorizationPolicies) != 0 {
		return true
	}
	for _, server := range c.Servers {
		if server.Authentication != nil || server.Authorization != nil {
			return true
		}
	}
	for _, api := range c.APIs {
		for _, route := range api.Routes {
			if route.Processing != nil {
				return true
			}
		}
	}
	return false
}

func copyResourcesOrDefault(values, defaults map[string]string) map[string]string {
	if values == nil {
		values = defaults
	}
	c := make(map[string]string, len(values))
	maps.Copy(c, values)
	return c
}

func defaultValue[T any](value *T, fallback T) *T {
	if value == nil {
		return &fallback
	}
	c := *value
	return &c
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

func validateRouteTimeouts(name string, t *RouteTimeouts) error {
	if t == nil {
		return nil
	}
	for _, value := range []struct {
		name  string
		value *Duration
	}{
		{"response_timeout", t.ResponseTimeout}, {"idle_timeout", t.IdleTimeout}, {maxStreamDurationFieldName, t.MaxStreamDuration},
	} {
		if err := validateDuration(name+"."+value.name, value.value, false); err != nil {
			return err
		}
	}
	return nil
}

func resolveRouteTimeouts(l Listener, api, route *RouteTimeouts) *RouteTimeouts {
	resolved := &RouteTimeouts{
		ResponseTimeout:   new(Duration(30 * time.Second)),
		IdleTimeout:       clonePointer(l.StreamIdleTimeout),
		MaxStreamDuration: clonePointer(l.MaxStreamDuration),
	}
	for _, overrides := range []*RouteTimeouts{api, route} {
		if overrides == nil {
			continue
		}
		if overrides.ResponseTimeout != nil {
			resolved.ResponseTimeout = clonePointer(overrides.ResponseTimeout)
		}
		if overrides.IdleTimeout != nil {
			resolved.IdleTimeout = clonePointer(overrides.IdleTimeout)
		}
		if overrides.MaxStreamDuration != nil {
			resolved.MaxStreamDuration = clonePointer(overrides.MaxStreamDuration)
		}
	}
	return resolved
}

func optionalUint32(value *uint32) *wrapperspb.UInt32Value {
	if value == nil {
		return nil
	}
	return wrapperspb.UInt32(*value)
}

func (o OverloadConfig) toOverloadManager() (*overload.OverloadManager, error) {
	heapConfig, err := packEnvoy(&heap.FixedHeapConfig{MaxHeapSizeBytes: o.MaxHeapBytes})
	if err != nil {
		return nil, fmt.Errorf("encode heap resource monitor: %w", err)
	}
	connectionConfig, err := packEnvoy(&connections.DownstreamConnectionsConfig{MaxActiveDownstreamConnections: int64(o.MaxDownstreamConnections)})
	if err != nil {
		return nil, fmt.Errorf("encode downstream connection resource monitor: %w", err)
	}
	const heapMonitor = "envoy.resource_monitors.fixed_heap"
	manager := &overload.OverloadManager{
		RefreshInterval: durationpb.New(250 * time.Millisecond),
		ResourceMonitors: []*overload.ResourceMonitor{
			{Name: heapMonitor, ConfigType: &overload.ResourceMonitor_TypedConfig{TypedConfig: heapConfig}},
			{Name: "envoy.resource_monitors.global_downstream_max_connections", ConfigType: &overload.ResourceMonitor_TypedConfig{TypedConfig: connectionConfig}},
		},
	}
	for _, action := range []struct {
		name      string
		threshold float64
	}{{"envoy.overload_actions.shrink_heap", *o.HeapShrinkThreshold}, {"envoy.overload_actions.stop_accepting_requests", *o.RequestRejectThreshold}} {
		manager.Actions = append(manager.Actions, &overload.OverloadAction{
			Name:     action.name,
			Triggers: []*overload.Trigger{{Name: heapMonitor, TriggerOneof: &overload.Trigger_Threshold{Threshold: &overload.ThresholdTrigger{Value: action.threshold}}}},
		})
	}
	return manager, nil
}

const requestControlsFilterName = "auth_gateway.request_controls"

var requestControlHeaders = []string{
	"x-envoy-original-path",
	"x-envoy-retry-on",
	"x-envoy-retry-grpc-on",
	"x-envoy-max-retries",
	"x-envoy-hedge-on-per-try-timeout",
	"x-envoy-upstream-rq-timeout-ms",
	"x-envoy-upstream-rq-per-try-timeout-ms",
	"x-envoy-expected-rq-timeout-ms",
	"x-envoy-upstream-alt-stat-name",
	"x-envoy-upstream-stream-duration-ms",
	"x-envoy-upstream-rq-timeout-alt-response",
	"x-envoy-retriable-status-codes",
	"x-envoy-retriable-header-names",
}

func isRequestControlHeader(name string) bool { return slices.Contains(requestControlHeaders, name) }

func requestControlMutations(extra ...string) *headermutation.HeaderMutation {
	mutations := make([]*mutationrules.HeaderMutation, 0, len(requestControlHeaders)+len(extra))
	for _, name := range append(slices.Clone(requestControlHeaders), extra...) {
		mutations = append(mutations, &mutationrules.HeaderMutation{Action: &mutationrules.HeaderMutation_Remove{Remove: name}})
	}
	return &headermutation.HeaderMutation{Mutations: &headermutation.Mutations{RequestMutations: mutations}}
}
