package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"path"
	"regexp"
	"strings"

	yaml "go.yaml.in/yaml/v3"
	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	configVersion            = 1
	defaultNodeID            = "auth-gateway"
	defaultNodeCluster       = "auth-gateway"
	invalidControlCharacters = "\r\n\x00"
)

var apiNamePattern = regexp.MustCompile("^[a-z][a-z0-9-]{0,52}$")

// Config describes gateway behavior, observability, and optional Kubernetes output.
type Config struct {
	Version               int                   `yaml:"version"`
	Node                  EnvoyNode             `yaml:"node,omitempty"`
	Listener              Listener              `yaml:"listener"`
	Overload              *OverloadConfig       `yaml:"overload,omitempty"`
	Authenticators        []Authenticator       `yaml:"authenticators,omitempty"`
	AuthorizationPolicies []AuthorizationPolicy `yaml:"authorization_policies,omitempty"`
	Servers               []Server              `yaml:"servers"`
	APIs                  []API                 `yaml:"apis"`
	Observability         ObservabilityConfig   `yaml:"observability,omitempty"`
	Kubernetes            *Kubernetes           `yaml:"kubernetes,omitempty"`
}

// EnvoyNode describes the identity and logical cluster of this Envoy instance.
type EnvoyNode struct {
	ID      string `yaml:"id,omitempty"`
	Cluster string `yaml:"cluster,omitempty"`
}

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

func validHost(value string) bool {
	return net.ParseIP(value) != nil || validDNSHost(value)
}

func validDNSHost(value string) bool {
	return net.ParseIP(value) == nil && len(validation.IsDNS1123Subdomain(value)) == 0
}

func (c Config) clone() Config {
	c.Listener = c.Listener.clone()
	c.Overload = cloneConfigPointer(c.Overload)
	c.Authenticators = cloneSlice(c.Authenticators)
	c.AuthorizationPolicies = cloneSlice(c.AuthorizationPolicies)
	c.Servers = cloneSlice(c.Servers)
	c.APIs = cloneSlice(c.APIs)
	c.Observability = c.Observability.clone()
	c.Kubernetes = cloneConfigPointer(c.Kubernetes)
	return c
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

func (c Config) validateAuthenticatorAttributes(apiKeyHeader string) error {
	for i, authenticator := range c.Authenticators {
		if err := validateAuthenticatorAttributes(fmt.Sprintf(authenticatorFieldPathFormat, i), authenticator, apiKeyHeader); err != nil {
			return err
		}
	}
	return nil
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

func (c Config) hasRequestMetrics() bool {
	for _, api := range c.APIs {
		if api.Metrics != nil {
			return true
		}
	}
	return false
}

func (c Config) requestMetricName() string {
	if c.Observability.Metrics.CustomMetricName != nil {
		return *c.Observability.Metrics.CustomMetricName
	}
	return defaultRequestMetricCounterName
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
