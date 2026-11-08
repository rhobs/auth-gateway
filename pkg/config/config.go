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

	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	yaml "go.yaml.in/yaml/v3"
	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	ConfigVersion            = 1
	DefaultNodeID            = "auth-gateway"
	DefaultNodeCluster       = "auth-gateway"
	InvalidControlCharacters = "\r\n\x00"
)

var ApiNamePattern = regexp.MustCompile("^[a-z][a-z0-9-]{0,52}$")

func validateGatewayName(fieldPath, value string) error {
	if !ApiNamePattern.MatchString(value) {
		return fmt.Errorf("%s.name must start with a lowercase letter and contain only lowercase letters, numbers, or hyphens", fieldPath)
	}
	return nil
}

// Load decodes one strict YAML document, applies defaults, and validates it.
// API and route timeout overrides stay as supplied, including omitted values.
// Validation checks their effective values; generation resolves them on a copy.
// On failure, Load returns the zero Config and a non-nil error.
func Load(r io.Reader) (gatewayapi.Config, error) {
	if r == nil {
		return gatewayapi.Config{}, fmt.Errorf("read gateway configuration: input is nil")
	}

	data, err := io.ReadAll(r)
	if err != nil {
		return gatewayapi.Config{}, fmt.Errorf("read gateway configuration: %w", err)
	}
	var c gatewayapi.Config
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&c); err != nil {
		var durationError *gatewayapi.DurationYAMLError
		if errors.As(err, &durationError) {
			var document yaml.Node
			if yaml.Unmarshal(data, &document) == nil {
				if field := yamlPathAtPosition(&document, durationError.Line, durationError.Column, ""); field != "" {
					return gatewayapi.Config{}, fmt.Errorf("%s: %w", field, err)
				}
			}
		}
		return gatewayapi.Config{}, fmt.Errorf("read gateway configuration: %w", err)
	}

	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return gatewayapi.Config{}, fmt.Errorf("read gateway configuration: expected exactly one YAML document")
	} else if err != io.EOF {
		return gatewayapi.Config{}, fmt.Errorf("read gateway configuration: %w", err)
	}

	c = withDefaultsConfig(c)
	if _, err := validateDefaultedConfig(c, false); err != nil {
		return gatewayapi.Config{}, err
	}
	return c, nil
}

// Validate checks whether c follows the public configuration contract.
// Use it when building a Config in Go instead of loading YAML with Load.
func Validate(c gatewayapi.Config) error {
	_, err := validateDefaultedConfig(withDefaultsConfig(c), false)
	return err
}

func validateBaseSettingsConfig(c gatewayapi.Config, metricsEnabled, tracingEnabled bool) error {
	if c.Version != ConfigVersion {
		return fmt.Errorf("version must be %d", ConfigVersion)
	}
	if strings.TrimSpace(c.Node.ID) == "" {
		return fmt.Errorf("node.id must not be empty")
	}
	if strings.TrimSpace(c.Node.Cluster) == "" {
		return fmt.Errorf("node.cluster must not be empty")
	}
	if err := validateListener(c.Listener, metricsEnabled, tracingEnabled); err != nil {
		return err
	}
	if err := validateObservabilityMetrics(c.Observability.Metrics); err != nil {
		return err
	}
	if err := validateObservabilityTracing(c.Observability.Tracing); err != nil {
		return err
	}
	return nil
}

func withDefaultsConfig(c gatewayapi.Config) gatewayapi.Config {
	c = CloneConfig(c)
	for i := range c.Authenticators {
		c.Authenticators[i] = withDefaultsAuthenticator(c.Authenticators[i])
	}
	if c.Node.ID == "" {
		c.Node.ID = DefaultNodeID
	}
	if c.Node.Cluster == "" {
		c.Node.Cluster = DefaultNodeCluster
	}
	c.Listener = withDefaultsListener(c.Listener)
	if c.Overload != nil {
		overload := withDefaultsOverloadConfig(*c.Overload)
		c.Overload = &overload
	}
	c.Observability = withDefaultsObservabilityConfig(c.Observability, c.Node.Cluster)
	for i := range c.Servers {
		if c.Servers[i].TLSConfig != nil {
			tlsConfig := withDefaultsServerTLS(*c.Servers[i].TLSConfig)
			c.Servers[i].TLSConfig = &tlsConfig
		}
	}
	for i := range c.APIs {
		c.APIs[i].Upstream = withDefaultsUpstream(c.APIs[i].Upstream)
	}
	for i := range c.APIs {
		c.APIs[i].CircuitBreakers = withDefaultsCircuitBreakerConfig(c.APIs[i].CircuitBreakers)
	}
	if c.Kubernetes != nil {
		kubernetes := withDefaultsKubernetes(*c.Kubernetes, HasHTTPSConfig(c))
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

func CloneConfig(c gatewayapi.Config) gatewayapi.Config {
	c.Listener = cloneListener(c.Listener)
	c.Overload = cloneConfigPointer(c.Overload, cloneOverloadConfig)
	c.Authenticators = cloneSlice(c.Authenticators, cloneAuthenticator)
	c.AuthorizationPolicies = cloneSlice(c.AuthorizationPolicies, cloneAuthorizationPolicy)
	c.Servers = cloneSlice(c.Servers, cloneServer)
	c.APIs = cloneSlice(c.APIs, cloneAPI)
	c.Observability = cloneObservabilityConfig(c.Observability)
	c.Kubernetes = cloneConfigPointer(c.Kubernetes, cloneKubernetes)
	return c
}

func validateAPIsConfig(c gatewayapi.Config) (map[string]gatewayapi.API, error) {
	if len(c.APIs) == 0 {
		return nil, fmt.Errorf("at least one API must be configured")
	}
	names := make(map[string]gatewayapi.API, len(c.APIs))
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

func validateAuthenticatorAttributesConfig(c gatewayapi.Config, apiKeyHeader string) error {
	for i, authenticator := range c.Authenticators {
		if err := validateAuthenticatorAttributes(fmt.Sprintf(AuthenticatorFieldPathFormat, i), authenticator, apiKeyHeader); err != nil {
			return err
		}
	}
	return nil
}

func validateAuthenticatorsConfig(c gatewayapi.Config) (map[string]gatewayapi.Authenticator, string, error) {
	authenticators := make(map[string]gatewayapi.Authenticator, len(c.Authenticators))
	apiKeyCount := 0
	apiKeyHeader := ""
	for i, authenticator := range c.Authenticators {
		name := fmt.Sprintf(AuthenticatorFieldPathFormat, i)
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
			if err := validateJWKSConfig(authenticator.JWT.JWKS, name+".jwt.jwks", c.Kubernetes != nil); err != nil {
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

func HasAuthenticationConfigConfig(c gatewayapi.Config) bool {
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

func validateAuthorizationPoliciesConfig(c gatewayapi.Config) (map[string]gatewayapi.AuthorizationPolicy, error) {
	policies := make(map[string]gatewayapi.AuthorizationPolicy, len(c.AuthorizationPolicies))
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

func validateAuthorizationPolicyGrantsConfig(c gatewayapi.Config, apis map[string]gatewayapi.API, authenticators map[string]gatewayapi.Authenticator) error {
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

func validateKubernetesConfig(c gatewayapi.Config, metricsEnabled, tracingEnabled bool) error {
	k := c.Kubernetes
	if strings.TrimSpace(k.Image) == "" || strings.ContainsAny(k.Image, ImageWhitespaceCharacters) {
		return fmt.Errorf("kubernetes.image must be an image reference")
	}
	if err := validateOTelCollectorImage(k.OTelCollectorImage, metricsEnabled || tracingEnabled); err != nil {
		return err
	}
	if k.Replicas != nil && *k.Replicas < 0 {
		return fmt.Errorf("kubernetes.replicas must not be negative")
	}
	if err := validateKubernetesServicePortsConfig(c, metricsEnabled); err != nil {
		return err
	}
	if k.EnvoyConcurrency != nil && *k.EnvoyConcurrency == 0 {
		return fmt.Errorf("kubernetes.envoy_concurrency must be positive")
	}
	if err := validateKubernetesResourceRequirements(KubernetesResourcesFieldPath, k.Resources); err != nil {
		return err
	}
	return validateKubernetesMetrics(k.Metrics)
}

func validateKubernetesServicePortsConfig(c gatewayapi.Config, metricsEnabled bool) error {
	k := c.Kubernetes
	if *k.ServicePort < 1 || *k.ServicePort > 65535 {
		if HasHTTPConfig(c) {
			return fmt.Errorf("kubernetes.service_port must be between 1 and 65535")
		}
	}
	if HasHTTPConfig(c) {
		if err := validateOTelMetricsServicePort("service_port", *k.ServicePort, metricsEnabled); err != nil {
			return err
		}
	}
	if HasHTTPSConfig(c) {
		if err := validateTLSMountsConfig(c); err != nil {
			return err
		}
		if *k.HTTPSServicePort < 1 || *k.HTTPSServicePort > 65535 {
			return fmt.Errorf("kubernetes.https_service_port must be between 1 and 65535")
		}
		if err := validateOTelMetricsServicePort("https_service_port", *k.HTTPSServicePort, metricsEnabled); err != nil {
			return err
		}
		if HasHTTPConfig(c) && *k.HTTPSServicePort == *k.ServicePort {
			return fmt.Errorf("kubernetes.service_port and kubernetes.https_service_port must differ")
		}
	} else if k.HTTPSServicePort != nil {
		return fmt.Errorf("kubernetes.https_service_port requires an HTTPS server")
	}
	return nil
}

func HasRequestMetricsConfig(c gatewayapi.Config) bool {
	for _, api := range c.APIs {
		if api.Metrics != nil {
			return true
		}
	}
	return false
}

func RequestMetricNameConfig(c gatewayapi.Config) string {
	if c.Observability.Metrics.CustomMetricName != nil {
		return *c.Observability.Metrics.CustomMetricName
	}
	return DefaultRequestMetricCounterName
}

func validateAPIKeyHeaderUseConfig(c gatewayapi.Config, apiKeyHeader string) error {
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

func validateServersConfig(c gatewayapi.Config, apis map[string]gatewayapi.API) ([]ResolvedServer, error) {
	if len(c.Servers) == 0 {
		return nil, fmt.Errorf("servers must contain at least one server")
	}
	servers := make([]ResolvedServer, len(c.Servers))
	hosts := make(map[string]int, len(c.Servers))
	for i, server := range c.Servers {
		name := fmt.Sprintf(ServerFieldPathFormat, i)
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
		bound, err := boundAPIsServer(server, apis)
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
		servers[i] = ResolvedServer{Server: &c.Servers[i], BoundAPIs: bound}
	}
	return servers, nil
}

func TlsMountsConfig(c gatewayapi.Config) []ServerTLSMount {
	var mounts []ServerTLSMount
	seen := make(map[gatewayapi.ServerTLS]struct{})
	for i, server := range c.Servers {
		if server.TLSConfig == nil {
			continue
		}
		binding := *server.TLSConfig
		if _, exists := seen[binding]; exists {
			continue
		}
		seen[binding] = struct{}{}
		mounts = append(mounts, ServerTLSMount{ServerIndex: i, Config: binding})
	}
	return mounts
}

func validateTLSMountsConfig(c gatewayapi.Config) error {
	mounts := TlsMountsConfig(c)
	for i, mount := range mounts {
		name := fmt.Sprintf("servers[%d].tls_config", mount.ServerIndex)
		if mount.Config.Secret == "" {
			return fmt.Errorf("%s.secret is required when generating Kubernetes resources", name)
		}
		directory := path.Dir(mount.Config.Certificate)
		for _, reserved := range []string{ConfigDirectory, CollectorConfigDirectory, CaDirectory} {
			if directoriesOverlap(directory, reserved) {
				return fmt.Errorf("%s certificate directory %q overlaps configuration directory %q", name, directory, reserved)
			}
		}
		for _, previous := range mounts[:i] {
			if directoriesOverlap(directory, path.Dir(previous.Config.Certificate)) {
				return fmt.Errorf("%s certificate directory overlaps servers[%d].tls_config", name, previous.ServerIndex)
			}
		}
	}
	return nil
}

func HasHTTPConfig(c gatewayapi.Config) bool {
	for _, server := range c.Servers {
		if server.TLSConfig == nil {
			return true
		}
	}
	return false
}

func HasHTTPSConfig(c gatewayapi.Config) bool {
	for _, server := range c.Servers {
		if server.TLSConfig != nil {
			return true
		}
	}
	return false
}
