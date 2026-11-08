package gateway

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	yaml "go.yaml.in/yaml/v3"
)

const (
	configVersion            = 1
	defaultNodeID            = "auth-gateway"
	defaultNodeCluster       = "auth-gateway"
	invalidControlCharacters = "\r\n\x00"
)

var (
	apiNamePattern = regexp.MustCompile("^[a-z][a-z0-9-]{0,52}$")
)

type resolvedConfig struct {
	gatewayapi.Config
	apiIndex           map[string]gatewayapi.API
	authenticatorIndex map[string]gatewayapi.Authenticator
	policyIndex        map[string]gatewayapi.AuthorizationPolicy
	servers            []resolvedServer
	usedAuthenticators map[string]struct{}
	apiKey             gatewayapi.Authenticator
	hasJWT             bool
	hasAPIKey          bool
	hasMTLS            bool
}

type resolvedServer struct {
	*gatewayapi.Server
	apis                   []gatewayapi.API
	authenticators         []gatewayapi.Authenticator
	policies               []gatewayapi.AuthorizationPolicy
	selectedAuthenticators map[string]struct{}
	hasJWT                 bool
	hasAPIKey              bool
	mtls                   gatewayapi.Authenticator
}

func validateAPI(name string, api gatewayapi.API, hasKubernetes bool) error {
	if !validHost(api.Upstream.Address) {
		return fmt.Errorf("%s.upstream.address must be an IP address or DNS name", name)
	}
	if api.Upstream.Port == 0 || api.Upstream.Port > 65535 {
		return fmt.Errorf("%s.upstream.port must be between 1 and 65535", name)
	}
	if err := validateUpstream(api.Upstream, name+".upstream", hasKubernetes); err != nil {
		return err
	}
	if err := validateRouteTimeouts(name+".timeouts", api.Timeouts); err != nil {
		return err
	}
	if err := validateAPIMetrics(name+".metrics", api.Metrics); err != nil {
		return err
	}
	if api.AdmissionControl != nil {
		if err := validateAdmissionControlConfig(*api.AdmissionControl, name+".admission_control"); err != nil {
			return err
		}
	}
	if api.FaultInjection != nil {
		if err := validateFaultInjectionConfig(*api.FaultInjection, name+".fault_injection"); err != nil {
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

func cloneAPI(a gatewayapi.API) gatewayapi.API {
	a.Routes = cloneSlice(a.Routes, cloneRoute)
	a.Upstream = cloneUpstream(a.Upstream)
	a.Metrics = cloneConfigPointer(a.Metrics, cloneAPIMetrics)
	a.AdmissionControl = cloneConfigPointer(a.AdmissionControl, cloneAdmissionControlConfig)
	a.FaultInjection = cloneConfigPointer(a.FaultInjection, cloneFaultInjectionConfig)
	if a.CircuitBreakers != nil {
		circuitBreakers := cloneCircuitBreakerConfig(a.CircuitBreakers)
		a.CircuitBreakers = &circuitBreakers
	}
	a.Timeouts = cloneConfigPointer(a.Timeouts, cloneRouteTimeouts)
	return a
}

func defaultValue[T any](value *T, fallback T) *T {
	if value == nil {
		return &fallback
	}
	c := *value
	return &c
}

func cloneSlice[T any](values []T, clone func(T) T) []T {
	if values == nil {
		return nil
	}
	cloned := make([]T, len(values))
	for index, value := range values {
		cloned[index] = clone(value)
	}
	return cloned
}

func cloneConfigPointer[T any](value *T, clone func(T) T) *T {
	if value == nil {
		return nil
	}
	cloned := clone(*value)
	return &cloned
}

func clonePointer[T any](value *T) *T {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
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
	if c.Version != configVersion {
		return fmt.Errorf("version must be %d", configVersion)
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
	c = cloneConfig(c)
	for i := range c.Authenticators {
		c.Authenticators[i] = withDefaultsAuthenticator(c.Authenticators[i])
	}
	if c.Node.ID == "" {
		c.Node.ID = defaultNodeID
	}
	if c.Node.Cluster == "" {
		c.Node.Cluster = defaultNodeCluster
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
		kubernetes := withDefaultsKubernetes(*c.Kubernetes, hasHTTPSConfig(c))
		c.Kubernetes = &kubernetes
	}
	return c
}

func cloneConfig(c gatewayapi.Config) gatewayapi.Config {
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

func resolveConfig(input gatewayapi.Config) (resolvedConfig, error) {
	return validateDefaultedConfig(withDefaultsConfig(input), true)
}

// validateDefaultedConfig expects defaults to have already been applied.
func validateDefaultedConfig(c gatewayapi.Config, resolveTimeouts bool) (resolvedConfig, error) {
	effective := resolvedConfig{Config: c}
	if err := validateConfig(&effective); err != nil {
		return resolvedConfig{}, err
	}
	for i := range c.APIs {
		api := &c.APIs[i]
		for j := range api.Routes {
			timers := resolveRouteTimeouts(c.Listener, api.Timeouts, api.Routes[j].Timeouts)
			if *timers.ResponseTimeout > *timers.MaxStreamDuration {
				field := fmt.Sprintf("apis[%d].routes[%d].timeouts", i, j)
				return resolvedConfig{}, fmt.Errorf("%s.response_timeout (%s) must not exceed effective %s.max_stream_duration (%s)", field, timers.ResponseTimeout, field, timers.MaxStreamDuration)
			}
			if resolveTimeouts {
				api.Routes[j].Timeouts = timers
			}
		}
	}
	effective.usedAuthenticators = make(map[string]struct{})
	for _, server := range effective.servers {
		for _, authenticator := range server.authenticators {
			effective.usedAuthenticators[authenticator.Name] = struct{}{}
		}
		effective.hasJWT = effective.hasJWT || server.hasJWT
		effective.hasAPIKey = effective.hasAPIKey || server.hasAPIKey
		effective.hasMTLS = effective.hasMTLS || server.usesMTLS()
	}
	for _, authenticator := range c.Authenticators {
		if authenticator.APIKey != nil {
			effective.apiKey = authenticator
			break
		}
	}
	return effective, nil
}

func validateConfig(c *resolvedConfig) error {
	metricsEnabled := c.Kubernetes != nil && enabledObservabilityMetrics(c.Observability.Metrics)
	tracingEnabled := enabledObservabilityTracing(c.Observability.Tracing)
	if err := validateBaseSettingsConfig(c.Config, metricsEnabled, tracingEnabled); err != nil {
		return err
	}
	var err error
	c.apiIndex, err = validateAPIsConfig(c.Config)
	if err != nil {
		return err
	}
	c.servers, err = validateServersConfig(c.Config, c.apiIndex)
	if err != nil {
		return err
	}
	if err := resolveAuthentication(c); err != nil {
		return err
	}
	if c.Kubernetes != nil {
		if err := validateKubernetesConfig(c.Config, metricsEnabled, tracingEnabled); err != nil {
			return err
		}
	}
	if c.Overload != nil {
		return validateOverloadConfig(*c.Overload, c.Kubernetes)
	}
	return nil
}

func resolveAuthentication(c *resolvedConfig) error {
	authenticators, apiKeyHeader, err := validateAuthenticatorsConfig(c.Config)
	if err != nil {
		return err
	}
	if err := validateAuthenticatorAttributesConfig(c.Config, apiKeyHeader); err != nil {
		return err
	}
	if apiKeyHeader != "" {
		if err := validateAPIKeyHeaderUseConfig(c.Config, apiKeyHeader); err != nil {
			return err
		}
	}
	if err := validateFaultHeaderReferences(c.APIs, apiKeyHeader); err != nil {
		return err
	}
	if err := validateMetricAttributeReferences(c.APIs, authenticators); err != nil {
		return err
	}
	policies, err := validateAuthorizationPoliciesConfig(c.Config)
	if err != nil {
		return err
	}
	c.authenticatorIndex = authenticators
	c.policyIndex = policies
	if err := validateAuthorizationPolicyGrantsConfig(c.Config, c.apiIndex, authenticators); err != nil {
		return err
	}
	if err := resolveServerAuthentication(c); err != nil {
		return err
	}
	return validatePermissiveJWTIssuerBindings(c.Servers, authenticators)
}

func resolveServerAuthentication(c *resolvedConfig) error {
	for i := range c.servers {
		server := &c.servers[i]
		name := fmt.Sprintf(serverFieldPathFormat, i)
		if server.Authentication != nil {
			selected, err := validateSelection(name+".authentication", server.Authentication.AnyOf, server.Authentication.AllOf, c.authenticatorIndex)
			if err != nil {
				return err
			}
			server.selectedAuthenticators = make(map[string]struct{}, len(selected))
			jwtCount, mtlsCount := 0, 0
			for _, selectedName := range selected {
				authenticator := c.authenticatorIndex[selectedName]
				server.authenticators = append(server.authenticators, authenticator)
				server.selectedAuthenticators[selectedName] = struct{}{}
				server.hasJWT = server.hasJWT || authenticator.JWT != nil
				server.hasAPIKey = server.hasAPIKey || authenticator.APIKey != nil
				if authenticator.MTLS != nil {
					mtlsCount++
					server.mtls = authenticator
				}
			}
			if mtlsCount > 1 {
				return fmt.Errorf("%s.authentication cannot contain more than one mTLS authenticator", name)
			}
			if mtlsCount > 0 && server.TLSConfig == nil {
				return fmt.Errorf("%s.authentication requires tls_config for mTLS", name)
			}
			for _, selectedName := range server.Authentication.AllOf {
				if c.authenticatorIndex[selectedName].JWT != nil {
					jwtCount++
				}
			}
			if jwtCount > 1 {
				return fmt.Errorf("%s.authentication.all_of cannot contain more than one JWT authenticator", name)
			}
			if err := validateUniqueIssuerBindings(name+".authentication", selected, c.authenticatorIndex); err != nil {
				return err
			}
		}
		if server.Authorization != nil {
			if server.Authentication == nil {
				return fmt.Errorf("%s.authorization requires authentication", name)
			}
			selected, err := validateSelection(name+".authorization", server.Authorization.AnyOf, server.Authorization.AllOf, c.policyIndex)
			if err != nil {
				return err
			}
			for _, policyName := range selected {
				server.policies = append(server.policies, c.policyIndex[policyName])
			}
		}
		if err := validateRouteAttributeSources(name, *server.Server, server.apis, c.authenticatorIndex); err != nil {
			return err
		}
		if err := validateFaultAttributeSources(name, *server); err != nil {
			return err
		}
	}
	return nil
}

func (c resolvedConfig) caMounts() []gatewayapi.CAConfigMap {
	var mounts []gatewayapi.CAConfigMap
	seen := map[gatewayapi.CAConfigMap]bool{}
	add := func(ca *gatewayapi.TrustedCA) {
		if ca != nil && ca.ConfigMap != nil && !seen[*ca.ConfigMap] {
			mounts = append(mounts, *ca.ConfigMap)
			seen[*ca.ConfigMap] = true
		}
	}
	for _, authenticator := range c.Authenticators {
		if authenticator.JWT != nil && c.authenticatorUsed(authenticator.Name) {
			add(authenticator.JWT.JWKS.TrustedCA)
		}
		if authenticator.MTLS != nil && c.authenticatorUsed(authenticator.Name) {
			add(authenticator.MTLS.TrustedCA)
		}
	}
	for _, api := range c.APIs {
		if api.Upstream.TLSConfig != nil {
			add(api.Upstream.TLSConfig.TrustedCA)
		}
	}
	return mounts
}

func (c resolvedConfig) apiKeyAuthenticator() (gatewayapi.Authenticator, bool) {
	return c.apiKey, c.apiKey.APIKey != nil
}

func (c resolvedConfig) usesAPIKeys() bool { return c.hasAPIKey }

func (c resolvedConfig) usesJWT() bool { return c.hasJWT }

func (c resolvedConfig) usesMTLS() bool { return c.hasMTLS }

func (c resolvedConfig) authenticatorUsed(name string) bool {
	_, used := c.usedAuthenticators[name]
	return used
}

func (s resolvedServer) usesMTLS() bool { return s.mtls.MTLS != nil }

func (s resolvedServer) mixedAnyOf() bool {
	if s.Authentication == nil || s.Authentication.AnyOf == nil {
		return false
	}
	types := 0
	for _, used := range []bool{s.hasJWT, s.hasAPIKey, s.usesMTLS()} {
		if used {
			types++
		}
	}
	return types > 1
}

func (s resolvedServer) selectsAuthenticator(name string) bool {
	_, selected := s.selectedAuthenticators[name]
	return selected
}
