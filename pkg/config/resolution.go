package config

import (
	"fmt"

	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
)

type ResolvedConfig struct {
	gatewayapi.Config
	APIIndex           map[string]gatewayapi.API
	AuthenticatorIndex map[string]gatewayapi.Authenticator
	PolicyIndex        map[string]gatewayapi.AuthorizationPolicy
	ResolvedServers    []ResolvedServer
	UsedAuthenticators map[string]struct{}
	APIKey             gatewayapi.Authenticator
	HasJWT             bool
	HasAPIKey          bool
	HasMTLS            bool
}

type ResolvedServer struct {
	*gatewayapi.Server
	BoundAPIs              []gatewayapi.API
	Authenticators         []gatewayapi.Authenticator
	Policies               []gatewayapi.AuthorizationPolicy
	SelectedAuthenticators map[string]struct{}
	HasJWT                 bool
	HasAPIKey              bool
	Mtls                   gatewayapi.Authenticator
}

func ResolveConfig(input gatewayapi.Config) (ResolvedConfig, error) {
	return validateDefaultedConfig(withDefaultsConfig(input), true)
}

// validateDefaultedConfig expects defaults to have already been applied.
func validateDefaultedConfig(c gatewayapi.Config, resolveTimeouts bool) (ResolvedConfig, error) {
	effective := ResolvedConfig{Config: c}
	if err := validateConfig(&effective); err != nil {
		return ResolvedConfig{}, err
	}
	for i := range c.APIs {
		api := &c.APIs[i]
		for j := range api.Routes {
			timers := resolveRouteTimeouts(c.Listener, api.Timeouts, api.Routes[j].Timeouts)
			if *timers.ResponseTimeout > *timers.MaxStreamDuration {
				field := fmt.Sprintf("apis[%d].routes[%d].timeouts", i, j)
				return ResolvedConfig{}, fmt.Errorf("%s.response_timeout (%s) must not exceed effective %s.max_stream_duration (%s)", field, timers.ResponseTimeout, field, timers.MaxStreamDuration)
			}
			if resolveTimeouts {
				api.Routes[j].Timeouts = timers
			}
		}
	}
	effective.UsedAuthenticators = make(map[string]struct{})
	for _, server := range effective.ResolvedServers {
		for _, authenticator := range server.Authenticators {
			effective.UsedAuthenticators[authenticator.Name] = struct{}{}
		}
		effective.HasJWT = effective.HasJWT || server.HasJWT
		effective.HasAPIKey = effective.HasAPIKey || server.HasAPIKey
		effective.HasMTLS = effective.HasMTLS || server.UsesMTLS()
	}
	for _, authenticator := range c.Authenticators {
		if authenticator.APIKey != nil {
			effective.APIKey = authenticator
			break
		}
	}
	return effective, nil
}

func validateConfig(c *ResolvedConfig) error {
	metricsEnabled := c.Kubernetes != nil && EnabledObservabilityMetrics(c.Observability.Metrics)
	tracingEnabled := EnabledObservabilityTracing(c.Observability.Tracing)
	if err := validateBaseSettingsConfig(c.Config, metricsEnabled, tracingEnabled); err != nil {
		return err
	}
	var err error
	c.APIIndex, err = validateAPIsConfig(c.Config)
	if err != nil {
		return err
	}
	c.ResolvedServers, err = validateServersConfig(c.Config, c.APIIndex)
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

func resolveAuthentication(c *ResolvedConfig) error {
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
	c.AuthenticatorIndex = authenticators
	c.PolicyIndex = policies
	if err := validateAuthorizationPolicyGrantsConfig(c.Config, c.APIIndex, authenticators); err != nil {
		return err
	}
	if err := resolveServerAuthentication(c); err != nil {
		return err
	}
	return validatePermissiveJWTIssuerBindings(c.Servers, authenticators)
}

func resolveServerAuthentication(c *ResolvedConfig) error {
	for i := range c.ResolvedServers {
		server := &c.ResolvedServers[i]
		name := fmt.Sprintf(ServerFieldPathFormat, i)
		if server.Authentication != nil {
			selected, err := validateSelection(name+".authentication", server.Authentication.AnyOf, server.Authentication.AllOf, c.AuthenticatorIndex)
			if err != nil {
				return err
			}
			server.SelectedAuthenticators = make(map[string]struct{}, len(selected))
			jwtCount, mtlsCount := 0, 0
			for _, selectedName := range selected {
				authenticator := c.AuthenticatorIndex[selectedName]
				server.Authenticators = append(server.Authenticators, authenticator)
				server.SelectedAuthenticators[selectedName] = struct{}{}
				server.HasJWT = server.HasJWT || authenticator.JWT != nil
				server.HasAPIKey = server.HasAPIKey || authenticator.APIKey != nil
				if authenticator.MTLS != nil {
					mtlsCount++
					server.Mtls = authenticator
				}
			}
			if mtlsCount > 1 {
				return fmt.Errorf("%s.authentication cannot contain more than one mTLS authenticator", name)
			}
			if mtlsCount > 0 && server.TLSConfig == nil {
				return fmt.Errorf("%s.authentication requires tls_config for mTLS", name)
			}
			for _, selectedName := range server.Authentication.AllOf {
				if c.AuthenticatorIndex[selectedName].JWT != nil {
					jwtCount++
				}
			}
			if jwtCount > 1 {
				return fmt.Errorf("%s.authentication.all_of cannot contain more than one JWT authenticator", name)
			}
			if err := validateUniqueIssuerBindings(name+".authentication", selected, c.AuthenticatorIndex); err != nil {
				return err
			}
		}
		if server.Authorization != nil {
			if server.Authentication == nil {
				return fmt.Errorf("%s.authorization requires authentication", name)
			}
			selected, err := validateSelection(name+".authorization", server.Authorization.AnyOf, server.Authorization.AllOf, c.PolicyIndex)
			if err != nil {
				return err
			}
			for _, policyName := range selected {
				server.Policies = append(server.Policies, c.PolicyIndex[policyName])
			}
		}
		if err := validateRouteAttributeSources(name, *server.Server, server.BoundAPIs, c.AuthenticatorIndex); err != nil {
			return err
		}
		if err := validateFaultAttributeSources(name, *server); err != nil {
			return err
		}
	}
	return nil
}

func (c ResolvedConfig) CAMounts() []gatewayapi.CAConfigMap {
	var mounts []gatewayapi.CAConfigMap
	seen := map[gatewayapi.CAConfigMap]bool{}
	add := func(ca *gatewayapi.TrustedCA) {
		if ca != nil && ca.ConfigMap != nil && !seen[*ca.ConfigMap] {
			mounts = append(mounts, *ca.ConfigMap)
			seen[*ca.ConfigMap] = true
		}
	}
	for _, authenticator := range c.Authenticators {
		if authenticator.JWT != nil && c.AuthenticatorUsed(authenticator.Name) {
			add(authenticator.JWT.JWKS.TrustedCA)
		}
		if authenticator.MTLS != nil && c.AuthenticatorUsed(authenticator.Name) {
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

func (c ResolvedConfig) APIKeyAuthenticator() (gatewayapi.Authenticator, bool) {
	return c.APIKey, c.APIKey.APIKey != nil
}

func (c ResolvedConfig) UsesAPIKeys() bool { return c.HasAPIKey }

func (c ResolvedConfig) UsesJWT() bool { return c.HasJWT }

func (c ResolvedConfig) UsesMTLS() bool { return c.HasMTLS }

func (c ResolvedConfig) AuthenticatorUsed(name string) bool {
	_, used := c.UsedAuthenticators[name]
	return used
}

func (s ResolvedServer) UsesMTLS() bool { return s.Mtls.MTLS != nil }

func (s ResolvedServer) MixedAnyOf() bool {
	if s.Authentication == nil || s.Authentication.AnyOf == nil {
		return false
	}
	types := 0
	for _, used := range []bool{s.HasJWT, s.HasAPIKey, s.UsesMTLS()} {
		if used {
			types++
		}
	}
	return types > 1
}

func (s ResolvedServer) SelectsAuthenticator(name string) bool {
	_, selected := s.SelectedAuthenticators[name]
	return selected
}
