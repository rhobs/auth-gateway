package config

import "fmt"

type effectiveConfig struct {
	Config
	apiIndex           map[string]API
	authenticatorIndex map[string]Authenticator
	policyIndex        map[string]AuthorizationPolicy
	servers            []resolvedServer
	usedAuthenticators map[string]struct{}
	apiKey             Authenticator
	hasJWT             bool
	hasAPIKey          bool
	hasMTLS            bool
}

type resolvedServer struct {
	*Server
	apis                   []API
	authenticators         []Authenticator
	policies               []AuthorizationPolicy
	selectedAuthenticators map[string]struct{}
	hasJWT                 bool
	hasAPIKey              bool
	mtls                   Authenticator
}

func resolveConfig(input Config) (effectiveConfig, error) {
	return validateDefaultedConfig(input.withDefaults(), true)
}

// validateDefaultedConfig expects defaults to have already been applied.
func validateDefaultedConfig(c Config, resolveTimeouts bool) (effectiveConfig, error) {
	effective := effectiveConfig{Config: c}
	if err := validateConfig(&effective); err != nil {
		return effectiveConfig{}, err
	}
	for i := range c.APIs {
		api := &c.APIs[i]
		for j := range api.Routes {
			timers := resolveRouteTimeouts(c.Listener, api.Timeouts, api.Routes[j].Timeouts)
			if *timers.ResponseTimeout > *timers.MaxStreamDuration {
				field := fmt.Sprintf("apis[%d].routes[%d].timeouts", i, j)
				return effectiveConfig{}, fmt.Errorf("%s.response_timeout (%s) must not exceed effective %s.max_stream_duration (%s)", field, timers.ResponseTimeout, field, timers.MaxStreamDuration)
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

func validateConfig(c *effectiveConfig) error {
	metricsEnabled := c.Kubernetes != nil && c.Observability.Metrics.enabled()
	tracingEnabled := c.Observability.Tracing.enabled()
	if err := c.validateBaseSettings(metricsEnabled, tracingEnabled); err != nil {
		return err
	}
	var err error
	c.apiIndex, err = c.validateAPIs()
	if err != nil {
		return err
	}
	c.servers, err = c.validateServers(c.apiIndex)
	if err != nil {
		return err
	}
	if err := resolveAuthentication(c); err != nil {
		return err
	}
	if c.Kubernetes != nil {
		if err := c.validateKubernetes(metricsEnabled, tracingEnabled); err != nil {
			return err
		}
	}
	if c.Overload != nil {
		return c.Overload.validate(c.Kubernetes)
	}
	return nil
}

func resolveAuthentication(c *effectiveConfig) error {
	authenticators, apiKeyHeader, err := c.validateAuthenticators()
	if err != nil {
		return err
	}
	if err := c.validateAuthenticatorAttributes(apiKeyHeader); err != nil {
		return err
	}
	if apiKeyHeader != "" {
		if err := c.validateAPIKeyHeaderUse(apiKeyHeader); err != nil {
			return err
		}
	}
	if err := validateMetricAttributeReferences(c.APIs, authenticators); err != nil {
		return err
	}
	policies, err := c.validateAuthorizationPolicies()
	if err != nil {
		return err
	}
	c.authenticatorIndex = authenticators
	c.policyIndex = policies
	if err := c.validateAuthorizationPolicyGrants(c.apiIndex, authenticators); err != nil {
		return err
	}
	if err := resolveServerAuthentication(c); err != nil {
		return err
	}
	return validatePermissiveJWTIssuerBindings(c.Servers, authenticators)
}

func resolveServerAuthentication(c *effectiveConfig) error {
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
	}
	return nil
}

func (c effectiveConfig) caMounts() []CAConfigMap {
	var mounts []CAConfigMap
	seen := map[CAConfigMap]bool{}
	add := func(ca *TrustedCA) {
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

func (c effectiveConfig) apiKeyAuthenticator() (Authenticator, bool) {
	return c.apiKey, c.apiKey.APIKey != nil
}

func (c effectiveConfig) usesAPIKeys() bool { return c.hasAPIKey }

func (c effectiveConfig) usesJWT() bool { return c.hasJWT }

func (c effectiveConfig) usesMTLS() bool { return c.hasMTLS }

func (c effectiveConfig) authenticatorUsed(name string) bool {
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
