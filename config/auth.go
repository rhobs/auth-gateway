package config

import (
	"fmt"
	"slices"
	"strings"
)

const authenticatorFieldPathFormat = "authenticators[%d]"

// Authenticator defines one named credential validator.
type Authenticator struct {
	Name       string                     `yaml:"name"`
	JWT        *JWTAuthenticator          `yaml:"jwt,omitempty"`
	APIKey     *APIKeyAuthenticator       `yaml:"api_key,omitempty"`
	MTLS       *MTLSAuthenticator         `yaml:"mtls,omitempty"`
	Attributes map[string]AttributeSource `yaml:"attributes,omitempty"`
}

// Authentication selects credential validators for a server.
type Authentication struct {
	AnyOf []string `yaml:"any_of,omitempty"`
	AllOf []string `yaml:"all_of,omitempty"`
}

func selectedAuthenticatorNames(server Server) []string {
	if server.Authentication == nil {
		return nil
	}
	if server.Authentication.AnyOf != nil {
		return server.Authentication.AnyOf
	}
	return server.Authentication.AllOf
}

func validateSelection[V any](name string, anyOf, allOf []string, known map[string]V) ([]string, error) {
	if (anyOf == nil) == (allOf == nil) {
		return nil, fmt.Errorf("%s must set exactly one of any_of or all_of", name)
	}
	values := anyOf
	field := "any_of"
	if allOf != nil {
		values = allOf
		field = "all_of"
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("%s.%s must contain at least one name", name, field)
	}
	if err := validateUniqueReferences(name+"."+field, values, known); err != nil {
		return nil, err
	}
	return values, nil
}

func validateUniqueReferences[V any](name string, values []string, known map[string]V) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" || strings.TrimSpace(value) != value {
			return fmt.Errorf("%s names must not be empty or have surrounding whitespace", name)
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("%s contains duplicate name %q", name, value)
		}
		seen[value] = struct{}{}
		if _, exists := known[value]; !exists {
			return fmt.Errorf("%s references unknown name %q", name, value)
		}
	}
	return nil
}

func authenticatorPriority(authenticator Authenticator) int {
	switch {
	case authenticator.JWT != nil:
		return 3
	case authenticator.MTLS != nil:
		return 2
	default:
		return 1
	}
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

func (authenticator Authenticator) clone() Authenticator {
	if authenticator.Attributes != nil {
		attributes := make(map[string]AttributeSource, len(authenticator.Attributes))
		for name, source := range authenticator.Attributes {
			attributes[name] = source.clone()
		}
		authenticator.Attributes = attributes
	}
	authenticator.JWT = cloneConfigPointer(authenticator.JWT)
	authenticator.APIKey = clonePointer(authenticator.APIKey)
	authenticator.MTLS = cloneConfigPointer(authenticator.MTLS)
	return authenticator
}

func (a Authentication) clone() Authentication {
	a.AnyOf = slices.Clone(a.AnyOf)
	a.AllOf = slices.Clone(a.AllOf)
	return a
}
