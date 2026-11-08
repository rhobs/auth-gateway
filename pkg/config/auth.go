package config

import (
	"fmt"
	"slices"
	"strings"

	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
)

const AuthenticatorFieldPathFormat = "authenticators[%d]"

func selectedAuthenticatorNames(server gatewayapi.Server) []string {
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

func AuthenticatorPriority(authenticator gatewayapi.Authenticator) int {
	switch {
	case authenticator.JWT != nil:
		return 3
	case authenticator.MTLS != nil:
		return 2
	default:
		return 1
	}
}

func withDefaultsAuthenticator(authenticator gatewayapi.Authenticator) gatewayapi.Authenticator {
	if authenticator.JWT != nil {
		authenticator.JWT.JWKS = withDefaultsJWKSConfig(authenticator.JWT.JWKS)
	}
	if authenticator.APIKey != nil {
		apiKey := withDefaultsAPIKeyAuthenticator(*authenticator.APIKey)
		authenticator.APIKey = &apiKey
	}
	return authenticator
}

func cloneAuthenticator(authenticator gatewayapi.Authenticator) gatewayapi.Authenticator {
	if authenticator.Attributes != nil {
		attributes := make(map[string]gatewayapi.AttributeSource, len(authenticator.Attributes))
		for name, source := range authenticator.Attributes {
			attributes[name] = cloneAttributeSource(source)
		}
		authenticator.Attributes = attributes
	}
	authenticator.JWT = cloneConfigPointer(authenticator.JWT, cloneJWTAuthenticator)
	authenticator.APIKey = clonePointer(authenticator.APIKey)
	authenticator.MTLS = cloneConfigPointer(authenticator.MTLS, cloneMTLSAuthenticator)
	return authenticator
}

func cloneAuthentication(a gatewayapi.Authentication) gatewayapi.Authentication {
	a.AnyOf = slices.Clone(a.AnyOf)
	a.AllOf = slices.Clone(a.AllOf)
	return a
}

func providesAttributeAuthenticator(authenticator gatewayapi.Authenticator, name string) bool {
	_, exists := authenticator.Attributes[name]
	return exists
}

func CredentialAttributeNamesAuthenticator(authenticator gatewayapi.Authenticator) []string {
	var names []string
	for name, source := range authenticator.Attributes {
		if source.Credential != nil && *source.Credential {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}
