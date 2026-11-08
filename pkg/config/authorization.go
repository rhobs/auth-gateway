package config

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
)

func validateAuthorizationGrant(name string, grant gatewayapi.AuthorizationGrant, apis map[string]gatewayapi.API, authenticators map[string]gatewayapi.Authenticator) error {
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

func validateGrantAttribute(name, authenticatorName, attribute string, values []string, authenticator gatewayapi.Authenticator) error {
	if !AttributeNamePattern.MatchString(attribute) {
		return fmt.Errorf(AttributeNameValidationErrorFormat, name, attribute)
	}
	if !providesAttributeAuthenticator(authenticator, attribute) {
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

func cloneAuthorizationPolicy(p gatewayapi.AuthorizationPolicy) gatewayapi.AuthorizationPolicy {
	p.Grants = cloneSlice(p.Grants, cloneAuthorizationGrant)
	return p
}

func cloneAuthorizationGrant(g gatewayapi.AuthorizationGrant) gatewayapi.AuthorizationGrant {
	g.APIs = slices.Clone(g.APIs)
	if g.Attributes != nil {
		attributes := make(map[string][]string, len(g.Attributes))
		for name, allowed := range g.Attributes {
			attributes[name] = slices.Clone(allowed)
		}
		g.Attributes = attributes
	}
	return g
}

func cloneAuthorization(a gatewayapi.Authorization) gatewayapi.Authorization {
	a.AnyOf = slices.Clone(a.AnyOf)
	a.AllOf = slices.Clone(a.AllOf)
	return a
}
