package config

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	rbac "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	headertometadata "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/header_to_metadata/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
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

func (authenticator Authenticator) providesAttribute(name string) bool {
	_, exists := authenticator.Attributes[name]
	return exists
}

func (authenticator Authenticator) credentialAttributeNames() []string {
	var names []string
	for name, source := range authenticator.Attributes {
		if source.Credential != nil && *source.Credential {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

func (authenticator Authenticator) toRequestMetadataFilter(headers []string, includeMTLS bool) (*hcm.HttpFilter, error) {
	var rules []*headertometadata.Config_Rule
	if authenticator.APIKey != nil {
		attributeNames := authenticator.credentialAttributeNames()
		rules = append(rules, &headertometadata.Config_Rule{
			Header: apiKeyClientHeader, Remove: len(attributeNames) == 0,
			OnHeaderPresent: &headertometadata.Config_KeyValuePair{
				MetadataNamespace: apiKeyMetadataNamespace, Key: apiKeyMetadataKey,
				Value: apiKeyVerifiedIdentity,
			},
		})
		for index, attribute := range attributeNames {
			rules = append(rules, &headertometadata.Config_Rule{
				Header: apiKeyClientHeader, Remove: index == len(attributeNames)-1,
				OnHeaderPresent: &headertometadata.Config_KeyValuePair{
					MetadataNamespace: apiKeyMetadataNamespace,
					Key:               apiKeyAttributeMetadataKey(attribute),
					RegexValueRewrite: &matcher.RegexMatchAndSubstitute{
						Pattern:      &matcher.RegexMatcher{Regex: apiKeyAttributePattern(attribute)},
						Substitution: `\1`,
					},
				},
			})
		}
	}
	if includeMTLS {
		rules = append(rules, mtlsPeerMetadataRules()...)
	}
	for _, header := range headers {
		rules = append(rules, &headertometadata.Config_Rule{
			Header: header,
			OnHeaderPresent: &headertometadata.Config_KeyValuePair{
				MetadataNamespace: requestHeaderMetadataNamespace,
				Key:               header,
			},
		})
	}
	config, err := packEnvoy(&headertometadata.Config{RequestRules: rules})
	if err != nil {
		return nil, err
	}
	return &hcm.HttpFilter{Name: headerToMetadataFilterName, ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: config}}, nil
}

func (authenticator Authenticator) toJWTMarkerPrincipal() *rbac.Principal {
	return &rbac.Principal{Identifier: &rbac.Principal_Header{Header: &route.HeaderMatcher{
		Name:                 jwtVerifiedHeaderName(authenticator.Name),
		HeaderMatchSpecifier: &route.HeaderMatcher_StringMatch{StringMatch: &matcher.StringMatcher{MatchPattern: &matcher.StringMatcher_Exact{Exact: authenticator.JWT.Issuer}}},
	}}}
}

func (authenticator Authenticator) toKeyGrantPrincipal(grant AuthorizationGrant) *rbac.Principal {
	conditions := []*rbac.Principal{apiKeyIdentityPrincipal()}
	for _, attribute := range slices.Sorted(maps.Keys(grant.Attributes)) {
		namespace, path := attributeMetadataPath(authenticator, attribute)
		conditions = append(conditions, dynamicMetadataPrincipal(namespace, path, allowedStringValueMatcher(grant.Attributes[attribute])))
	}
	return andPrincipals(conditions...)
}
