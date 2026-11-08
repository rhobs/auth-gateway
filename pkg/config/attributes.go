package config

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
)

const AttributeNameValidationErrorFormat = "%s.attributes contains invalid attribute name %q"

var AttributeNamePattern = regexp.MustCompile("^[a-z][a-z0-9_-]{0,63}$")

func validateAuthenticatorAttributes(name string, authenticator gatewayapi.Authenticator, apiKeyHeader string) error {
	for _, attribute := range slices.Sorted(maps.Keys(authenticator.Attributes)) {
		if !AttributeNamePattern.MatchString(attribute) {
			return fmt.Errorf(AttributeNameValidationErrorFormat, name, attribute)
		}
		source := authenticator.Attributes[attribute]
		field := name + ".attributes." + attribute
		if authenticator.JWT != nil {
			if source.Credential != nil || source.URISAN != nil || source.DNSSAN != nil || (source.ClaimPath == nil) == (source.Header == nil) {
				return fmt.Errorf("%s must set exactly one of claim_path or header", field)
			}
		} else if authenticator.APIKey != nil {
			if source.ClaimPath != nil || source.URISAN != nil || source.DNSSAN != nil || (source.Credential == nil) == (source.Header == nil) {
				return fmt.Errorf("%s must set exactly one of credential: true or header", field)
			}
		} else {
			sources := 0
			for _, present := range []bool{source.Header != nil, source.URISAN != nil, source.DNSSAN != nil} {
				if present {
					sources++
				}
			}
			if source.ClaimPath != nil || source.Credential != nil || sources != 1 {
				return fmt.Errorf("%s must set exactly one of uri_san: true, dns_san: true, or header", field)
			}
		}
		if source.ClaimPath != nil {
			if len(source.ClaimPath) == 0 {
				return fmt.Errorf("%s.claim_path must contain at least one literal object key", field)
			}
			if slices.Contains(source.ClaimPath, "") {
				return fmt.Errorf("%s.claim_path keys must not be empty", field)
			}
		}
		if source.Credential != nil && !*source.Credential {
			return fmt.Errorf("%s.credential must be true", field)
		}
		if source.URISAN != nil && !*source.URISAN {
			return fmt.Errorf("%s.uri_san must be true", field)
		}
		if source.DNSSAN != nil && !*source.DNSSAN {
			return fmt.Errorf("%s.dns_san must be true", field)
		}
		if source.Header != nil {
			header := *source.Header
			lower := strings.ToLower(header)
			if !validHeaderFieldName(header) || strings.Contains(header, "_") || ForbiddenIdentityHeader(lower) {
				return fmt.Errorf("%s.header must be a safe HTTP request header name", field)
			}
			if strings.EqualFold(header, apiKeyHeader) {
				return fmt.Errorf("%s.header is reserved for API-key credentials", field)
			}
		}
	}
	return nil
}

func validateRouteAttributeSources(serverName string, server gatewayapi.Server, bound []gatewayapi.API, authenticators map[string]gatewayapi.Authenticator) error {
	for _, api := range bound {
		for routeIndex, route := range api.Routes {
			if route.Processing == nil {
				continue
			}
			if server.Authentication == nil {
				return fmt.Errorf("%s processing on API %q route %d requires authentication", serverName, api.Name, routeIndex)
			}
			selected := selectedAuthenticatorNames(server)
			for _, header := range route.Processing.RequestHeaders {
				provided := false
				for _, name := range selected {
					if providesAttributeAuthenticator(authenticators[name], header.FromAttribute) {
						provided = true
						break
					}
				}
				if !provided {
					return fmt.Errorf("%s authentication does not provide processing attribute %q", serverName, header.FromAttribute)
				}
			}
		}
	}
	return nil
}

func AttributeMetadataPath(authenticator gatewayapi.Authenticator, attribute string) (string, []string) {
	source := authenticator.Attributes[attribute]
	if source.Header != nil {
		return RequestHeaderMetadataNamespace, []string{strings.ToLower(*source.Header)}
	}
	if authenticator.JWT != nil {
		return JwtAuthnFilterName, append([]string{authenticator.Name}, source.ClaimPath...)
	}
	if authenticator.MTLS != nil {
		if source.URISAN != nil {
			return MtlsMetadataNamespace, []string{MtlsURIMetadataKey}
		}
		return MtlsMetadataNamespace, []string{MtlsDNSMetadataKey}
	}
	return ApiKeyMetadataNamespace, []string{ApiKeyAttributeMetadataKey(attribute)}
}

func cloneAttributeSource(a gatewayapi.AttributeSource) gatewayapi.AttributeSource {
	a.ClaimPath = slices.Clone(a.ClaimPath)
	a.Header = clonePointer(a.Header)
	a.Credential = clonePointer(a.Credential)
	a.URISAN = clonePointer(a.URISAN)
	a.DNSSAN = clonePointer(a.DNSSAN)
	return a
}
