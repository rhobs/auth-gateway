package config

import (
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	httpsProtocolToken             = "https"
	invalidJWTTextCharacters       = "\r\n\t"
	jwksDNSLookupFamilyAuto        = "AUTO"
	jwksDNSLookupFamilyV4Only      = "V4_ONLY"
	jwksDNSLookupFamilyV6Only      = "V6_ONLY"
	jwksDNSLookupFamilyV4Preferred = "V4_PREFERRED"
	jwksDNSLookupFamilyAll         = "ALL"
)

// JWTAuthenticator validates one issuer and optionally restricts audiences.
type JWTAuthenticator struct {
	Issuer    string     `yaml:"issuer"`
	JWKS      JWKSConfig `yaml:"jwks"`
	Audiences []string   `yaml:"audiences,omitempty"`
}

// JWKSConfig controls on-demand key fetching for one JWT authenticator.
type JWKSConfig struct {
	URI             string                `yaml:"uri"`
	DNSLookupFamily string                `yaml:"dns_lookup_family,omitempty"`
	CacheDuration   *Duration             `yaml:"cache_duration,omitempty"`
	FetchTimeout    *Duration             `yaml:"fetch_timeout,omitempty"`
	ConnectTimeout  *Duration             `yaml:"connect_timeout,omitempty"`
	TrustedCA       *TrustedCA            `yaml:"trusted_ca,omitempty"`
	CircuitBreakers *CircuitBreakerConfig `yaml:"circuit_breakers,omitempty"`
}

func validateUniqueIssuerBindings(name string, selected []string, authenticators map[string]Authenticator) error {
	seen := make(map[string]string, len(selected))
	for _, authenticatorName := range selected {
		jwt := authenticators[authenticatorName].JWT
		if jwt == nil {
			continue
		}
		issuer := jwt.Issuer
		if previous, exists := seen[issuer]; exists {
			return fmt.Errorf("%s binds authenticators %q and %q with the same issuer %q", name, previous, authenticatorName, issuer)
		}
		seen[issuer] = authenticatorName
	}
	return nil
}

func validatePermissiveJWTIssuerBindings(servers []Server, authenticators map[string]Authenticator) error {
	selected := make([]string, 0, len(authenticators))
	seen := make(map[string]struct{}, len(authenticators))
	mixedServer := -1
	for index, server := range servers {
		if server.TLSConfig != nil || server.Authentication == nil {
			continue
		}
		names := selectedAuthenticatorNames(server)
		hasOther, hasJWT := false, false
		for _, name := range names {
			if authenticators[name].JWT != nil {
				hasJWT = true
				if _, exists := seen[name]; !exists {
					selected = append(selected, name)
					seen[name] = struct{}{}
				}
			} else {
				hasOther = true
			}
		}
		if server.Authentication.AnyOf != nil && hasOther && hasJWT {
			mixedServer = index
		}
	}
	if mixedServer < 0 {
		return nil
	}
	return validateUniqueIssuerBindings(fmt.Sprintf("servers[%d].authentication.any_of", mixedServer), selected, authenticators)
}

func validateJWTAuthenticator(name string, jwt JWTAuthenticator) error {
	if jwt.Issuer == "" || strings.TrimSpace(jwt.Issuer) != jwt.Issuer || strings.ContainsAny(jwt.Issuer, invalidJWTTextCharacters) {
		return fmt.Errorf("%s.issuer must be a nonempty issuer identifier without surrounding whitespace", name)
	}
	parsed, err := url.Parse(jwt.JWKS.URI)
	if err != nil || !strings.EqualFold(parsed.Scheme, httpsProtocolToken) || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" || parsed.Opaque != "" {
		return fmt.Errorf("%s.jwks.uri must be an absolute HTTPS URL without user information or a fragment", name)
	}
	if !validHost(strings.ToLower(parsed.Hostname())) || strings.HasSuffix(parsed.Host, ":") {
		return fmt.Errorf("%s.jwks.uri must use a valid DNS name or IP address and optional port", name)
	}
	if port := parsed.Port(); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 {
			return fmt.Errorf("%s.jwks.uri must use a valid port", name)
		}
	}
	seenAudiences := make(map[string]struct{}, len(jwt.Audiences))
	for _, audience := range jwt.Audiences {
		if audience == "" || strings.TrimSpace(audience) != audience || strings.ContainsAny(audience, invalidJWTTextCharacters) {
			return fmt.Errorf("%s.audiences must not contain empty values or surrounding whitespace", name)
		}
		if _, exists := seenAudiences[audience]; exists {
			return fmt.Errorf("%s.audiences contains duplicate value %q", name, audience)
		}
		seenAudiences[audience] = struct{}{}
	}
	return nil
}

func (j JWKSConfig) withDefaults() JWKSConfig {
	if j.DNSLookupFamily == "" {
		j.DNSLookupFamily = jwksDNSLookupFamilyV4Only
	}
	j.CacheDuration = j.CacheDuration.withDefault(5 * time.Minute)
	j.FetchTimeout = j.FetchTimeout.withDefault(5 * time.Second)
	j.ConnectTimeout = j.ConnectTimeout.withDefault(5 * time.Second)
	j.TrustedCA = cloneConfigPointer(j.TrustedCA)
	j.CircuitBreakers = j.CircuitBreakers.withDefaults()
	return j
}

func (j JWTAuthenticator) clone() JWTAuthenticator {
	j.JWKS = j.JWKS.clone()
	j.Audiences = slices.Clone(j.Audiences)
	return j
}

func (j JWKSConfig) clone() JWKSConfig {
	j.CacheDuration = clonePointer(j.CacheDuration)
	j.FetchTimeout = clonePointer(j.FetchTimeout)
	j.ConnectTimeout = clonePointer(j.ConnectTimeout)
	j.TrustedCA = cloneConfigPointer(j.TrustedCA)
	if j.CircuitBreakers != nil {
		circuitBreakers := j.CircuitBreakers.clone()
		j.CircuitBreakers = &circuitBreakers
	}
	return j
}

func (j JWKSConfig) validate(name string, kubernetes bool) error {
	switch j.DNSLookupFamily {
	case "", jwksDNSLookupFamilyAuto, jwksDNSLookupFamilyV4Only, jwksDNSLookupFamilyV6Only, jwksDNSLookupFamilyV4Preferred, jwksDNSLookupFamilyAll:
	default:
		return fmt.Errorf("%s.dns_lookup_family must be one of AUTO, V4_ONLY, V6_ONLY, V4_PREFERRED, or ALL", name)
	}
	for _, setting := range []struct {
		name  string
		value *Duration
	}{
		{"cache_duration", j.CacheDuration}, {"fetch_timeout", j.FetchTimeout}, {"connect_timeout", j.ConnectTimeout},
	} {
		if err := validateDuration(name+"."+setting.name, setting.value, false); err != nil {
			return err
		}
	}
	if *j.ConnectTimeout > *j.FetchTimeout {
		return fmt.Errorf("%s.connect_timeout (%s) must not exceed %s.fetch_timeout (%s)", name, j.ConnectTimeout, name, j.FetchTimeout)
	}
	return validateTrustedCA(name+".trusted_ca", j.TrustedCA, kubernetes)
}
