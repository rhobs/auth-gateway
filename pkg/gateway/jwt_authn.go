package gateway

import (
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	jwt "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/jwt_authn/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	"google.golang.org/protobuf/types/known/emptypb"
)

const (
	httpsProtocolToken             = "https"
	invalidJWTTextCharacters       = "\r\n\t"
	jwksDNSLookupFamilyAuto        = "AUTO"
	jwksDNSLookupFamilyV4Only      = "V4_ONLY"
	jwksDNSLookupFamilyV6Only      = "V6_ONLY"
	jwksDNSLookupFamilyV4Preferred = "V4_PREFERRED"
	jwksDNSLookupFamilyAll         = "ALL"
	jwtVerifiedHeaderPrefix        = "x-auth-gateway-jwt-verified-"
	jwtAuthnFilterName             = "envoy.filters.http.jwt_authn"
	jwtIssuerClaimName             = "iss"
)

func validateUniqueIssuerBindings(name string, selected []string, authenticators map[string]gatewayapi.Authenticator) error {
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

func validatePermissiveJWTIssuerBindings(servers []gatewayapi.Server, authenticators map[string]gatewayapi.Authenticator) error {
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

func validateJWTAuthenticator(name string, jwt gatewayapi.JWTAuthenticator) error {
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

func withDefaultsJWKSConfig(j gatewayapi.JWKSConfig) gatewayapi.JWKSConfig {
	if j.DNSLookupFamily == "" {
		j.DNSLookupFamily = jwksDNSLookupFamilyV4Only
	}
	j.CacheDuration = withDefaultDuration(j.CacheDuration, 5*time.Minute)
	j.FetchTimeout = withDefaultDuration(j.FetchTimeout, 5*time.Second)
	j.ConnectTimeout = withDefaultDuration(j.ConnectTimeout, 5*time.Second)
	j.TrustedCA = cloneConfigPointer(j.TrustedCA, cloneTrustedCA)
	j.CircuitBreakers = withDefaultsCircuitBreakerConfig(j.CircuitBreakers)
	return j
}

func cloneJWTAuthenticator(j gatewayapi.JWTAuthenticator) gatewayapi.JWTAuthenticator {
	j.JWKS = cloneJWKSConfig(j.JWKS)
	j.Audiences = slices.Clone(j.Audiences)
	return j
}

func cloneJWKSConfig(j gatewayapi.JWKSConfig) gatewayapi.JWKSConfig {
	j.CacheDuration = clonePointer(j.CacheDuration)
	j.FetchTimeout = clonePointer(j.FetchTimeout)
	j.ConnectTimeout = clonePointer(j.ConnectTimeout)
	j.TrustedCA = cloneConfigPointer(j.TrustedCA, cloneTrustedCA)
	if j.CircuitBreakers != nil {
		circuitBreakers := cloneCircuitBreakerConfig(j.CircuitBreakers)
		j.CircuitBreakers = &circuitBreakers
	}
	return j
}

func validateJWKSConfig(j gatewayapi.JWKSConfig, name string, kubernetes bool) error {
	switch j.DNSLookupFamily {
	case "", jwksDNSLookupFamilyAuto, jwksDNSLookupFamilyV4Only, jwksDNSLookupFamilyV6Only, jwksDNSLookupFamilyV4Preferred, jwksDNSLookupFamilyAll:
	default:
		return fmt.Errorf("%s.dns_lookup_family must be one of AUTO, V4_ONLY, V6_ONLY, V4_PREFERRED, or ALL", name)
	}
	for _, setting := range []struct {
		Name  string
		Value *gatewayapi.Duration
	}{
		{"cache_duration", j.CacheDuration}, {"fetch_timeout", j.FetchTimeout}, {"connect_timeout", j.ConnectTimeout},
	} {
		if err := validateDuration(name+"."+setting.Name, setting.Value, false); err != nil {
			return err
		}
	}
	if *j.ConnectTimeout > *j.FetchTimeout {
		return fmt.Errorf("%s.connect_timeout (%s) must not exceed %s.fetch_timeout (%s)", name, j.ConnectTimeout, name, j.FetchTimeout)
	}
	return validateTrustedCA(name+".trusted_ca", j.TrustedCA, kubernetes)
}

func jwtVerifiedHeaderName(name string) string { return jwtVerifiedHeaderPrefix + name }

func serverJWTRequirementName(index int) string { return "server-" + strconv.Itoa(index) }

func addServerJWTRequirement(c resolvedConfig, host *route.VirtualHost, index int, server resolvedServer) error {
	if !server.hasJWT {
		return nil
	}
	requirementName := serverJWTRequirementName(index)
	perRoute, err := packEnvoy(&jwt.PerRouteConfig{RequirementSpecifier: &jwt.PerRouteConfig_RequirementName{RequirementName: requirementName}})
	if err != nil {
		return fmt.Errorf("servers[%d] JWT requirement: %w", index, err)
	}
	host.TypedPerFilterConfig[jwtAuthnFilterName] = perRoute
	return nil
}

func jwtFilterConfig(c resolvedConfig, serverIndexes ...int) (*jwt.JwtAuthentication, error) {
	config := &jwt.JwtAuthentication{Providers: map[string]*jwt.JwtProvider{}, RequirementMap: map[string]*jwt.JwtRequirement{}, StripFailureResponse: true}
	if len(serverIndexes) == 0 {
		for index := range c.servers {
			serverIndexes = append(serverIndexes, index)
		}
	}
	used := make(map[string]struct{})
	permissive := false
	for _, index := range serverIndexes {
		server := c.servers[index]
		permissive = permissive || server.mixedAnyOf()
		for _, authenticator := range server.authenticators {
			used[authenticator.Name] = struct{}{}
		}
	}
	for _, authenticator := range c.Authenticators {
		if authenticator.JWT == nil {
			continue
		}
		if _, exists := used[authenticator.Name]; !exists {
			continue
		}
		provider := &jwt.JwtProvider{
			Issuer:            authenticator.JWT.Issuer,
			Audiences:         authenticator.JWT.Audiences,
			RequireExpiration: true,
			JwksSourceSpecifier: &jwt.JwtProvider_RemoteJwks{RemoteJwks: &jwt.RemoteJwks{
				HttpUri:       &core.HttpUri{Uri: authenticator.JWT.JWKS.URI, HttpUpstreamType: &core.HttpUri_Cluster{Cluster: jwksClusterName(authenticator.Name)}, Timeout: protobufDuration(authenticator.JWT.JWKS.FetchTimeout)},
				CacheDuration: protobufDuration(authenticator.JWT.JWKS.CacheDuration),
			}},
			FromHeaders:       []*jwt.JwtHeader{{Name: "Authorization", ValuePrefix: "Bearer "}},
			PayloadInMetadata: authenticator.Name,
		}
		if permissive {
			provider.ClaimToHeaders = []*jwt.JwtClaimToHeader{{HeaderName: jwtVerifiedHeaderName(authenticator.Name), ClaimName: jwtIssuerClaimName}}
		}
		config.Providers[authenticator.Name] = provider
	}
	for _, index := range serverIndexes {
		server := c.servers[index]
		if server.Authentication == nil || !server.hasJWT {
			continue
		}
		requirements := make([]*jwt.JwtRequirement, 0, len(server.authenticators))
		for _, authenticator := range server.authenticators {
			if authenticator.JWT != nil {
				requirements = append(requirements, &jwt.JwtRequirement{RequiresType: &jwt.JwtRequirement_ProviderName{ProviderName: authenticator.Name}})
			}
		}
		var requirement *jwt.JwtRequirement
		if server.mixedAnyOf() {
			requirement = &jwt.JwtRequirement{RequiresType: &jwt.JwtRequirement_AllowMissingOrFailed{AllowMissingOrFailed: &emptypb.Empty{}}}
		} else if len(requirements) == 1 {
			requirement = requirements[0]
		} else if len(server.Authentication.AllOf) > 0 {
			requirement = &jwt.JwtRequirement{RequiresType: &jwt.JwtRequirement_RequiresAll{RequiresAll: &jwt.JwtRequirementAndList{Requirements: requirements}}}
		} else {
			requirement = &jwt.JwtRequirement{RequiresType: &jwt.JwtRequirement_RequiresAny{RequiresAny: &jwt.JwtRequirementOrList{Requirements: requirements}}}
		}
		config.RequirementMap[serverJWTRequirementName(index)] = requirement
	}
	return config, nil
}

func jwtHTTPFilter(c resolvedConfig, serverIndexes []int) (*hcm.HttpFilter, error) {
	var jwtConfig *jwt.JwtAuthentication
	var err error
	if c.usesAPIKeys() || c.usesMTLS() {
		jwtConfig, err = jwtFilterConfig(c, serverIndexes...)
	} else {
		jwtConfig, err = jwtFilterConfig(c)
	}
	if err != nil {
		return nil, err
	}
	packed, err := packEnvoy(jwtConfig)
	if err != nil {
		return nil, fmt.Errorf("encode JWT authentication filter: %w", err)
	}
	return &hcm.HttpFilter{Name: jwtAuthnFilterName, ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: packed}}, nil
}
