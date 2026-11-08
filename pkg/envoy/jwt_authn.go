package envoy

import (
	"fmt"
	"strconv"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	jwt "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/jwt_authn/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	configuration "github.com/rhobs/auth-gateway/pkg/config"
	"google.golang.org/protobuf/types/known/emptypb"
)

func jwtVerifiedHeaderName(name string) string { return configuration.JwtVerifiedHeaderPrefix + name }

func serverJWTRequirementName(index int) string { return "server-" + strconv.Itoa(index) }

func addServerJWTRequirement(c configuration.ResolvedConfig, host *route.VirtualHost, index int, server configuration.ResolvedServer) error {
	if !server.HasJWT {
		return nil
	}
	requirementName := serverJWTRequirementName(index)
	perRoute, err := packEnvoy(&jwt.PerRouteConfig{RequirementSpecifier: &jwt.PerRouteConfig_RequirementName{RequirementName: requirementName}})
	if err != nil {
		return fmt.Errorf("servers[%d] JWT requirement: %w", index, err)
	}
	host.TypedPerFilterConfig[configuration.JwtAuthnFilterName] = perRoute
	return nil
}

func toJWTFilterConfig(c configuration.ResolvedConfig, serverIndexes ...int) (*jwt.JwtAuthentication, error) {
	config := &jwt.JwtAuthentication{Providers: map[string]*jwt.JwtProvider{}, RequirementMap: map[string]*jwt.JwtRequirement{}, StripFailureResponse: true}
	if len(serverIndexes) == 0 {
		for index := range c.ResolvedServers {
			serverIndexes = append(serverIndexes, index)
		}
	}
	used := make(map[string]struct{})
	permissive := false
	for _, index := range serverIndexes {
		server := c.ResolvedServers[index]
		permissive = permissive || server.MixedAnyOf()
		for _, authenticator := range server.Authenticators {
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
				HttpUri:       &core.HttpUri{Uri: authenticator.JWT.JWKS.URI, HttpUpstreamType: &core.HttpUri_Cluster{Cluster: configuration.JwksClusterName(authenticator.Name)}, Timeout: protobufDuration(authenticator.JWT.JWKS.FetchTimeout)},
				CacheDuration: protobufDuration(authenticator.JWT.JWKS.CacheDuration),
			}},
			FromHeaders:       []*jwt.JwtHeader{{Name: "Authorization", ValuePrefix: "Bearer "}},
			PayloadInMetadata: authenticator.Name,
		}
		if permissive {
			provider.ClaimToHeaders = []*jwt.JwtClaimToHeader{{HeaderName: jwtVerifiedHeaderName(authenticator.Name), ClaimName: configuration.JwtIssuerClaimName}}
		}
		config.Providers[authenticator.Name] = provider
	}
	for _, index := range serverIndexes {
		server := c.ResolvedServers[index]
		if server.Authentication == nil || !server.HasJWT {
			continue
		}
		requirements := make([]*jwt.JwtRequirement, 0, len(server.Authenticators))
		for _, authenticator := range server.Authenticators {
			if authenticator.JWT != nil {
				requirements = append(requirements, &jwt.JwtRequirement{RequiresType: &jwt.JwtRequirement_ProviderName{ProviderName: authenticator.Name}})
			}
		}
		var requirement *jwt.JwtRequirement
		if server.MixedAnyOf() {
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

func jwtHTTPFilter(c configuration.ResolvedConfig, serverIndexes []int) (*hcm.HttpFilter, error) {
	var jwtConfig *jwt.JwtAuthentication
	var err error
	if c.UsesAPIKeys() || c.UsesMTLS() {
		jwtConfig, err = toJWTFilterConfig(c, serverIndexes...)
	} else {
		jwtConfig, err = toJWTFilterConfig(c)
	}
	if err != nil {
		return nil, err
	}
	packed, err := packEnvoy(jwtConfig)
	if err != nil {
		return nil, fmt.Errorf("encode JWT authentication filter: %w", err)
	}
	return &hcm.HttpFilter{Name: configuration.JwtAuthnFilterName, ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: packed}}, nil
}
