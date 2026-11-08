package config

import (
	"fmt"
	"strconv"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	jwt "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/jwt_authn/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"google.golang.org/protobuf/types/known/emptypb"
)

const (
	jwtVerifiedHeaderPrefix = "x-auth-gateway-jwt-verified-"
	jwtAuthnFilterName      = "envoy.filters.http.jwt_authn"
	jwtIssuerClaimName      = "iss"
)

func jwtVerifiedHeaderName(name string) string { return jwtVerifiedHeaderPrefix + name }

func addServerJWTRequirement(c effectiveConfig, host *route.VirtualHost, index int, server resolvedServer) error {
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

func serverJWTRequirementName(index int) string { return "server-" + strconv.Itoa(index) }

func (c effectiveConfig) toJWTFilterConfig(serverIndexes ...int) (*jwt.JwtAuthentication, error) {
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
				HttpUri:       &core.HttpUri{Uri: authenticator.JWT.JWKS.URI, HttpUpstreamType: &core.HttpUri_Cluster{Cluster: jwksClusterName(authenticator.Name)}, Timeout: authenticator.JWT.JWKS.FetchTimeout.protobuf()},
				CacheDuration: authenticator.JWT.JWKS.CacheDuration.protobuf(),
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

func (c effectiveConfig) jwtHTTPFilter(serverIndexes []int) (*hcm.HttpFilter, error) {
	var jwtConfig *jwt.JwtAuthentication
	var err error
	if c.usesAPIKeys() || c.usesMTLS() {
		jwtConfig, err = c.toJWTFilterConfig(serverIndexes...)
	} else {
		jwtConfig, err = c.toJWTFilterConfig()
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
