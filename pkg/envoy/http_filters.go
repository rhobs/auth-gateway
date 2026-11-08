package envoy

import (
	"fmt"

	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	configuration "github.com/rhobs/auth-gateway/pkg/config"
)

func toHTTPFilters(c configuration.ResolvedConfig, hosts []indexedVirtualHost, protected bool) ([]*hcm.HttpFilter, error) {
	filters, err := requestControlFilters(c, routeVirtualHosts(hosts))
	if err != nil {
		return nil, err
	}
	if protected {
		filters, err = protectedHTTPFilters(c, filters, hosts)
		if err != nil {
			return nil, err
		}
	}
	if (c.UsesAPIKeys() || c.UsesJWT() || c.UsesMTLS()) && !protected {
		cleanup, err := toCredentialCleanupFilter(c)
		if err != nil {
			return nil, err
		}
		filters = append(filters, cleanup)
	}
	fault, err := faultHTTPFilter(c, hosts)
	if err != nil {
		return nil, err
	}
	if fault != nil {
		filters = append(filters, fault)
	}
	admission, err := admissionHTTPFilter(c, hosts)
	if err != nil {
		return nil, err
	}
	if admission != nil {
		filters = append(filters, admission)
	}
	terminalRouter, err := routerHTTPFilter()
	if err != nil {
		return nil, err
	}
	return append(filters, terminalRouter), nil
}

func requestControlFilters(c configuration.ResolvedConfig, hosts []*route.VirtualHost) ([]*hcm.HttpFilter, error) {
	controls, err := requestControlHeaderFilter(c)
	if err != nil {
		return nil, err
	}
	filters := []*hcm.HttpFilter{controls}
	if !hasRequestMetricRoutes(hosts) {
		return filters, nil
	}
	metric, err := requestMetricsHTTPFilter(c)
	if err != nil {
		return nil, err
	}
	filters = append(filters, metric)
	return filters, nil
}

func protectedHTTPFilters(c configuration.ResolvedConfig, filters []*hcm.HttpFilter, hosts []indexedVirtualHost) ([]*hcm.HttpFilter, error) {
	usesJWT, usesKey, usesMTLS := false, false, false
	serverIndexes := make([]int, 0, len(hosts))
	for _, host := range hosts {
		serverIndexes = append(serverIndexes, host.serverIndex)
		usesJWT = usesJWT || c.ResolvedServers[host.serverIndex].HasJWT
		usesKey = usesKey || c.ResolvedServers[host.serverIndex].HasAPIKey
		usesMTLS = usesMTLS || c.ResolvedServers[host.serverIndex].UsesMTLS()
	}
	var err error
	filters, err = authenticationHTTPFilters(c, filters, serverIndexes, usesJWT, usesKey, usesMTLS)
	if err != nil {
		return nil, err
	}
	if needsWorkingAttributes(c) {
		filters, err = attributeHTTPFilters(c, filters, hosts)
		if err != nil {
			return nil, err
		}
	}
	return authorizationHTTPFilters(c, filters)
}

func authenticationHTTPFilters(c configuration.ResolvedConfig, filters []*hcm.HttpFilter, serverIndexes []int, usesJWT, usesKey, usesMTLS bool) ([]*hcm.HttpFilter, error) {
	if usesMTLS {
		peer, err := mtlsPeerHeadersFilter()
		if err != nil {
			return nil, fmt.Errorf("encode mTLS peer headers: %w", err)
		}
		filters = append(filters, peer)
	}
	if usesJWT {
		jwtFilter, err := jwtHTTPFilter(c, serverIndexes)
		if err != nil {
			return nil, err
		}
		filters = append(filters, jwtFilter)
	}
	headers := requestHeaderSources(c, serverIndexes)
	var keyAuthenticator gatewayapi.Authenticator
	if usesKey {
		filters = append(filters, apiKeyFilter())
		keyAuthenticator, _ = c.APIKeyAuthenticator()
	}
	if usesKey || usesMTLS || len(headers) > 0 {
		metadata, err := requestMetadataFilter(keyAuthenticator, headers, usesMTLS)
		if err != nil {
			return nil, fmt.Errorf("encode request metadata filter: %w", err)
		}
		filters = append(filters, metadata)
	}
	if usesKey || usesMTLS {
		var err error
		filters, err = appendAuthenticationRBAC(filters)
		if err != nil {
			return nil, err
		}
	}
	if usesMTLS {
		cleanup, err := mtlsPendingCleanupFilter()
		if err != nil {
			return nil, fmt.Errorf("encode mTLS authentication marker cleanup: %w", err)
		}
		filters = append(filters, cleanup)
		cardinality, err := mtlsSANCardinalityFilter()
		if err != nil {
			return nil, fmt.Errorf("encode mTLS SAN cardinality: %w", err)
		}
		filters = append(filters, cardinality)
		shared, err := mtlsSharedAttributesHTTPFilter()
		if err != nil {
			return nil, err
		}
		filters = append(filters, shared)
	}
	return filters, nil
}

func authorizationHTTPFilters(c configuration.ResolvedConfig, filters []*hcm.HttpFilter) ([]*hcm.HttpFilter, error) {
	authorization, err := authorizationHTTPFilter()
	if err != nil {
		return nil, err
	}
	filters = append(filters, authorization)
	if configuration.HasRequestHeaderProcessing(c.APIs) {
		filters, err = appendRequiredHeaderRBAC(filters)
		if err != nil {
			return nil, err
		}
	}
	if c.UsesAPIKeys() || c.UsesJWT() || c.UsesMTLS() {
		cleanup, err := toCredentialCleanupFilter(c)
		if err != nil {
			return nil, err
		}
		filters = append(filters, cleanup)
	}
	if configuration.HasRequestHeaderProcessing(c.APIs) {
		headers, err := requestHeaderHTTPFilter(c.APIs)
		if err != nil {
			return nil, err
		}
		filters = append(filters, headers)
	}
	return filters, nil
}

func hasProtectedHosts(hosts []indexedVirtualHost) bool {
	for _, host := range hosts {
		if host.host != nil && host.host.TypedPerFilterConfig[authorizationFilterName] != nil {
			return true
		}
	}
	return false
}
