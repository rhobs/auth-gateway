package config

import (
	"fmt"

	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
)

func (c effectiveConfig) toHTTPFilters(hosts []indexedVirtualHost, protected bool) ([]*hcm.HttpFilter, error) {
	filters, err := c.requestControlFilters(routeVirtualHosts(hosts))
	if err != nil {
		return nil, err
	}
	if protected {
		filters, err = c.protectedHTTPFilters(filters, hosts)
		if err != nil {
			return nil, err
		}
	}
	if (c.usesAPIKeys() || c.usesJWT() || c.usesMTLS()) && !protected {
		cleanup, err := c.toCredentialCleanupFilter()
		if err != nil {
			return nil, err
		}
		filters = append(filters, cleanup)
	}
	fault, err := c.faultHTTPFilter(hosts)
	if err != nil {
		return nil, err
	}
	if fault != nil {
		filters = append(filters, fault)
	}
	admission, err := c.admissionHTTPFilter(hosts)
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

func (c effectiveConfig) requestControlFilters(hosts []*route.VirtualHost) ([]*hcm.HttpFilter, error) {
	controls, err := c.requestControlHeaderFilter()
	if err != nil {
		return nil, err
	}
	filters := []*hcm.HttpFilter{controls}
	if !hasRequestMetricRoutes(hosts) {
		return filters, nil
	}
	metric, err := c.requestMetricsHTTPFilter()
	if err != nil {
		return nil, err
	}
	filters = append(filters, metric)
	return filters, nil
}

func (c effectiveConfig) protectedHTTPFilters(filters []*hcm.HttpFilter, hosts []indexedVirtualHost) ([]*hcm.HttpFilter, error) {
	usesJWT, usesKey, usesMTLS := false, false, false
	serverIndexes := make([]int, 0, len(hosts))
	for _, host := range hosts {
		serverIndexes = append(serverIndexes, host.serverIndex)
		usesJWT = usesJWT || c.servers[host.serverIndex].hasJWT
		usesKey = usesKey || c.servers[host.serverIndex].hasAPIKey
		usesMTLS = usesMTLS || c.servers[host.serverIndex].usesMTLS()
	}
	var err error
	filters, err = c.authenticationHTTPFilters(filters, serverIndexes, usesJWT, usesKey, usesMTLS)
	if err != nil {
		return nil, err
	}
	if needsWorkingAttributes(c) {
		filters, err = c.attributeHTTPFilters(filters, hosts)
		if err != nil {
			return nil, err
		}
	}
	return c.authorizationHTTPFilters(filters)
}

func (c effectiveConfig) authenticationHTTPFilters(filters []*hcm.HttpFilter, serverIndexes []int, usesJWT, usesKey, usesMTLS bool) ([]*hcm.HttpFilter, error) {
	if usesMTLS {
		peer, err := mtlsPeerHeadersFilter()
		if err != nil {
			return nil, fmt.Errorf("encode mTLS peer headers: %w", err)
		}
		filters = append(filters, peer)
	}
	if usesJWT {
		jwtFilter, err := c.jwtHTTPFilter(serverIndexes)
		if err != nil {
			return nil, err
		}
		filters = append(filters, jwtFilter)
	}
	headers := requestHeaderSources(c, serverIndexes)
	var keyAuthenticator Authenticator
	if usesKey {
		filters = append(filters, apiKeyFilter())
		keyAuthenticator, _ = c.apiKeyAuthenticator()
	}
	if usesKey || usesMTLS || len(headers) > 0 {
		metadata, err := keyAuthenticator.toRequestMetadataFilter(headers, usesMTLS)
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

func (c effectiveConfig) authorizationHTTPFilters(filters []*hcm.HttpFilter) ([]*hcm.HttpFilter, error) {
	authorization, err := authorizationHTTPFilter()
	if err != nil {
		return nil, err
	}
	filters = append(filters, authorization)
	if hasRequestHeaderProcessing(c.APIs) {
		filters, err = appendRequiredHeaderRBAC(filters)
		if err != nil {
			return nil, err
		}
	}
	if c.usesAPIKeys() || c.usesJWT() || c.usesMTLS() {
		cleanup, err := c.toCredentialCleanupFilter()
		if err != nil {
			return nil, err
		}
		filters = append(filters, cleanup)
	}
	if hasRequestHeaderProcessing(c.APIs) {
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
