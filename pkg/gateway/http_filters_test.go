package gateway

import (
	"slices"
	"testing"

	jwt "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/jwt_authn/v3"
	httpRBAC "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rbac/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
)

func hasHTTPFilter(manager *hcm.HttpConnectionManager, name string) bool {
	return generatedHTTPFilter(manager, name) != nil
}

func generatedHTTPFilter(manager *hcm.HttpConnectionManager, name string) *hcm.HttpFilter {
	for _, filter := range manager.GetHttpFilters() {
		if filter.GetName() == name {
			return filter
		}
	}
	return nil
}

func TestAccessRoutesUseOnlyTheirSelectedNativeFilters(t *testing.T) {
	c := loadConfigCase(t, "access-control")
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	manager := firstHTTPManager(t, files.EnvoyBootstrap.Contents)
	if !generatedHTTPFilter(manager, apiKeyFilterName).GetDisabled() {
		t.Fatal("API-key filter must be disabled until selected by a route")
	}
	host := manager.GetRouteConfig().GetVirtualHosts()[0]
	var defaultJWT jwt.PerRouteConfig
	if err := host.TypedPerFilterConfig[jwtAuthnFilterName].UnmarshalTo(&defaultJWT); err != nil {
		t.Fatal(err)
	}
	if !defaultJWT.GetDisabled() {
		t.Fatal("JWT authentication must be disabled until selected by a route")
	}
	for _, test := range []struct {
		routeName, jwtRequirement, tenant string
		key                               bool
	}{
		{"api-0-write-route-0-method-0-access-0-match-0", "server-0-api-0-access-0", "tenant-a", false},
		{"api-0-write-route-0-method-0-access-0-match-1", "server-0-api-0-access-0", "tenant-b", false},
		{"api-0-write-route-0-method-0-access-1-match-0", "", "partner-a", true},
		{"api-1-read-route-0-method-0-access-0-match-0", "server-0-api-1-access-0", "tenant-a", false},
	} {
		generated := namedRoute(host.Routes, test.routeName)
		if generated == nil {
			t.Fatalf("missing route %q", test.routeName)
		}
		configs := generated.TypedPerFilterConfig
		var selectedJWT jwt.PerRouteConfig
		if test.jwtRequirement != "" {
			if err := configs[jwtAuthnFilterName].UnmarshalTo(&selectedJWT); err != nil {
				t.Fatal(err)
			}
			if selectedJWT.GetRequirementName() != test.jwtRequirement {
				t.Fatalf("JWT requirement = %q", selectedJWT.GetRequirementName())
			}
		} else if configs[jwtAuthnFilterName] != nil {
			t.Fatal("key route enabled JWT")
		}
		if (configs[apiKeyFilterName] != nil) != test.key {
			t.Fatalf("route %q has the wrong API-key selection", test.routeName)
		}
		if configs["envoy.filters.http.set_filter_state"] == nil {
			t.Fatalf("route %q is missing its attribute initializer", test.routeName)
		}
		var tenant string
		for _, header := range generated.Match.Headers {
			if header.Name == "x-tenant" {
				tenant = header.GetStringMatch().GetExact()
			}
		}
		if tenant != test.tenant {
			t.Fatalf("route tenant = %q, want %q", tenant, test.tenant)
		}
	}
	denied := namedRoute(host.Routes, "api-0-write-route-0-method-0-access-denied")
	if denied.GetDirectResponse().GetStatus() != 403 || len(denied.TypedPerFilterConfig) != 1 || denied.TypedPerFilterConfig[requestValidationFilterName] == nil {
		t.Fatalf("unmatched access must deny before processing: %v", denied)
	}
	public := namedRoute(host.Routes, "api-2-health-route-0-method-0")
	var publicRBAC httpRBAC.RBACPerRoute
	if err := public.TypedPerFilterConfig[authorizationFilterName].UnmarshalTo(&publicRBAC); err != nil {
		t.Fatal(err)
	}
	if publicRBAC.Rbac != nil || public.TypedPerFilterConfig[jwtAuthnFilterName] != nil || public.TypedPerFilterConfig[apiKeyFilterName] != nil {
		t.Fatal("public API inherited authentication or authorization")
	}
}

func TestAccessFilterOrderPreservesOriginalSources(t *testing.T) {
	c := loadConfigCase(t, "access-control")
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	manager := firstHTTPManager(t, files.EnvoyBootstrap.Contents)
	names := httpFilterNames(manager)
	previous := -1
	for _, name := range []string{credentialConflictFilterName, requestControlsFilterName, requestValidationFilterName, jwtAuthnFilterName, apiKeyFilterName, headerToMetadataFilterName, authorizationFilterName, requiredHeaderFilterName, credentialCleanupFilterName, headerMutationFilterName, routerFilterName} {
		index := slices.Index(names, name)
		if index <= previous {
			t.Fatalf("%q has unsafe filter order: %v", name, names)
		}
		previous = index
	}
}
