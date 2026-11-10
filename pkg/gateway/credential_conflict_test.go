package gateway

import (
	"slices"
	"testing"

	rbac "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	httpRBAC "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rbac/v3"
)

func TestCredentialConflictPrecedesMetricsOnEveryChain(t *testing.T) {
	c := loadConfigCase(t, "api-key-auth")
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := decodeBootstrap(t, files.EnvoyBootstrap.Contents)
	chains := 0
	for _, listener := range bootstrap.StaticResources.Listeners {
		for _, chain := range listener.FilterChains {
			chains++
			manager := decodeHTTPManager(t, chain)
			names := httpFilterNames(manager)
			if len(names) == 0 || names[0] != credentialConflictFilterName {
				t.Fatalf("HTTP filter order = %v", names)
			}
			if metrics := slices.Index(names, requestMetricsFilterName); metrics <= 0 {
				t.Fatalf("request metrics must follow credential rejection: %v", names)
			}
			if got := len(manager.GetRouteConfig().GetVirtualHosts()); got < 2 {
				t.Fatalf("HTTP manager has %d virtual hosts, want public and protected hosts", got)
			}
			var config httpRBAC.RBAC
			if err := manager.HttpFilters[0].GetTypedConfig().UnmarshalTo(&config); err != nil {
				t.Fatal(err)
			}
			if config.GetRules().GetAction() != rbac.RBAC_DENY {
				t.Fatalf("credential conflict action = %v", config.GetRules().GetAction())
			}
			policy := config.GetRules().GetPolicies()["mixed-credentials"]
			if policy == nil || len(policy.GetPermissions()) != 1 || len(policy.GetPrincipals()) != 1 || !policy.GetPrincipals()[0].GetAny() {
				t.Fatalf("credential conflict policy = %v", policy)
			}
			permissions := policy.GetPermissions()[0].GetAndRules().GetRules()
			if len(permissions) != 2 || permissions[0].GetHeader().GetName() != authorizationHeaderName || !permissions[0].GetHeader().GetPresentMatch() ||
				permissions[1].GetHeader().GetName() != "x-partner-key" || !permissions[1].GetHeader().GetPresentMatch() {
				t.Fatalf("credential conflict permissions = %v", permissions)
			}
		}
	}
	if chains == 0 {
		t.Fatal("no HTTP filter chains were generated")
	}
}

func TestCredentialConflictUsesDefaultAPIKeyHeader(t *testing.T) {
	c := loadConfigCase(t, "api-key-auth")
	c.Authenticators[1].APIKey.Header = ""
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	manager := firstHTTPManager(t, files.EnvoyBootstrap.Contents)
	var config httpRBAC.RBAC
	if err := manager.HttpFilters[0].GetTypedConfig().UnmarshalTo(&config); err != nil {
		t.Fatal(err)
	}
	permissions := config.GetRules().GetPolicies()["mixed-credentials"].GetPermissions()[0].GetAndRules().GetRules()
	if got := permissions[1].GetHeader().GetName(); got != "x-api-key" {
		t.Fatalf("default API-key header = %q", got)
	}
}
