package config

import (
	"reflect"
	"testing"

	setfilterstatecommon "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/common/set_filter_state/v3"
	headermutation "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/header_mutation/v3"
	httpRBAC "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rbac/v3"
	router "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	setfilterstate "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"
)

func TestRewrittenRouteUsesEnvoyOriginalPathHeader(t *testing.T) {
	c := loadConfigCase(t, "public-routing")
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	generated := decodeBootstrap(t, files.EnvoyBootstrap.Contents)
	manager := decodeHTTPManager(t, generated.StaticResources.Listeners[0].FilterChains[0])
	route := manager.GetRouteConfig().GetVirtualHosts()[0].GetRoutes()[0]
	if got := route.GetRequestHeadersToAdd(); len(got) != 0 {
		t.Fatalf("rewritten route adds request headers: %v", got)
	}
	filters := manager.GetHttpFilters()
	var routerConfig router.Router
	if err := filters[len(filters)-1].GetTypedConfig().UnmarshalTo(&routerConfig); err != nil {
		t.Fatal(err)
	}
	if routerConfig.GetSuppressEnvoyHeaders() {
		t.Fatal("router suppresses Envoy headers")
	}

	var controls headermutation.HeaderMutation
	if err := filters[0].GetTypedConfig().UnmarshalTo(&controls); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range controls.GetMutations().GetRequestMutations() {
		if mutation.GetRemove() == "x-envoy-original-path" {
			return
		}
	}
	t.Fatal("request controls do not remove client-supplied x-envoy-original-path")
}

func TestJWTRequiredHeadersAreRouteScopedAndManaged(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-with-headers")
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	manager := firstHTTPManager(t, files.EnvoyBootstrap.Contents)
	var globalMutation headermutation.HeaderMutation
	for _, filter := range manager.HttpFilters {
		if filter.Name == "envoy.filters.http.header_mutation" {
			if err := filter.GetTypedConfig().UnmarshalTo(&globalMutation); err != nil {
				t.Fatal(err)
			}
		}
	}
	removed := make(map[string]bool)
	for _, mutation := range globalMutation.GetMutations().GetRequestMutations() {
		removed[mutation.GetRemove()] = mutation.GetRemove() != ""
	}
	if len(removed) != 2 || !removed["x-scope-orgid"] || !removed["x-writer-id"] {
		t.Fatalf("managed headers removed = %v", removed)
	}
	var initialized setfilterstate.Config
	for _, filter := range manager.HttpFilters {
		if filter.Name == attributeFilterName {
			if err := filter.GetTypedConfig().UnmarshalTo(&initialized); err != nil {
				t.Fatal(err)
			}
		}
	}
	if len(initialized.OnRequestHeaders) != 2 {
		t.Fatalf("initialized attribute count = %d, want tenant_id and writer_id", len(initialized.OnRequestHeaders))
	}
	for i, name := range []string{"tenant_id", "writer_id"} {
		update := initialized.OnRequestHeaders[i]
		key, ok := update.GetKey().(*setfilterstatecommon.FilterStateValue_ObjectKey)
		value, valueOK := update.GetValue().(*setfilterstatecommon.FilterStateValue_FormatString)
		if !ok || key.ObjectKey != filterStateKey(name) || !valueOK || update.FactoryKey != "envoy.string" || !update.SkipIfEmpty || !value.FormatString.OmitEmptyValues {
			t.Fatalf("initialized attribute %q has unsafe or incomplete filter-state settings: %#v", name, update)
		}
	}

	host := manager.GetRouteConfig().GetVirtualHosts()[0]
	var protected, methodFallback, notFound bool
	for _, generatedRoute := range host.GetRoutes() {
		switch generatedRoute.Name {
		case "api-0-metrics-route-0-method-0":
			protected = true
			headerConfig := generatedRoute.TypedPerFilterConfig["envoy.filters.http.header_mutation"]
			if headerConfig == nil {
				t.Fatal("protected route has no per-route header values")
			}
			var perRoute headermutation.HeaderMutationPerRoute
			if err := headerConfig.UnmarshalTo(&perRoute); err != nil {
				t.Fatal(err)
			}
			values := make(map[string]string)
			for _, mutation := range perRoute.GetMutations().GetRequestMutations() {
				append := mutation.GetAppend()
				if append != nil && append.GetHeader() != nil {
					values[append.GetHeader().GetKey()] = append.GetHeader().GetValue()
				}
			}
			if !reflect.DeepEqual(values, map[string]string{
				"X-Scope-OrgID": "%FILTER_STATE(auth_gateway.attributes.tenant_id:PLAIN)%",
				"X-Writer-ID":   "%FILTER_STATE(auth_gateway.attributes.writer_id:PLAIN)%",
			}) {
				t.Fatalf("per-route header values = %v", values)
			}
			rbacConfig := generatedRoute.TypedPerFilterConfig[requiredHeaderFilterName]
			if rbacConfig == nil {
				t.Fatal("protected route has no required-attribute check")
			}
			var required httpRBAC.RBACPerRoute
			if err := rbacConfig.UnmarshalTo(&required); err != nil {
				t.Fatal(err)
			}
			policy := required.GetRbac().GetRules().GetPolicies()["required-attributes"]
			if policy == nil || len(policy.Principals) != 1 {
				t.Fatalf("required header policy = %#v", policy)
			}
			principals := policy.Principals[0].GetAndIds().Ids
			if len(principals) != 2 {
				t.Fatalf("required header attribute count = %d", len(principals))
			}
			keys := make([]string, 0, len(principals))
			for _, principal := range principals {
				filterState := principal.GetFilterState()
				if filterState.GetStringMatch().GetSafeRegex().GetRegex() != headerValuePattern {
					t.Fatalf("required attribute matcher = %#v", filterState.GetStringMatch())
				}
				keys = append(keys, filterState.GetKey())
			}
			if !reflect.DeepEqual(keys, []string{filterStateKey("tenant_id"), filterStateKey("writer_id")}) {
				t.Fatalf("required header filter-state keys = %v", keys)
			}
		case "method-not-allowed-0":
			methodFallback = true
			if generatedRoute.TypedPerFilterConfig[requiredHeaderFilterName] != nil {
				t.Fatal("method fallback incorrectly requires upstream header values")
			}
		case "not-found":
			notFound = true
			if generatedRoute.TypedPerFilterConfig[requiredHeaderFilterName] != nil {
				t.Fatal("not-found route incorrectly requires upstream header values")
			}
		}
	}
	if !protected || !methodFallback || !notFound {
		t.Fatalf("route cases protected/fallback/not-found = %t/%t/%t", protected, methodFallback, notFound)
	}
}
