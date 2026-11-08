package gateway

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	lua "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/lua/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
)

func TestAPIMetricsConfigurationAndValidation(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-with-attributes")
	type apiMetricsDefaults struct {
		Configured bool
		Tenant     string
		LabelCount int
	}
	gotMetrics := make([]apiMetricsDefaults, 0, len(c.APIs))
	for _, api := range c.APIs {
		settings := apiMetricsDefaults{}
		if api.Metrics != nil {
			settings.Configured = true
			settings.Tenant = api.Metrics.Labels["tenant"]
			settings.LabelCount = len(api.Metrics.Labels)
		}
		gotMetrics = append(gotMetrics, settings)
	}
	wantMetrics := []apiMetricsDefaults{
		{Configured: true, Tenant: "tenant_id", LabelCount: 1},
		{Configured: true},
	}
	assertConfigDiff(t, "fixture API metrics", wantMetrics, gotMetrics)

	tests := []struct {
		name string
		want string
		edit func(*gatewayapi.Config)
	}{
		{name: "invalid label name", want: "apis[0].metrics.labels", edit: func(c *gatewayapi.Config) { c.APIs[0].Metrics.Labels["bad-name"] = "tenant_id" }},
		{name: "reserved API label", want: "apis[0].metrics.labels", edit: func(c *gatewayapi.Config) { c.APIs[0].Metrics.Labels["api"] = "tenant_id" }},
		{name: "reserved status label", want: "apis[0].metrics.labels", edit: func(c *gatewayapi.Config) { c.APIs[0].Metrics.Labels["http_status_code"] = "tenant_id" }},
		{name: "reserved Prometheus prefix", want: "apis[0].metrics.labels", edit: func(c *gatewayapi.Config) { c.APIs[0].Metrics.Labels["__internal"] = "tenant_id" }},
		{name: "reserved Envoy label", want: "apis[0].metrics.labels", edit: func(c *gatewayapi.Config) { c.APIs[0].Metrics.Labels["envoy_http_conn_manager_prefix"] = "tenant_id" }},
		{name: "invalid attribute name", want: "apis[0].metrics.labels.tenant", edit: func(c *gatewayapi.Config) { c.APIs[0].Metrics.Labels["tenant"] = "TenantID" }},
		{name: "unknown attribute", want: "apis[0].metrics.labels.tenant references unknown authenticator attribute", edit: func(c *gatewayapi.Config) { c.APIs[0].Metrics.Labels["tenant"] = "unknown" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := loadConfigCase(t, "jwt-auth-with-attributes")
			test.edit(&config)
			if err := Validate(config); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestRequestMetricNameConfigurationAndValidation(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-with-attributes")
	c.Observability.Metrics.CustomMetricName = new("gateway_http_requests_total")
	if err := Validate(c); err != nil {
		t.Fatalf("valid custom metric name was rejected: %v", err)
	}
	for _, test := range []struct{ name, value string }{
		{name: "empty"},
		{name: "leading digit", value: "9requests_total"},
		{name: "hyphen", value: "bad-name"},
		{name: "period", value: "bad.name"},
		{name: "stat delimiter", value: "bad|name"},
		{name: "reserved prefix", value: "__reserved"},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := loadConfigCase(t, "jwt-auth-with-attributes")
			config.Observability.Metrics.CustomMetricName = new(test.value)
			if err := Validate(config); err == nil || !strings.Contains(err.Error(), "observability.metrics.custom_metric_name") {
				t.Fatalf("Validate error = %v, want observability.metrics.custom_metric_name", err)
			}
		})
	}
}

func TestRequestMetricsGenerateTagsAndRouteMetadata(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-with-attributes")
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := decodeBootstrap(t, files.EnvoyBootstrap.Contents)
	tags := bootstrap.GetStatsConfig().GetStatsTags()
	if len(tags) != 3 {
		t.Fatalf("stats tags = %#v, want API, status, and tenant", tags)
	}
	raw := "http.ingress.lua.gateway_http_requests_total|api=metrics-write|http_status_code=403|tenant=team-a"
	for i, want := range []struct{ label, value string }{{"api", "metrics-write"}, {"http_status_code", "403"}, {"tenant", "team-a"}} {
		if tags[i].GetTagName() != want.label {
			t.Fatalf("tag %d name = %q, want %q", i, tags[i].GetTagName(), want.label)
		}
		pattern, err := regexp.Compile(tags[i].GetRegex())
		if err != nil {
			t.Fatal(err)
		}
		groups := pattern.FindStringSubmatch(raw)
		if len(groups) != 3 || groups[2] != want.value {
			t.Fatalf("tag %q matched %q with groups %v", want.label, raw, groups)
		}
	}

	manager := firstHTTPManager(t, files.EnvoyBootstrap.Contents)
	var luaConfig lua.Lua
	for _, filter := range manager.HttpFilters {
		if filter.Name == requestMetricsFilterName {
			if err := filter.GetTypedConfig().UnmarshalTo(&luaConfig); err != nil {
				t.Fatal(err)
			}
		}
	}
	script := luaConfig.GetDefaultSourceCode().GetInlineString()
	if !strings.Contains(script, `local counter_name = "gateway_http_requests_total"`) ||
		!strings.Contains(script, "function envoy_on_response(response_handle)") ||
		!strings.Contains(script, `filter_state:get("auth_gateway.attributes." .. attribute)`) ||
		strings.Contains(script, "function envoy_on_request") {
		t.Fatalf("generated Lua is missing response-only metric collection: %s", script)
	}

	routes := manager.GetRouteConfig().GetVirtualHosts()[0].GetRoutes()
	metricRoute := namedRoute(routes, apiRouteName(0, "metrics-write", 0, 0))
	if metricRoute == nil {
		t.Fatal("metrics-write route is missing")
	}
	metricMetadata := metricRoute.GetMetadata().GetFilterMetadata()[requestMetricsFilterName]
	if metricMetadata == nil || metricMetadata.Fields[apiMetadataName].GetStringValue() != "metrics-write" ||
		metricMetadata.Fields["labels"].GetStructValue().Fields["tenant"].GetStringValue() != "tenant_id" {
		t.Fatalf("metrics-write route metadata = %#v", metricMetadata)
	}
	statusOnlyRoute := namedRoute(routes, apiRouteName(1, "logs", 0, 0))
	if statusOnlyRoute == nil {
		t.Fatal("logs route is missing")
	}
	statusMetadata := statusOnlyRoute.GetMetadata().GetFilterMetadata()[requestMetricsFilterName]
	if statusMetadata == nil || statusMetadata.Fields[apiMetadataName].GetStringValue() != "logs" ||
		len(statusMetadata.Fields["labels"].GetStructValue().Fields) != 0 {
		t.Fatalf("status-only route metadata = %#v", statusMetadata)
	}
	for _, generated := range routes {
		if strings.HasPrefix(generated.Name, "method-not-allowed-") || generated.Name == "not-found" {
			if generated.GetMetadata().GetFilterMetadata()[requestMetricsFilterName] != nil {
				t.Fatalf("fallback route %q has request metric metadata", generated.Name)
			}
		}
	}
}

func TestRequestMetricsDefaultCounterName(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-with-attributes")
	c.Observability.Metrics.CustomMetricName = nil
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := decodeBootstrap(t, files.EnvoyBootstrap.Contents)
	if tags := bootstrap.GetStatsConfig().GetStatsTags(); len(tags) == 0 ||
		!strings.Contains(tags[0].GetRegex(), "auth_gateway_http_requests_total") {
		t.Fatalf("default request metric stats tags = %#v", tags)
	}
	if !strings.Contains(string(files.EnvoyBootstrap.Contents), `local counter_name = "auth_gateway_http_requests_total"`) {
		t.Fatal("default request metric name is missing from Lua")
	}
}

func TestRequestMetricNameAloneDoesNotEnableCounter(t *testing.T) {
	c := loadConfigCase(t, "public-routing")
	c.Observability.Metrics.CustomMetricName = new("gateway_http_requests_total")
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := decodeBootstrap(t, files.EnvoyBootstrap.Contents)
	if bootstrap.GetStatsConfig() != nil {
		t.Fatal("name-only request metric configuration added stats tags")
	}
	manager := decodeHTTPManager(t, bootstrap.StaticResources.Listeners[0].FilterChains[0])
	if containsFilter(manager, requestMetricsFilterName) {
		t.Fatal("name-only request metric configuration added Lua")
	}
}

func TestRequestMetricsUseAttributesWithoutHeaderProcessing(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth")
	c.APIs[0].Metrics = &gatewayapi.APIMetrics{Labels: map[string]string{"tenant": "tenant_id"}}
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	manager := firstHTTPManager(t, files.EnvoyBootstrap.Contents)
	want := []string{requestControlsFilterName, requestMetricsFilterName, jwtAuthnFilterName, attributeFilterName, authorizationFilterName, credentialCleanupFilterName, routerFilterName}
	if got := httpFilterNames(manager); !slices.Equal(got, want) {
		t.Fatalf("HTTP filters = %v, want %v", got, want)
	}
}

func TestStatusOnlyRequestMetricsOnPublicAPI(t *testing.T) {
	c := loadConfigCase(t, "public-routing")
	c.APIs[0].Metrics = &gatewayapi.APIMetrics{}
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := decodeBootstrap(t, files.EnvoyBootstrap.Contents)
	if got := len(bootstrap.GetStatsConfig().GetStatsTags()); got != 2 {
		t.Fatalf("status-only stats tags = %d, want API and status", got)
	}
	manager := decodeHTTPManager(t, bootstrap.StaticResources.Listeners[0].FilterChains[0])
	want := []string{requestControlsFilterName, requestMetricsFilterName, routerFilterName}
	if got := httpFilterNames(manager); !slices.Equal(got, want) {
		t.Fatalf("public HTTP filters = %v, want %v", got, want)
	}
}

func TestRequestMetricsOnlyOnSelectedAPIs(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-with-attributes")
	c.APIs[1].Metrics = nil
	c.Servers[1].APIs = []string{"logs"}
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := decodeBootstrap(t, files.EnvoyBootstrap.Contents)
	for _, chain := range bootstrap.StaticResources.Listeners[0].FilterChains {
		manager := decodeHTTPManager(t, chain)
		metered := chain.GetFilterChainMatch().GetTransportProtocol() != "tls"
		if containsFilter(manager, requestMetricsFilterName) != metered {
			t.Fatalf("chain %q metrics filter = %t, want %t", chain.GetFilterChainMatch().GetTransportProtocol(), containsFilter(manager, requestMetricsFilterName), metered)
		}
		for _, host := range manager.GetRouteConfig().GetVirtualHosts() {
			for _, generated := range host.GetRoutes() {
				if strings.Contains(generated.Name, "-logs-") && generated.GetMetadata().GetFilterMetadata()[requestMetricsFilterName] != nil {
					t.Fatalf("unmetered logs route %q has metric metadata", generated.Name)
				}
			}
		}
	}
}
