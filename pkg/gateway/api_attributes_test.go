package gateway

import (
	"strings"
	"testing"

	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	lua "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/lua/v3"
	setfilterstate "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
)

func TestLoadAPIFixedAttributes(t *testing.T) {
	c := loadConfigCase(t, "api-fixed-attributes")
	want := []gatewayapi.AttributeSource{
		testTextAttribute("role", "fixed", "metrics:read"),
		testTextAttribute("api", "fixed", "metrics"),
	}
	assertConfigDiff(t, "fixed API attributes", want, c.APIs[0].Attributes)
	if len(c.APIs[1].Attributes) != 0 {
		t.Fatal("plain API gained fixed attributes")
	}
	if c.APIs[0].Metrics.Labels["operation"] != "role" {
		t.Fatal("metric label does not reference the fixed role")
	}
}

func TestAPIFixedAttributeValidation(t *testing.T) {
	for _, test := range []struct {
		name, field string
		edit        func(*gatewayapi.Config)
	}{
		{"invalid name", "apis[0].attributes[0].name", func(c *gatewayapi.Config) { c.APIs[0].Attributes[0].Name = "Role" }},
		{"duplicate name", "apis[0].attributes[2].name", func(c *gatewayapi.Config) {
			c.APIs[0].Attributes = append(c.APIs[0].Attributes, c.APIs[0].Attributes[0])
		}},
		{"dynamic claim", "apis[0].attributes[0].from_source", func(c *gatewayapi.Config) { c.APIs[0].Attributes[0].FromSource = "claim" }},
		{"dynamic header", "apis[0].attributes[0].from_source", func(c *gatewayapi.Config) { c.APIs[0].Attributes[0].FromSource = "header" }},
		{"empty value", "apis[0].attributes[0].value", func(c *gatewayapi.Config) { c.APIs[0].Attributes[0].Value.Text = "" }},
		{"path value", "apis[0].attributes[0].value", func(c *gatewayapi.Config) {
			c.APIs[0].Attributes[0].Value = gatewayapi.AttributeValue{Path: []string{"role"}, IsPath: true}
		}},
		{"control value", "apis[0].attributes[0].value", func(c *gatewayapi.Config) { c.APIs[0].Attributes[0].Value.Text = "bad\nvalue" }},
		{"Unicode control value", "apis[0].attributes[0].value", func(c *gatewayapi.Config) { c.APIs[0].Attributes[0].Value.Text = "bad\u0085value" }},
		{"surrounding whitespace", "apis[0].attributes[0].value", func(c *gatewayapi.Config) { c.APIs[0].Attributes[0].Value.Text = " metrics:read " }},
		{"invalid UTF-8", "apis[0].attributes[0].value", func(c *gatewayapi.Config) { c.APIs[0].Attributes[0].Value.Text = string([]byte{0xff}) }},
		{"other API label", "apis[1].metrics.labels.operation", func(c *gatewayapi.Config) {
			c.APIs[1].Metrics = &gatewayapi.APIMetrics{Labels: map[string]string{"operation": "role"}}
		}},
		{"public dynamic forwarding", "servers[0].apis[0].public", func(c *gatewayapi.Config) {
			c.APIs[0].Routes[0].Processing.RequestHeaders[0].FromAttribute = "tenant_id"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := loadConfigCase(t, "api-fixed-attributes")
			test.edit(&c)
			if err := Validate(c); err == nil || !strings.Contains(err.Error(), test.field) {
				t.Fatalf("validation error = %v, want %q", err, test.field)
			}
		})
	}
}

func TestAPIFixedAttributeSourceCollisions(t *testing.T) {
	for _, test := range []struct {
		name, fixture, attribute string
	}{
		{"authenticator", "jwt-auth-with-attributes", "tenant_id"},
		{"external authorization", "ext-authz", "requested_tenant"},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := loadConfigCase(t, test.fixture)
			c.APIs[0].Attributes = []gatewayapi.AttributeSource{testTextAttribute(test.attribute, "fixed", "fixed-value")}
			if err := Validate(c); err == nil || !strings.Contains(err.Error(), "conflicts with a fixed attribute") {
				t.Fatalf("validation error = %v, want source collision", err)
			}
		})
	}
}

func TestAPIFixedAttributesCloneInput(t *testing.T) {
	c := loadConfigCase(t, "api-fixed-attributes")
	defaulted := withDefaultsConfig(c)
	defaulted.APIs[0].Attributes[0].Name = "changed"
	defaulted.APIs[0].Attributes[0].Value.Text = "changed"
	if c.APIs[0].Attributes[0].Name != "role" || c.APIs[0].Attributes[0].Value.Text != "metrics:read" {
		t.Fatal("defaulting aliased fixed API attributes")
	}
}

func TestAPIFixedAttributesGenerateForPublicRoutes(t *testing.T) {
	c := loadConfigCase(t, "api-fixed-attributes")
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := decodeBootstrap(t, files.EnvoyBootstrap.Contents)
	manager := decodeHTTPManager(t, bootstrap.StaticResources.Listeners[0].FilterChains[0])
	var fixedFilter bool
	for _, filter := range manager.HttpFilters {
		fixedFilter = fixedFilter || filter.Name == apiFixedAttributeFilterName
	}
	if !fixedFilter {
		t.Fatal("fixed attribute filter is missing from the public HTTP manager")
	}
	routes := manager.GetRouteConfig().GetVirtualHosts()[0].GetRoutes()
	matched := namedRoute(routes, apiRouteName(0, "metrics", 0, 0))
	if matched == nil {
		t.Fatal("metrics route is missing")
	}
	assertFixedRouteAttributes(t, matched, map[string]string{"api": "metrics", "role": "metrics:read"})
	metrics := matched.GetMetadata().GetFilterMetadata()[requestMetricsFilterName]
	if got := metrics.Fields["labels"].GetStructValue().Fields["operation"].GetStringValue(); got != "role" {
		t.Fatalf("metric label source = %q, want role", got)
	}
	if matched.TypedPerFilterConfig[requiredHeaderFilterName] == nil || matched.TypedPerFilterConfig[headerMutationFilterName] == nil {
		t.Fatal("public route does not enforce or forward its fixed request header")
	}
	for _, generated := range routes {
		if generated.Name == matched.Name {
			continue
		}
		if generated.TypedPerFilterConfig[apiFixedAttributeFilterName] != nil || generated.GetMetadata().GetFilterMetadata()[apiFixedAttributeFilterName] != nil {
			t.Fatalf("route %q received another API's fixed attributes", generated.Name)
		}
	}
}

func TestAPIFixedAttributesGenerateForProtectedRoutes(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-with-attributes")
	c.APIs[0].Attributes = []gatewayapi.AttributeSource{testTextAttribute("role", "fixed", "metrics:write")}
	c.APIs[0].Metrics.Labels["operation"] = "role"
	c.APIs[0].Routes[0].Processing.RequestHeaders = append(c.APIs[0].Routes[0].Processing.RequestHeaders,
		gatewayapi.RequestHeaderMapping{Name: "X-Operation", FromAttribute: "role"})
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	manager := firstHTTPManager(t, files.EnvoyBootstrap.Contents)
	routes := manager.GetRouteConfig().GetVirtualHosts()[0].GetRoutes()
	base := apiRouteName(0, "metrics-write", 0, 0)
	for _, name := range []string{base + "-access-0-match-0", base + "-access-denied"} {
		generated := namedRoute(routes, name)
		if generated == nil {
			t.Fatalf("route %q is missing", name)
		}
		assertFixedRouteAttributes(t, generated, map[string]string{"role": "metrics:write"})
	}
	if namedRoute(routes, base+"-access-0-match-0").TypedPerFilterConfig[attributeFilterName] == nil {
		t.Fatal("fixed attributes displaced credential attributes")
	}
	if namedRoute(routes, base+"-access-denied").TypedPerFilterConfig[attributeFilterName] != nil {
		t.Fatal("access-denied route initializes credential attributes")
	}
}

func TestAPIFixedAttributesReachExternalAuthorization(t *testing.T) {
	c := loadConfigCase(t, "ext-authz")
	c.APIs[0].Attributes = []gatewayapi.AttributeSource{testTextAttribute("role", "fixed", "metrics:read")}
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	manager := firstHTTPManager(t, files.EnvoyBootstrap.Contents)
	routes := manager.GetRouteConfig().GetVirtualHosts()[0].GetRoutes()
	var generated *route.Route
	for _, candidate := range routes {
		if candidate.TypedPerFilterConfig[extAuthzAttributeBridgeName] != nil {
			generated = candidate
			break
		}
	}
	if generated == nil {
		t.Fatal("external authorization route is missing")
	}
	assertFixedRouteAttributes(t, generated, map[string]string{"role": "metrics:read"})
	var bridge lua.LuaPerRoute
	if err := generated.TypedPerFilterConfig[extAuthzAttributeBridgeName].UnmarshalTo(&bridge); err != nil {
		t.Fatal(err)
	}
	script := bridge.GetSourceCode().GetInlineString()
	if !strings.Contains(script, `state:get("auth_gateway.attributes.role")`) ||
		!strings.Contains(script, `metadata:set("auth_gateway.ext_authz.attributes", "role", value)`) {
		t.Fatalf("external authorization bridge omits fixed role: %s", script)
	}
}

func assertFixedRouteAttributes(t *testing.T, generated *route.Route, want map[string]string) {
	t.Helper()
	metadata := generated.GetMetadata().GetFilterMetadata()[apiFixedAttributeFilterName]
	if metadata == nil || len(metadata.Fields) != len(want) {
		t.Fatalf("route %q fixed metadata = %v, want %v", generated.Name, metadata, want)
	}
	for name, value := range want {
		if got := metadata.Fields[name].GetStringValue(); got != value {
			t.Fatalf("route %q attribute %q = %q, want %q", generated.Name, name, got, value)
		}
	}
	var wrapper route.FilterConfig
	packed := generated.TypedPerFilterConfig[apiFixedAttributeFilterName]
	if packed == nil || packed.UnmarshalTo(&wrapper) != nil {
		t.Fatalf("route %q has no fixed attribute filter config", generated.Name)
	}
	var config setfilterstate.Config
	if err := wrapper.GetConfig().UnmarshalTo(&config); err != nil {
		t.Fatal(err)
	}
	if len(config.OnRequestHeaders) != len(want) {
		t.Fatalf("route %q initializes %d attributes, want %d", generated.Name, len(config.OnRequestHeaders), len(want))
	}
	for _, update := range config.OnRequestHeaders {
		name := strings.TrimPrefix(update.GetObjectKey(), managedAttributePrefix)
		format := update.GetFormatString().GetTextFormatSource().GetInlineString()
		if _, ok := want[name]; !ok || format != "%METADATA(ROUTE:"+apiFixedAttributeFilterName+":"+name+")%" {
			t.Fatalf("route %q update = %v", generated.Name, update)
		}
	}
}
