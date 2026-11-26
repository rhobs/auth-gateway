package gateway

import (
	"slices"
	"strings"
	"testing"

	extauthz "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	jwt "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/jwt_authn/v3"
	lua "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/lua/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
)

func TestExternalAuthorizationValidation(t *testing.T) {
	cases := []struct {
		name string
		want string
		edit func(*gatewayapi.Config)
	}{
		{"unknown service", "authorization.ext_authz.service references unknown service", func(c *gatewayapi.Config) {
			c.Servers[0].APIs[0].Access[0].Authorization.ExtAuthz.Service = "missing"
		}},
		{"grants and external", "authorization must select exactly one", func(c *gatewayapi.Config) {
			c.Servers[0].APIs[0].Access[0].Authorization.Grants = []gatewayapi.AuthorizationGrant{{Authenticator: "internal-jwt"}}
		}},
		{"empty grants and external", "authorization must select exactly one", func(c *gatewayapi.Config) {
			c.Servers[0].APIs[0].Access[0].Authorization.Grants = []gatewayapi.AuthorizationGrant{}
		}},
		{"missing service TLS", "ext_authz_services[0].upstream.tls_config is required", func(c *gatewayapi.Config) {
			c.ExtAuthzServices[0].Upstream.TLSConfig = nil
		}},
		{"HTTP/1 service", "ext_authz_services[0].upstream.http_protocol must be http2", func(c *gatewayapi.Config) {
			c.ExtAuthzServices[0].Upstream.HTTPProtocol = "http1"
		}},
		{"no request allowlist", "request_headers must not be empty", func(c *gatewayapi.Config) {
			c.ExtAuthzServices[0].RequestHeaders = nil
		}},
		{"unlisted credential header", "credential_headers must contain distinct request_headers", func(c *gatewayapi.Config) {
			c.ExtAuthzServices[0].CredentialHeaders = []string{"x-other"}
		}},
		{"undeclared header", "attributes[0].from.header must name a safe request_headers entry", func(c *gatewayapi.Config) {
			*c.ExtAuthzServices[0].Attributes[0].From.Header = "X-Other"
		}},
		{"credential as attribute", "attributes[0].from.header must name a safe request_headers entry", func(c *gatewayapi.Config) {
			*c.ExtAuthzServices[0].Attributes[0].From.Header = "Authorization"
		}},
		{"invalid source", "attributes[0].from must select exactly one of header or attribute", func(c *gatewayapi.Config) {
			c.ExtAuthzServices[0].Attributes[0].From = gatewayapi.SourceReference{Claim: []string{"role"}}
		}},
		{"duplicate attribute", "attributes[1].name must be a unique valid attribute name", func(c *gatewayapi.Config) {
			c.ExtAuthzServices[0].Attributes[1].Name = "requested_tenant"
		}},
		{"authenticator attribute alias", "attributes[1].from.attribute must match name", func(c *gatewayapi.Config) {
			*c.ExtAuthzServices[0].Attributes[1].From.Attribute = "writer_id"
		}},
		{"missing authenticator attribute", "service attribute \"missing\" requires an attribute", func(c *gatewayapi.Config) {
			c.ExtAuthzServices[0].Attributes[1].Name = "missing"
			*c.ExtAuthzServices[0].Attributes[1].From.Attribute = "missing"
		}},
		{"header attribute collision", "service attribute \"requested_tenant\" collides", func(c *gatewayapi.Config) {
			c.Authenticators[0].Attributes = append(c.Authenticators[0].Attributes, gatewayapi.AttributeSource{Name: "requested_tenant", From: gatewayapi.SourceReference{Header: new("X-Tenant")}})
		}},
		{"missing forwarded attribute", "does not provide processing attribute", func(c *gatewayapi.Config) {
			c.ExtAuthzServices[0].Attributes = c.ExtAuthzServices[0].Attributes[1:]
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			c := loadConfigCase(t, "ext-authz")
			test.edit(&c)
			if err := Validate(c); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate() = %v, want %q", err, test.want)
			}
		})
	}
}

func TestExternalAuthorizationGeneratedFilterAndRoutes(t *testing.T) {
	c := loadConfigCase(t, "ext-authz")
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := decodeBootstrap(t, files.EnvoyBootstrap.Contents)
	if len(bootstrap.GetStaticResources().GetClusters()) != 3 {
		t.Fatalf("clusters = %d, want API, JWKS, and external authorization", len(bootstrap.GetStaticResources().GetClusters()))
	}
	manager := firstHTTPManager(t, files.EnvoyBootstrap.Contents)
	var filter *extauthz.ExtAuthz
	var filterPosition, bridgePosition, attributePosition, rbacPosition int
	var jwtFilter *jwt.JwtAuthentication
	for index, item := range manager.GetHttpFilters() {
		switch item.GetName() {
		case jwtAuthnFilterName:
			jwtFilter = new(jwt.JwtAuthentication)
			if err := item.GetTypedConfig().UnmarshalTo(jwtFilter); err != nil {
				t.Fatal(err)
			}
		case attributeFilterName:
			attributePosition = index
		case extAuthzFilterName("policy"):
			filterPosition = index
			if !item.GetDisabled() {
				t.Fatal("external authorization must be disabled by default")
			}
			filter = new(extauthz.ExtAuthz)
			if err := item.GetTypedConfig().UnmarshalTo(filter); err != nil {
				t.Fatal(err)
			}
		case extAuthzAttributeBridgeName:
			bridgePosition = index
			var bridge lua.Lua
			if err := item.GetTypedConfig().UnmarshalTo(&bridge); err != nil {
				t.Fatal(err)
			}
			if bridge.GetClearRouteCache().GetValue() {
				t.Fatal("attribute bridge may clear the route cache")
			}
			if script := bridge.GetDefaultSourceCode().GetInlineString(); !strings.Contains(script, `context:get("attributes")`) ||
				!strings.Contains(script, "ipairs(attributes)") {
				t.Fatal("attribute bridge does not use the route's attribute list")
			}
		case authorizationFilterName:
			rbacPosition = index
		}
	}
	if filter == nil || jwtFilter == nil || attributePosition >= rbacPosition || rbacPosition >= bridgePosition || bridgePosition >= filterPosition {
		t.Fatalf("attribute, RBAC, bridge, and external check filter order = %d, %d, %d, %d", attributePosition, rbacPosition, bridgePosition, filterPosition)
	}
	if jwtFilter.GetProviders()["internal-jwt"].GetPayloadInMetadata() != "internal-jwt" {
		t.Fatal("verified JWT payload is not placed in metadata")
	}
	if filter.GetGrpcService().GetEnvoyGrpc().GetClusterName() != extAuthzClusterName("policy") || filter.GetFailureModeAllow() || filter.GetClearRouteCache() || filter.GetStatusOnError() == nil || !filter.GetDecoderHeaderMutationRules().GetDisallowAll().GetValue() {
		t.Fatalf("external authorization filter does not fail closed: %+v", filter)
	}
	if !slices.Equal(filter.GetMetadataContextNamespaces(), []string{extAuthzInputMetadataName, jwtAuthnFilterName}) || filter.GetEnableDynamicMetadataIngestion().GetValue() {
		t.Fatalf("external authorization metadata context = %v, want declared attributes and JWT claims only", filter.GetMetadataContextNamespaces())
	}
	for _, generated := range manager.GetRouteConfig().GetVirtualHosts()[0].GetRoutes() {
		if !strings.Contains(generated.GetName(), "-access-") || strings.HasSuffix(generated.GetName(), "-access-denied") {
			continue
		}
		var perRoute extauthz.ExtAuthzPerRoute
		if err := generated.GetTypedPerFilterConfig()[extAuthzFilterName("policy")].UnmarshalTo(&perRoute); err != nil {
			t.Fatal(err)
		}
		var bridge lua.LuaPerRoute
		if err := generated.GetTypedPerFilterConfig()[extAuthzAttributeBridgeName].UnmarshalTo(&bridge); err != nil {
			t.Fatal(err)
		}
		if perRoute.GetDisabled() || generated.GetMetadata().GetFilterMetadata()[extAuthzMetadataName] == nil ||
			bridge.GetOverride() != nil {
			t.Fatalf("route %q lacks the external check or declared attributes", generated.GetName())
		}
		assertConfigDiff(t, "external authorization attribute context", map[string]any{
			"attributes": []any{"auth_origin", "requested_tenant", "tenant_id"},
		}, bridge.GetFilterContext().AsMap())
	}
}

func TestExternalAuthorizationAfterMTLS(t *testing.T) {
	c := loadConfigCase(t, "mtls-auth")
	service := loadConfigCase(t, "ext-authz").ExtAuthzServices[0]
	service.Attributes = []gatewayapi.AttributeSource{
		{Name: "tenant_id", From: gatewayapi.SourceReference{Attribute: new("tenant_id")}},
		{Name: "requested_tenant", From: gatewayapi.SourceReference{Attribute: new("requested_tenant")}},
	}
	c.ExtAuthzServices = []gatewayapi.ExternalAuthorizationService{service}
	c.Servers[0].APIs[0].Access[0].Authorization = gatewayapi.Authorization{ExtAuthz: &gatewayapi.ExternalAuthorization{Service: "policy"}}
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := decodeBootstrap(t, files.EnvoyBootstrap.Contents)
	for _, listener := range bootstrap.GetStaticResources().GetListeners() {
		for _, chain := range listener.GetFilterChains() {
			manager := decodeHTTPManager(t, chain)
			if !containsFilter(manager, extAuthzFilterName("policy")) {
				continue
			}
			for _, generated := range manager.GetRouteConfig().GetVirtualHosts()[0].GetRoutes() {
				if generated.GetTypedPerFilterConfig()[extAuthzFilterName("policy")] == nil {
					continue
				}
				var bridge lua.LuaPerRoute
				if err := generated.GetTypedPerFilterConfig()[extAuthzAttributeBridgeName].UnmarshalTo(&bridge); err != nil {
					t.Fatal(err)
				}
				assertConfigDiff(t, "mTLS attribute context", map[string]any{
					"attributes": []any{"requested_tenant", "tenant_id"},
				}, bridge.GetFilterContext().AsMap())
				return
			}
		}
	}
	t.Fatal("mTLS access route has no external authorization filter")
}

func TestExternalAuthorizationBridgeContextIsRouteScoped(t *testing.T) {
	c := loadConfigCase(t, "ext-authz")
	c.APIs[0].Attributes = []gatewayapi.AttributeSource{testTextAttribute("role", "fixed", "metrics:read")}
	headersOnly := c.ExtAuthzServices[0]
	headersOnly.Name = "headers-only"
	headersOnly.Attributes = []gatewayapi.AttributeSource{testTextAttribute("requested_tenant", "header", "X-Tenant")}
	c.ExtAuthzServices = append(c.ExtAuthzServices, headersOnly)
	c.Servers[0].APIs[0].Access[1].Authorization.ExtAuthz.Service = "headers-only"
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	host := firstHTTPManager(t, files.EnvoyBootstrap.Contents).GetRouteConfig().GetVirtualHosts()[0]
	for _, test := range []struct {
		name string
		want []any
	}{
		{"api-0-metrics-route-0-access-0-match-0", []any{"auth_origin", "requested_tenant", "role", "tenant_id"}},
		{"api-0-metrics-route-0-access-1-match-0", []any{"requested_tenant", "role"}},
	} {
		generated := namedRoute(host.Routes, test.name)
		if generated == nil {
			t.Fatalf("route %q is missing", test.name)
		}
		var bridge lua.LuaPerRoute
		if err := generated.GetTypedPerFilterConfig()[extAuthzAttributeBridgeName].UnmarshalTo(&bridge); err != nil {
			t.Fatal(err)
		}
		if bridge.GetOverride() != nil {
			t.Fatalf("route %q overrides the shared Lua script", test.name)
		}
		assertConfigDiff(t, test.name, map[string]any{"attributes": test.want}, bridge.GetFilterContext().AsMap())
	}
	for _, generated := range host.Routes {
		if generated.GetDirectResponse() != nil && generated.GetTypedPerFilterConfig()[extAuthzAttributeBridgeName] != nil {
			t.Fatalf("local response %q received attribute context", generated.Name)
		}
	}
}

func TestExternalAuthorizationBridgeSupportsEmptyAttributes(t *testing.T) {
	packed, err := extAuthzAttributeBridgePerRouteConfig(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var bridge lua.LuaPerRoute
	if err := packed.UnmarshalTo(&bridge); err != nil {
		t.Fatal(err)
	}
	assertConfigDiff(t, "empty attribute context", map[string]any{"attributes": []any{}}, bridge.GetFilterContext().AsMap())
}
