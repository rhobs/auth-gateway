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
		{"undeclared header", "attributes[0].value must name a safe request_headers entry", func(c *gatewayapi.Config) {
			c.ExtAuthzServices[0].Attributes[0].Value.Text = "X-Other"
		}},
		{"credential as attribute", "attributes[0].value must name a safe request_headers entry", func(c *gatewayapi.Config) {
			c.ExtAuthzServices[0].Attributes[0].Value.Text = "Authorization"
		}},
		{"invalid source", "attributes[0].from_source must be header or authenticator", func(c *gatewayapi.Config) {
			c.ExtAuthzServices[0].Attributes[0].FromSource = "response"
		}},
		{"duplicate attribute", "attributes[1].name must be a unique valid attribute name", func(c *gatewayapi.Config) {
			c.ExtAuthzServices[0].Attributes[1].Name = "requested_tenant"
		}},
		{"authenticator attribute alias", "attributes[1].value must match name", func(c *gatewayapi.Config) {
			c.ExtAuthzServices[0].Attributes[1].Value.Text = "writer_id"
		}},
		{"missing authenticator attribute", "service attribute \"missing\" requires an attribute", func(c *gatewayapi.Config) {
			c.ExtAuthzServices[0].Attributes[1].Name = "missing"
			c.ExtAuthzServices[0].Attributes[1].Value.Text = "missing"
		}},
		{"header attribute collision", "service attribute \"requested_tenant\" collides", func(c *gatewayapi.Config) {
			c.Authenticators[0].Attributes = append(c.Authenticators[0].Attributes, gatewayapi.AttributeSource{Name: "requested_tenant", FromSource: "header", Value: gatewayapi.AttributeValue{Text: "X-Tenant"}})
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
		script := bridge.GetSourceCode().GetInlineString()
		if perRoute.GetDisabled() || generated.GetMetadata().GetFilterMetadata()[extAuthzMetadataName] == nil ||
			!strings.Contains(script, filterStateKey("requested_tenant")) || !strings.Contains(script, filterStateKey("tenant_id")) ||
			!strings.Contains(script, extAuthzInputMetadataName) {
			t.Fatalf("route %q lacks the external check or declared attributes", generated.GetName())
		}
	}
}

func TestExternalAuthorizationAfterMTLS(t *testing.T) {
	c := loadConfigCase(t, "mtls-auth")
	service := loadConfigCase(t, "ext-authz").ExtAuthzServices[0]
	service.Attributes = []gatewayapi.AttributeSource{
		{Name: "tenant_id", FromSource: "authenticator", Value: gatewayapi.AttributeValue{Text: "tenant_id"}},
		{Name: "requested_tenant", FromSource: "authenticator", Value: gatewayapi.AttributeValue{Text: "requested_tenant"}},
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
				script := bridge.GetSourceCode().GetInlineString()
				if !strings.Contains(script, filterStateKey("tenant_id")) || !strings.Contains(script, filterStateKey("requested_tenant")) {
					t.Fatalf("mTLS route %q does not send its declared attributes", generated.GetName())
				}
				return
			}
		}
	}
	t.Fatal("mTLS access route has no external authorization filter")
}
