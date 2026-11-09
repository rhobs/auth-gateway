package gateway

import (
	"strings"
	"testing"

	extauthz "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
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
		{"invalid response path", "response_attributes.requested_tenant must have a valid name and nonempty path", func(c *gatewayapi.Config) {
			c.Servers[0].APIs[0].Access[0].Authorization.ExtAuthz.ResponseAttributes["requested_tenant"] = nil
		}},
		{"attribute collision", "response_attributes.tenant_id collides with authenticator", func(c *gatewayapi.Config) {
			c.Servers[0].APIs[0].Access[0].Authorization.ExtAuthz.ResponseAttributes["tenant_id"] = []string{"identity", "tenant"}
		}},
		{"missing forwarded attribute", "does not provide processing attribute", func(c *gatewayapi.Config) {
			c.Servers[0].APIs[0].Access[1].Authorization.ExtAuthz.ResponseAttributes = nil
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
	var filterPosition, attributePosition, rbacPosition int
	for index, item := range manager.GetHttpFilters() {
		switch item.GetName() {
		case extAuthzFilterName("policy"):
			filterPosition = index
			if !item.GetDisabled() {
				t.Fatal("external authorization must be disabled by default")
			}
			filter = new(extauthz.ExtAuthz)
			if err := item.GetTypedConfig().UnmarshalTo(filter); err != nil {
				t.Fatal(err)
			}
		case extAuthzAttributeFilterName:
			attributePosition = index
		case authorizationFilterName:
			rbacPosition = index
		}
	}
	if filter == nil || rbacPosition >= filterPosition || filterPosition >= attributePosition {
		t.Fatalf("RBAC, external check, and response attribute filter order = %d, %d, %d", rbacPosition, filterPosition, attributePosition)
	}
	if filter.GetGrpcService().GetEnvoyGrpc().GetClusterName() != extAuthzClusterName("policy") || filter.GetFailureModeAllow() || filter.GetClearRouteCache() || filter.GetStatusOnError() == nil || !filter.GetDecoderHeaderMutationRules().GetDisallowAll().GetValue() {
		t.Fatalf("external authorization filter does not fail closed: %+v", filter)
	}
	for _, generated := range manager.GetRouteConfig().GetVirtualHosts()[0].GetRoutes() {
		if !strings.Contains(generated.GetName(), "-access-") || strings.HasSuffix(generated.GetName(), "-access-denied") {
			continue
		}
		var perRoute extauthz.ExtAuthzPerRoute
		if err := generated.GetTypedPerFilterConfig()[extAuthzFilterName("policy")].UnmarshalTo(&perRoute); err != nil {
			t.Fatal(err)
		}
		if perRoute.GetDisabled() || generated.GetTypedPerFilterConfig()[extAuthzAttributeFilterName] == nil || generated.GetMetadata().GetFilterMetadata()[extAuthzMetadataName] == nil {
			t.Fatalf("route %q lacks external check or response attributes", generated.GetName())
		}
	}
}
