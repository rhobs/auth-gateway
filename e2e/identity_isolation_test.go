//go:build e2e

package e2e

import (
	"crypto/tls"
	"net/http"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/rhobs/auth-gateway/config"
)

var identityIsolationNamespace = e2eNamespace("auth-gateway-identity-e2e")

var _ = Describe("Mixed identity isolation", Label("gateway", "identity-isolation", "authentication", "authorization", "namespace-"+identityIsolationNamespace), Ordered, ContinueOnFailure, func() {
	var gateway *mtlsE2E

	BeforeAll(func(ctx SpecContext) {
		DeferCleanup(func() { deleteNamespaceInBackground(identityIsolationNamespace) })
		var err error
		gateway, err = setupMTLSGatewayWithShape(ctx, identityIsolationNamespace, func(c *config.Config) {
			c.Authenticators[0].Attributes["writer_id"] = config.AttributeSource{ClaimPath: []string{"sub"}}
			c.Authenticators[0].Attributes["requested_tenant"] = config.AttributeSource{Header: new("X-JWT-Tenant")}
			c.AuthorizationPolicies[0].Grants[0].Attributes = map[string][]string{"writer_id": {"writer-a"}}
			for _, index := range []int{1, 2} {
				c.Servers[index].Authorization.AnyOf = []string{"jwt-writers"}
			}
			certificateRoute := c.APIs[0].Routes[0]
			certificateRoute.Path.Exact = "/certificate-attribute"
			certificateRoute.Processing = &config.RouteProcessing{RequestHeaders: []config.RequestHeaderMapping{
				{Name: "X-Certificate-DNS", FromAttribute: "dns_id"},
			}}
			c.APIs[0].Routes = append(c.APIs[0].Routes, certificateRoute)
			headerRoute := c.APIs[0].Routes[0]
			headerRoute.Path.Exact = "/header-attribute"
			headerRoute.Processing = &config.RouteProcessing{RequestHeaders: []config.RequestHeaderMapping{
				{Name: "X-Scope-OrgID", FromAttribute: "tenant_id"},
				{Name: "X-Requested-Tenant", FromAttribute: "requested_tenant"},
			}}
			c.APIs[0].Routes = append(c.APIs[0].Routes, headerRoute)
			c.AuthorizationPolicies[3].Grants[0].APIs = []string{"ingest", "probe"}
			certificateKeyServer := c.Servers[1]
			certificateKeyServer.Hostname = "cert-key.mtls.auth-gateway.test"
			certificateKeyServer.Authentication = &config.Authentication{AnyOf: []string{"partner-key", "client-cert"}}
			certificateKeyServer.Authorization = &config.Authorization{AnyOf: []string{"trusted-clients", "key-writers"}}
			c.Servers = append(c.Servers, certificateKeyServer)
		})
		Expect(err).NotTo(HaveOccurred())
	}, NodeTimeout(12*time.Minute))
	BeforeEach(func(ctx SpecContext) {
		gateway.address = env.ForwardWithCleanup(ctx, identityIsolationNamespace, "service/auth-gateway", 443)
	})

	It("does not combine a JWT grant with another identity's tenant", func(ctx SpecContext) {
		for _, host := range []string{mtlsJWTCertHost, mtlsMixedHost} {
			expectMTLSDenied(ctx, gateway, "certificate without a JWT grant", host, &gateway.allowed, "", "", mtlsRequestHeaders(), http.StatusForbidden)
		}
		for _, test := range []struct {
			name         string
			organization any
		}{
			{name: "missing tenant"},
			{name: "missing nested tenant", organization: map[string]any{}},
			{name: "empty tenant", organization: map[string]any{"id": ""}},
			{name: "non-string tenant", organization: map[string]any{"id": []string{mtlsAllowedURI}}},
		} {
			claims := map[string]any{"sub": "writer-a", "aud": "gateway-test", "exp": time.Now().Add(5 * time.Minute).Unix()}
			if test.organization != nil {
				claims["organization"] = test.organization
			}
			token := (&jwtE2E{keys: gateway.keys}).token("issuer-one", claims, nil)
			for _, host := range []string{mtlsJWTCertHost, mtlsMixedHost} {
				for _, certificate := range []*tls.Certificate{nil, &gateway.allowed} {
					expectMTLSDenied(ctx, gateway, test.name, host, certificate, token, mtlsAllowedKey, mtlsRequestHeaders(), http.StatusForbidden)
				}
			}
		}
	}, NodeTimeout(90*time.Second))

	It("does not borrow an attribute undeclared by the selected JWT identity", func(ctx SpecContext) {
		claims := map[string]any{
			"sub": "writer-a", "organization": map[string]any{"id": mtlsSecondURI},
			"aud": "gateway-test", "exp": time.Now().Add(5 * time.Minute).Unix(),
		}
		token := (&jwtE2E{keys: gateway.keys}).token("issuer-one", claims, nil)
		expectDeniedBeforeUpstream(ctx, gateway.adminAddr, "api-ingest", "certificate-only attribute with JWT", http.StatusForbidden, func() (int, []byte, error) {
			return gateway.request(ctx, mtlsMixedHost, &gateway.allowed, token, mtlsAllowedKey,
				http.MethodPost, "/certificate-attribute", mtlsPayload, http.Header{"X-Certificate-DNS": []string{"caller-controlled"}})
		})
	}, NodeTimeout(60*time.Second))

	It("forwards the selected JWT's mapped tenant when credentials conflict", func(ctx SpecContext) {
		claims := map[string]any{
			"sub": "writer-a", "organization": map[string]any{"id": mtlsSecondURI},
			"aud": "gateway-test", "exp": time.Now().Add(5 * time.Minute).Unix(),
		}
		token := (&jwtE2E{keys: gateway.keys}).token("issuer-one", claims, nil)
		status, body := expectUpstreamRequestDelta(ctx, gateway.adminAddr, "api-ingest", "JWT before certificate and key", 1, func() (int, []byte, error) {
			return gateway.request(ctx, mtlsMixedHost, &gateway.allowed, token, mtlsAllowedKey,
				http.MethodPost, "/ingest", mtlsPayload, mtlsRequestHeaders())
		})
		Expect(status).To(Equal(http.StatusOK), string(body))
		expectMTLSEcho(body, "team-b")
	}, NodeTimeout(60*time.Second))

	It("uses only the selected JWT's request-header attribute", func(ctx SpecContext) {
		claims := map[string]any{
			"sub": "writer-a", "organization": map[string]any{"id": mtlsSecondURI},
			"aud": "gateway-test", "exp": time.Now().Add(5 * time.Minute).Unix(),
		}
		token := (&jwtE2E{keys: gateway.keys}).token("issuer-one", claims, nil)
		for _, test := range []struct {
			name   string
			value  *string
			status int
			delta  uint64
		}{
			{name: "missing JWT header", status: http.StatusForbidden},
			{name: "empty JWT header", value: new(""), status: http.StatusForbidden},
			{name: "selected JWT header", value: new("jwt-tenant"), status: http.StatusOK, delta: 1},
		} {
			headers := mtlsRequestHeaders()
			if test.value != nil {
				headers.Set("X-JWT-Tenant", *test.value)
			}
			status, body := expectUpstreamRequestDelta(ctx, gateway.adminAddr, "api-ingest", test.name, test.delta, func() (int, []byte, error) {
				return gateway.request(ctx, mtlsMixedHost, &gateway.allowed, token, mtlsAllowedKey,
					http.MethodPost, "/header-attribute", mtlsPayload, headers)
			})
			Expect(status).To(Equal(test.status), test.name+": "+string(body))
			if status != http.StatusOK {
				continue
			}
			expectMTLSEcho(body, "team-b")
			Expect(headerValue(jwtEchoHeaders(body), "X-Requested-Tenant")).To(Equal("jwt-tenant"))
		}
	}, NodeTimeout(60*time.Second))

	It("keeps a selected certificate's missing tenant from falling through to an API key", func(ctx SpecContext) {
		const host = "cert-key.mtls.auth-gateway.test"
		status, body := expectUpstreamRequestDelta(ctx, gateway.adminAddr, "api-ingest", "API key without certificate", 1, func() (int, []byte, error) {
			return gateway.request(ctx, host, nil, "", mtlsAllowedKey, http.MethodPost, "/ingest", mtlsPayload, mtlsRequestHeaders())
		})
		Expect(status).To(Equal(http.StatusOK), string(body))
		expectMTLSEcho(body, "team-a")
		for _, key := range []string{"", mtlsAllowedKey} {
			expectMTLSDenied(ctx, gateway, "SAN-less certificate", host, &gateway.noSAN, "", key, mtlsRequestHeaders(), http.StatusForbidden)
		}
	}, NodeTimeout(60*time.Second))
})
