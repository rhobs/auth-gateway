//go:build e2e

package e2e

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	gatewayconfig "github.com/rhobs/auth-gateway/pkg/gateway"
)

const accessJourneyHost = "access.auth-gateway.test"

var identityIsolationNamespace = e2eNamespace("auth-gateway-tenant-access-e2e")

var _ = Describe("Tenant and resource isolation", Label("gateway", "identity-isolation", "authentication", "authorization", "namespace-"+identityIsolationNamespace), Ordered, ContinueOnFailure, func() {
	var gateway *apiKeyE2E
	var token func(string, any, string) string
	BeforeAll(func(ctx SpecContext) {
		DeferCleanup(func() { deleteNamespaceInBackground(identityIsolationNamespace) })
		var err error
		credentials := append(baselineAPIKeyCredentials(), gatewayapi.APIKeyCredential{Key: "journey-key", Attributes: map[string]string{"tenant_id": "key-a", "role": "writer", "writer_id": "key-writer"}})
		gateway, err = setupAPIKeyGatewayWithShape(ctx, identityIsolationNamespace, false, credentials, apiKeySharedSecretKey, func(c *gatewayapi.Config) {
			fixture, err := env.Fixture("tenant-access.yaml")
			Expect(err).NotTo(HaveOccurred())
			journey, err := gatewayconfig.Load(bytes.NewReader(fixture))
			Expect(err).NotTo(HaveOccurred())
			for index := range c.Authenticators {
				c.Authenticators[index].Attributes = journey.Authenticators[index].Attributes
			}
			c.APIs = append(c.APIs, journey.APIs...)
			c.Servers = append(c.Servers, journey.Servers...)
		})
		Expect(err).NotTo(HaveOccurred())
		token = func(issuer string, tenant any, role string) string {
			claims := map[string]any{"aud": "gateway-test", "exp": time.Now().Add(5 * time.Minute).Unix(), "sub": "journey-writer"}
			if issuer == "issuer-one" {
				claims["organization"], claims["role"] = map[string]any{"id": tenant}, role
			} else {
				claims["account"], claims["permissions"] = map[string]any{"tenant": tenant}, map[string]any{"role": role}
			}
			return (&jwtE2E{keys: gateway.keys}).token(issuer, claims, nil)
		}
	}, NodeTimeout(12*time.Minute))

	It("supports concrete JWT tenants, shared JWT tenants, API keys, and multiple read issuers", func(ctx SpecContext) {
		for _, test := range []struct{ name, tenant, verified, method, path, token, key string }{
			{"external writer", "external-a", "external-org", http.MethodPost, "/write", token("issuer-two", "external-org", "writer"), ""},
			{"internal writer A", "client-a", "client-a", http.MethodPost, "/write", token("issuer-one", "client-a", "writer"), ""},
			{"internal writer B", "client-b", "client-b", http.MethodPost, "/write", token("issuer-one", "client-b", "writer"), ""},
			{"key writer", "key-a", "key-a", http.MethodPost, "/write", "", "journey-key"},
			{"internal reader", "client-a", "", http.MethodGet, "/read", token("issuer-one", "client-a", "reader"), ""},
			{"external reader", "client-b", "", http.MethodGet, "/read", token("issuer-two", "client-b", "viewer"), ""},
		} {
			payload, cluster := "", "api-journey-read"
			if test.method == http.MethodPost {
				payload, cluster = apiKeyRequestBody, "api-journey-write"
			}
			headers := http.Header{"X-Tenant": []string{test.tenant}, "X-Environment": []string{"production"}, "X-Scope-OrgID": []string{"spoofed"}, "X-Verified-Tenant": []string{"spoofed"}}
			status, body := expectUpstreamRequestDelta(ctx, gateway.adminAddr, cluster, test.name, 1, func() (int, []byte, error) {
				return gateway.request(ctx, accessJourneyHost, false, test.method, test.path, payload, test.token, test.key, headers)
			})
			Expect(status).To(Equal(http.StatusOK), test.name+": "+string(body))
			echo, err := decodeHTTPBinEcho(body)
			Expect(err).NotTo(HaveOccurred())
			Expect(echo.Method).To(Equal(test.method))
			Expect(echo.URL).To(HaveSuffix("/anything"))
			if payload == "" {
				Expect(echo.Data).To(BeEmpty())
			} else {
				Expect(echo.Data).To(Equal("data:application/octet-stream;base64," + base64.StdEncoding.EncodeToString([]byte(payload))))
			}
			Expect(headerValue(echo.Headers, "X-Scope-OrgID")).To(Equal(test.tenant))
			Expect(headerValue(echo.Headers, "X-Verified-Tenant")).To(Equal(test.verified))
			Expect(headerValue(echo.Headers, "X-Tenant")).To(Equal(test.tenant))
			for _, name := range []string{"Authorization", "X-Partner-Key", "X-Auth-Gateway-API-Key-Client", "X-Auth-Gateway-Request-Validation-Pending"} {
				Expect(headerValue(echo.Headers, name)).To(BeEmpty(), name)
			}
		}
	}, NodeTimeout(2*time.Minute))

	It("injects a fault from the selected API-key credential attribute", func(ctx SpecContext) {
		headers := http.Header{"X-Tenant": []string{"key-a"}, "X-Environment": []string{"production"}, "X-Inject-Fault": []string{"true"}}
		expectDeniedBeforeUpstream(ctx, gateway.adminAddr, "api-journey-write", "API-key writer fault", http.StatusServiceUnavailable, func() (int, []byte, error) {
			return gateway.request(ctx, accessJourneyHost, false, http.MethodPost, "/write", apiKeyRequestBody, "", "journey-key", headers)
		})
	}, NodeTimeout(60*time.Second))

	It("forwards a JWT request when its selected path has no matching attribute", func(ctx SpecContext) {
		headers := http.Header{"X-Tenant": []string{"client-a"}, "X-Environment": []string{"production"}, "X-Inject-Fault": []string{"true"}}
		status, body := expectUpstreamRequestDelta(ctx, gateway.adminAddr, "api-journey-write", "JWT without writer attribute", 1, func() (int, []byte, error) {
			return gateway.request(ctx, accessJourneyHost, false, http.MethodPost, "/write", apiKeyRequestBody, token("issuer-one", "client-a", "writer"), "", headers)
		})
		Expect(status).To(Equal(http.StatusOK), string(body))
		echo, err := decodeHTTPBinEcho(body)
		Expect(err).NotTo(HaveOccurred())
		Expect(echo.Method).To(Equal(http.MethodPost))
		Expect(echo.URL).To(HaveSuffix("/anything"))
		Expect(headerValue(echo.Headers, "X-Verified-Tenant")).To(Equal("client-a"))
	}, NodeTimeout(60*time.Second))

	It("matches a declared header attribute after JWT authorization", func(ctx SpecContext) {
		headers := http.Header{"X-Tenant": []string{"client-a"}, "X-Environment": []string{"production"}, "X-Inject-Fault": []string{"true"}, "X-Writer": []string{"key-writer"}}
		expectDeniedBeforeUpstream(ctx, gateway.adminAddr, "api-journey-write", "JWT header attribute fault", http.StatusServiceUnavailable, func() (int, []byte, error) {
			return gateway.request(ctx, accessJourneyHost, false, http.MethodPost, "/write", apiKeyRequestBody, token("issuer-one", "client-a", "writer"), "", headers)
		})
	}, NodeTimeout(60*time.Second))

	registerIdentityDeniedSpecs(func() (*apiKeyE2E, func(string, any, string) string) { return gateway, token })

	It("keeps public APIs explicit on the same host", func(ctx SpecContext) {
		status, body, err := gateway.request(ctx, accessJourneyHost, false, http.MethodGet, "/health", "", "broken.jwt", "", nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(status).To(Equal(http.StatusOK), string(body))
		echo, err := decodeHTTPBinEcho(body)
		Expect(err).NotTo(HaveOccurred())
		Expect(echo.Method).To(Equal(http.MethodGet))
		Expect(echo.URL).To(HaveSuffix("/anything"))
		Expect(echo.Data).To(BeEmpty())
		Expect(headerValue(echo.Headers, "Authorization")).To(BeEmpty())
		Expect(headerValue(echo.Headers, "X-Partner-Key")).To(BeEmpty())
	}, NodeTimeout(60*time.Second))
})
