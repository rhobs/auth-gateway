//go:build e2e

package e2e

import (
	"net/http"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const faultInjectionJWTHost = "fault.jwt.auth-gateway.test"

var faultInjectionJWTNamespace = e2eNamespace("fault-injection-jwt-e2e")

var _ = Describe("JWT tenant fault injection", Label("gateway", "jwt", "fault-injection", "namespace-"+faultInjectionJWTNamespace), Ordered, func() {
	var gateway *jwtE2E
	var adminAddress string

	BeforeAll(func(ctx SpecContext) {
		DeferCleanup(func() { deleteNamespaceInBackground(faultInjectionJWTNamespace) })
		var err error
		gateway, err = setupJWTGateway(ctx, faultInjectionJWTNamespace, "fault-injection-jwt.yaml")
		Expect(err).NotTo(HaveOccurred())
		adminAddress = env.ForwardEnvoyAdminWithCleanup(ctx, faultInjectionJWTNamespace)
	}, NodeTimeout(10*time.Minute))

	It("injects faults using the verified JWT tenant without a header trigger", func(ctx SpecContext) {
		labels := map[string]string{"api": "injected", "http_status_code": "503", "tenant": "customer-a"}
		before, err := requestMetricCount(ctx, adminAddress, labels)
		Expect(err).NotTo(HaveOccurred())
		token := gateway.token("issuer-one", jwtTestClaims("customer-a"), nil)
		expectDeniedBeforeUpstream(ctx, adminAddress, "api-injected", "selected JWT tenant", http.StatusServiceUnavailable, func() (int, []byte, error) {
			return gateway.requestMethodPathHeaders(ctx, gateway.httpAddr, faultInjectionJWTHost, false, http.MethodGet, "/injected/probe", token,
				http.Header{"X-Scope-Orgid": []string{"customer-b"}})
		})
		after, err := requestMetricCount(ctx, adminAddress, labels)
		Expect(err).NotTo(HaveOccurred())
		Expect(after).To(Equal(before + 1))
	}, NodeTimeout(60*time.Second))

	It("forwards other JWT tenants despite a spoofed tenant header", func(ctx SpecContext) {
		token := gateway.token("issuer-one", jwtTestClaims("customer-b"), nil)
		status, body := expectUpstreamRequestDelta(ctx, adminAddress, "api-injected", "other JWT tenant", 1, func() (int, []byte, error) {
			return gateway.requestMethodPathHeaders(ctx, gateway.httpAddr, faultInjectionJWTHost, false, http.MethodGet, "/injected/probe?source=jwt", token,
				http.Header{"X-Scope-Orgid": []string{"customer-a"}})
		})
		Expect(status).To(Equal(http.StatusOK), string(body))
		echo, err := decodeHTTPBinEcho(body)
		Expect(err).NotTo(HaveOccurred())
		Expect(echo.Method).To(Equal(http.MethodGet))
		Expect(echo.URL).To(HaveSuffix("/anything/injected/probe?source=jwt"))
		Expect(echo.Data).To(BeEmpty())
		Expect(headerValue(echo.Headers, "X-Scope-OrgID")).To(Equal("customer-b"))
		Expect(headerValue(echo.Headers, "Authorization")).To(BeEmpty())
	}, NodeTimeout(60*time.Second))

	It("preserves JWT authentication and authorization denials", func(ctx SpecContext) {
		for _, test := range []struct {
			token  string
			status int
		}{
			{token: gateway.token("issuer-one", jwtTestClaims("customer-a"), gateway.wrongKey), status: http.StatusUnauthorized},
			{token: gateway.token("issuer-one", jwtTestClaims("customer-denied"), nil), status: http.StatusForbidden},
		} {
			expectDeniedBeforeUpstream(ctx, adminAddress, "api-injected", "denied JWT", test.status, func() (int, []byte, error) {
				return gateway.requestPath(ctx, gateway.httpAddr, faultInjectionJWTHost, false, "/injected/probe", test.token, false)
			})
		}
	}, NodeTimeout(60*time.Second))
})
