//go:build e2e

package e2e

import (
	"bytes"
	"crypto/rsa"
	"fmt"
	"net/http"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/rhobs/auth-gateway/config"
)

var _ = Describe("Plain JWT authorization", Label("gateway", "jwt", "authentication", "authorization", "namespace-"+jwtPlainNamespace), Ordered, func() {
	BeforeAll(func(ctx SpecContext) {
		DeferCleanup(func(ctx SpecContext) { Expect(env.DeleteNamespace(ctx, jwtPlainNamespace)).To(Succeed()) }, NodeTimeout(3*time.Minute))
		var err error
		jwtPlainGateway, err = setupJWTGateway(ctx, jwtPlainNamespace, "jwt-auth.yaml")
		Expect(err).NotTo(HaveOccurred())
		jwtPlainGateway.adminAddr = env.ForwardEnvoyAdminWithCleanup(ctx, jwtPlainNamespace)
	}, NodeTimeout(12*time.Minute))

	It("skips audience validation when none is configured", func(ctx SpecContext) {
		for _, test := range []struct {
			name     string
			audience string
		}{
			{name: "missing aud claim"},
			{name: "unlisted aud claim", audience: "other-service"},
		} {
			claims := map[string]any{
				"x":   map[string]any{"my_list": []string{"y", "z"}},
				"exp": time.Now().Add(5 * time.Minute).Unix(),
			}
			if test.audience != "" {
				claims["aud"] = test.audience
			}
			token := jwtPlainGateway.token("issuer-one", claims, nil)
			status, body, err := jwtPlainGateway.request(ctx, jwtPlainGateway.httpAddr, jwtPlainHost, false, token, false)
			Expect(err).NotTo(HaveOccurred(), test.name)
			Expect(status).To(Equal(http.StatusOK), test.name+": "+string(body))

			echo, err := decodeHTTPBinEcho(body)
			Expect(err).NotTo(HaveOccurred(), test.name)
			Expect(echo.Method).To(Equal(http.MethodGet), test.name)
			Expect(echo.URL).To(HaveSuffix("/anything"), test.name)
			Expect(headerValue(echo.Headers, "Authorization")).To(BeEmpty(), test.name)
		}
	}, NodeTimeout(60*time.Second))

	It("authorizes each listed member and rejects an unlisted member", func(ctx SpecContext) {
		adminAddress := jwtPlainGateway.adminAddr
		for _, test := range []struct {
			name   string
			values []string
		}{
			{name: "y member", values: []string{"y"}},
			{name: "z member", values: []string{"z"}},
			{name: "both members", values: []string{"y", "z"}},
		} {
			claims := map[string]any{
				"x":   map[string]any{"my_list": test.values},
				"aud": "gateway-test",
				"exp": time.Now().Add(5 * time.Minute).Unix(),
			}
			token := jwtPlainGateway.token("issuer-one", claims, nil)
			status, body := expectUpstreamRequestDelta(ctx, adminAddress, "api-metrics", test.name, 1, func() (int, []byte, error) {
				return jwtPlainGateway.request(ctx, jwtPlainGateway.httpAddr, jwtPlainHost, false, token, false)
			})
			Expect(status).To(Equal(http.StatusOK), test.name+": "+string(body))
			echo, err := decodeHTTPBinEcho(body)
			Expect(err).NotTo(HaveOccurred(), test.name)
			Expect(echo.Method).To(Equal(http.MethodGet), test.name)
			Expect(echo.URL).To(HaveSuffix("/anything"), test.name)
			Expect(headerValue(echo.Headers, "Authorization")).To(BeEmpty(), test.name)
			Expect(headerValue(echo.Headers, "X-Scope-OrgID")).To(BeEmpty(), test.name)
		}
		disallowedClaims := map[string]any{
			"x": map[string]any{"my_list": []string{"unlisted"}}, "aud": "gateway-test", "exp": time.Now().Add(5 * time.Minute).Unix(),
		}
		disallowedToken := jwtPlainGateway.token("issuer-one", disallowedClaims, nil)
		expectDeniedBeforeUpstream(ctx, adminAddress, "api-metrics", "unlisted list member", http.StatusForbidden, func() (int, []byte, error) {
			return jwtPlainGateway.request(ctx, jwtPlainGateway.httpAddr, jwtPlainHost, false, disallowedToken, false)
		})
	}, SpecTimeout(90*time.Second))

	It("rejects invalid credentials and denied claims before the upstream", func(ctx SpecContext) {
		adminAddress := jwtPlainGateway.adminAddr

		allowed := map[string]any{"x": map[string]any{"my_list": []string{"y", "z"}}, "aud": "gateway-test", "exp": time.Now().Add(5 * time.Minute).Unix()}
		denied := map[string]any{"x": map[string]any{"my_list": []string{"unlisted"}}, "aud": "gateway-test", "exp": time.Now().Add(5 * time.Minute).Unix()}
		futureNotBefore := map[string]any{"x": map[string]any{"my_list": []string{"y"}}, "aud": "gateway-test", "exp": time.Now().Add(10 * time.Minute).Unix(), "nbf": time.Now().Add(5 * time.Minute).Unix()}
		cases := []struct {
			name   string
			token  string
			status int
		}{
			{name: "missing token", status: http.StatusUnauthorized},
			{name: "invalid signature", token: jwtPlainGateway.token("issuer-one", allowed, jwtPlainGateway.wrongKey), status: http.StatusUnauthorized},
			{name: "future not-before", token: jwtPlainGateway.token("issuer-one", futureNotBefore, nil), status: http.StatusUnauthorized},
			{name: "denied claim", token: jwtPlainGateway.token("issuer-one", denied, nil), status: http.StatusForbidden},
		}
		for _, test := range cases {
			expectDeniedBeforeUpstream(ctx, adminAddress, "api-metrics", test.name, test.status, func() (int, []byte, error) {
				return jwtPlainGateway.request(ctx, jwtPlainGateway.httpAddr, jwtPlainHost, false, test.token, false)
			})
		}

		var accessLogs []jwtEnvoyAccessLog
		var accessLogsErr error
		Eventually(func() bool {
			accessLogs, accessLogsErr = jwtEnvoyAccessLogs(ctx, jwtPlainNamespace)
			if accessLogsErr != nil {
				return false
			}
			for _, accessLog := range accessLogs {
				if accessLog.Status == http.StatusUnauthorized {
					return true
				}
			}
			return false
		}).WithContext(ctx).WithTimeout(15*time.Second).WithPolling(250*time.Millisecond).Should(BeTrue(), func() string {
			return fmt.Sprintf("expected a JSON 401 access log; got %+v (read error: %v)", accessLogs, accessLogsErr)
		})
		Expect(accessLogsErr).NotTo(HaveOccurred())
		foundUnauthorized := false
		for _, accessLog := range accessLogs {
			Expect(accessLog.Status).NotTo(Equal(http.StatusOK), "successful responses must not be logged: %+v", accessLog)
			if accessLog.Status == http.StatusUnauthorized {
				foundUnauthorized = true
				Expect(accessLog.ResponseCodeDetails).NotTo(BeEmpty(), "401 access log must include response_code_details")
			}
		}
		Expect(foundUnauthorized).To(BeTrue(), "expected a JSON 401 access log with response_code_details")
	}, NodeTimeout(60*time.Second))

	It("denies a valid JWT on a protected server with no selected policy", func(ctx SpecContext) {
		claims := map[string]any{
			"x":   map[string]any{"my_list": []string{"y"}},
			"aud": "gateway-test",
			"exp": time.Now().Add(5 * time.Minute).Unix(),
		}
		token := jwtPlainGateway.token("issuer-one", claims, nil)
		expectDeniedBeforeUpstream(ctx, jwtPlainGateway.adminAddr, "api-metrics", "valid JWT without an authorization policy", http.StatusForbidden, func() (int, []byte, error) {
			return jwtPlainGateway.request(ctx, jwtPlainGateway.httpAddr, jwtPlainNoPolicyHost, false, token, false)
		})
	}, NodeTimeout(60*time.Second))

	It("applies any_of and all_of policy decisions to the same authenticated request", func(ctx SpecContext) {
		for _, test := range []struct {
			name     string
			host     string
			values   []string
			status   int
			upstream uint64
		}{
			{name: "any_of accepts one policy grant", host: jwtPlainAnyPolicyHost, values: []string{"y"}, status: http.StatusOK, upstream: 1},
			{name: "all_of rejects a policy veto", host: jwtPlainAllPolicyHost, values: []string{"y"}, status: http.StatusForbidden},
			{name: "all_of accepts both policy grants", host: jwtPlainAllPolicyHost, values: []string{"y", "z"}, status: http.StatusOK, upstream: 1},
		} {
			claims := map[string]any{
				"x":   map[string]any{"my_list": test.values},
				"aud": "gateway-test",
				"exp": time.Now().Add(5 * time.Minute).Unix(),
			}
			token := jwtPlainGateway.token("issuer-one", claims, nil)
			status, body := expectUpstreamRequestDelta(ctx, jwtPlainGateway.adminAddr, "api-metrics", test.name, test.upstream, func() (int, []byte, error) {
				return jwtPlainGateway.request(ctx, jwtPlainGateway.httpAddr, test.host, false, token, false)
			})
			Expect(status).To(Equal(test.status), test.name+": "+string(body))
			if test.status != http.StatusOK {
				continue
			}
			echo, err := decodeHTTPBinEcho(body)
			Expect(err).NotTo(HaveOccurred(), test.name)
			Expect(echo.Method).To(Equal(http.MethodGet), test.name)
			Expect(echo.URL).To(HaveSuffix("/anything"), test.name)
			Expect(headerValue(echo.Headers, "Authorization")).To(BeEmpty(), test.name)
		}
	}, SpecTimeout(90*time.Second))
})

var _ = Describe("Direct JWT headers", Label("gateway", "jwt", "authentication", "authorization", "namespace-"+jwtHeadersNamespace), Ordered, func() {
	BeforeAll(func(ctx SpecContext) {
		DeferCleanup(func(ctx SpecContext) { Expect(env.DeleteNamespace(ctx, jwtHeadersNamespace)).To(Succeed()) }, NodeTimeout(3*time.Minute))
		var err error
		jwtHeadersGateway, err = setupJWTGateway(ctx, jwtHeadersNamespace, "jwt-auth-with-headers.yaml")
		Expect(err).NotTo(HaveOccurred())
		jwtHeadersGateway.adminAddr = env.ForwardEnvoyAdminWithCleanup(ctx, jwtHeadersNamespace)
	}, NodeTimeout(12*time.Minute))

	It("replaces caller-supplied managed headers with verified values", func(ctx SpecContext) {
		claims := map[string]any{
			"organization": map[string]any{"id": "customer-a"},
			"sub":          "writer-17",
			"aud":          "gateway-test",
			"exp":          time.Now().Add(5 * time.Minute).Unix(),
		}
		token := jwtHeadersGateway.token("issuer-one", claims, nil)
		status, body, err := jwtHeadersGateway.request(ctx, jwtHeadersGateway.httpAddr, jwtHeadersHost, false, token, true)
		Expect(err).NotTo(HaveOccurred())
		Expect(status).To(Equal(http.StatusOK), string(body))
		headers := jwtEchoHeaders(body)
		Expect(headerValue(headers, "X-Scope-OrgID")).To(Equal("customer-a"))
		Expect(headerValue(headers, "X-Writer-ID")).To(Equal("writer-17"))
		Expect(headerValue(headers, "Authorization")).To(BeEmpty())
	}, NodeTimeout(60*time.Second))

	It("authorizes with the original managed header before replacing it", func(ctx SpecContext) {
		token := jwtHeadersGateway.token("issuer-one", jwtTestClaims("customer-a"), nil)
		status, body, err := jwtHeadersGateway.requestMethodPathHeaders(ctx, jwtHeadersGateway.httpAddr, jwtManagedHeaderHost,
			false, http.MethodGet, "/protected", token, http.Header{"X-Scope-OrgID": []string{"requested-a"}})
		Expect(err).NotTo(HaveOccurred())
		Expect(status).To(Equal(http.StatusOK), string(body))
		echo, err := decodeHTTPBinEcho(body)
		Expect(err).NotTo(HaveOccurred())
		Expect(echo.Method).To(Equal(http.MethodGet))
		Expect(echo.URL).To(HaveSuffix("/anything"))
		Expect(headerValue(echo.Headers, "X-Scope-OrgID")).To(Equal("customer-a"))
		Expect(headerValue(echo.Headers, "X-Writer-ID")).To(Equal("writer-17"))
		Expect(headerValue(echo.Headers, "Authorization")).To(BeEmpty())

		expectDeniedBeforeUpstream(ctx, jwtHeadersGateway.adminAddr, "api-metrics", "denied managed header", http.StatusForbidden, func() (int, []byte, error) {
			return jwtHeadersGateway.requestMethodPathHeaders(ctx, jwtHeadersGateway.httpAddr, jwtManagedHeaderHost,
				false, http.MethodGet, "/protected", token, http.Header{"X-Scope-OrgID": []string{"requested-b"}})
		})
	}, NodeTimeout(90*time.Second))

	It("removes a managed input header on routes without that output", func(ctx SpecContext) {
		token := jwtHeadersGateway.token("issuer-one", jwtTestClaims("customer-a"), nil)
		status, body, err := jwtHeadersGateway.requestMethodPathHeaders(ctx, jwtHeadersGateway.httpAddr, jwtManagedHeaderHost,
			false, http.MethodGet, "/headerless", token, http.Header{"X-Scope-OrgID": []string{"requested-a"}})
		Expect(err).NotTo(HaveOccurred())
		Expect(status).To(Equal(http.StatusOK), string(body))
		echo, err := decodeHTTPBinEcho(body)
		Expect(err).NotTo(HaveOccurred())
		Expect(echo.Method).To(Equal(http.MethodGet))
		Expect(echo.URL).To(HaveSuffix("/anything"))
		Expect(headerValue(echo.Headers, "X-Scope-OrgID")).To(BeEmpty())
		Expect(headerValue(echo.Headers, "X-Writer-ID")).To(BeEmpty())
		Expect(headerValue(echo.Headers, "Authorization")).To(BeEmpty())
	}, NodeTimeout(60*time.Second))

	It("rejects a missing required header attribute even when the caller supplies that header", func(ctx SpecContext) {
		claims := map[string]any{
			"organization": map[string]any{"id": "customer-a"},
			"aud":          "gateway-test",
			"exp":          time.Now().Add(5 * time.Minute).Unix(),
		}
		token := jwtHeadersGateway.token("issuer-one", claims, nil)
		expectDeniedBeforeUpstream(ctx, jwtHeadersGateway.adminAddr, "api-metrics", "missing verified header attribute", http.StatusForbidden, func() (int, []byte, error) {
			return jwtHeadersGateway.request(ctx, jwtHeadersGateway.httpAddr, jwtHeadersHost, false, token, true)
		})
	}, NodeTimeout(60*time.Second))
})

var _ = Describe("JWT access and identity processing", Label("gateway", "jwt", "authentication", "authorization", "namespace-"+jwtNamespace), Ordered, func() {
	BeforeAll(func(ctx SpecContext) {
		DeferCleanup(func(ctx SpecContext) { Expect(env.DeleteNamespace(ctx, jwtNamespace)).To(Succeed()) }, NodeTimeout(3*time.Minute))
		var err error
		jwtGateway, err = setupJWTGateway(ctx, jwtNamespace, "jwt-gateway.yaml")
		Expect(err).NotTo(HaveOccurred())
		jwtGateway.adminAddr = env.ForwardEnvoyAdminWithCleanup(ctx, jwtNamespace)
		jwtGateway.metricsAddr = env.ForwardWithCleanup(ctx, jwtNamespace, "service/auth-gateway", 8889)
	}, NodeTimeout(12*time.Minute))

	It("authorizes original claims and sends processed attributes over HTTP and HTTPS", func(ctx SpecContext) {
		for _, target := range []struct {
			address string
			host    string
			tls     bool
		}{{jwtGateway.httpAddr, jwtHTTPHost, false}, {jwtGateway.httpsAddr, jwtHTTPSHost, true}} {
			for _, test := range []struct {
				issuer string
				tenant string
				team   string
				path   string
			}{{"issuer-one", "customer-a", "team-a", "/protected"}, {"issuer-two", "customer-b", "team-b", "/status-only"}} {
				claims := jwtTestClaims(test.tenant)
				claims["sub"] = "writer-17"
				token := jwtGateway.token(test.issuer, claims, nil)
				status, responseBody, err := jwtGateway.requestPath(ctx, target.address, target.host, target.tls, test.path, token, true)
				Expect(err).NotTo(HaveOccurred())
				if status != http.StatusOK {
					writeTestOutput("valid %s request status=%d body=%s\n", test.issuer, status, responseBody)
				}
				Expect(status).To(Equal(http.StatusOK), string(responseBody))
				echo, err := decodeHTTPBinEcho(responseBody)
				Expect(err).NotTo(HaveOccurred())
				Expect(echo.Method).To(Equal(http.MethodGet))
				Expect(echo.URL).To(HaveSuffix("/anything"))
				Expect(headerValue(echo.Headers, "X-Scope-OrgID")).To(Equal(test.team))
				Expect(headerValue(echo.Headers, "X-Writer-ID")).To(Equal("writer-17"))
				Expect(headerValue(echo.Headers, "X-Chain")).To(Equal("second"), "one processor must perform one lookup")
				Expect(headerValue(echo.Headers, "X-Order")).To(Equal("final"), "later processors must consume earlier output")
				Expect(headerValue(echo.Headers, "X-Literal")).To(Equal(`mapped "quoted" \ value`))
				Expect(headerValue(echo.Headers, "Authorization")).To(BeEmpty())
			}
		}
		claims := jwtTestClaims("customer-a")
		delete(claims, "sub")
		delete(claims, "chain")
		delete(claims, "order")
		delete(claims, "literal.claim")
		token := jwtGateway.token("issuer-one", claims, nil)
		status, responseBody, err := jwtGateway.requestPath(ctx, jwtGateway.httpAddr, jwtHTTPHost, false, "/headerless", token, true)
		Expect(err).NotTo(HaveOccurred())
		Expect(status).To(Equal(http.StatusOK), string(responseBody))
		echo, err := decodeHTTPBinEcho(responseBody)
		Expect(err).NotTo(HaveOccurred())
		Expect(headerValue(echo.Headers, "X-Scope-OrgID")).To(BeEmpty())
		Expect(headerValue(echo.Headers, "X-Writer-ID")).To(BeEmpty())
		Expect(headerValue(echo.Headers, "Authorization")).To(BeEmpty())
	}, SpecTimeout(2*time.Minute))

	It("scopes grants to individual APIs on the same hostname", func(ctx SpecContext) {
		adminAddress := jwtGateway.adminAddr
		for _, test := range []struct {
			name           string
			issuer         string
			tenant         string
			allowedPath    string
			allowedCluster string
			deniedPath     string
			deniedCluster  string
		}{
			{
				name: "metrics writer", issuer: "issuer-one", tenant: "customer-a",
				allowedPath: "/protected", allowedCluster: "api-metrics",
				deniedPath: "/status-only", deniedCluster: "api-status-only",
			},
			{
				name: "status writer", issuer: "issuer-two", tenant: "customer-b",
				allowedPath: "/status-only", allowedCluster: "api-status-only",
				deniedPath: "/protected", deniedCluster: "api-metrics",
			},
		} {
			token := jwtGateway.token(test.issuer, jwtTestClaims(test.tenant), nil)
			status, body := expectUpstreamRequestDelta(ctx, adminAddress, test.allowedCluster, test.name+" allowed API", 1, func() (int, []byte, error) {
				return jwtGateway.requestPath(ctx, jwtGateway.httpAddr, jwtHTTPHost, false, test.allowedPath, token, false)
			})
			Expect(status).To(Equal(http.StatusOK), test.name+": "+string(body))
			echo, err := decodeHTTPBinEcho(body)
			Expect(err).NotTo(HaveOccurred(), test.name)
			Expect(echo.Method).To(Equal(http.MethodGet), test.name)
			Expect(echo.URL).To(HaveSuffix("/anything"), test.name)

			expectDeniedBeforeUpstream(ctx, adminAddress, test.deniedCluster, test.name+" denied API", http.StatusForbidden, func() (int, []byte, error) {
				return jwtGateway.requestPath(ctx, jwtGateway.httpAddr, jwtHTTPHost, false, test.deniedPath, token, false)
			})
		}
	}, SpecTimeout(90*time.Second))

	It("passes through authorized values without a mapping", func(ctx SpecContext) {
		claims := jwtTestClaims("customer-pass")
		token := jwtGateway.token("issuer-one", claims, nil)
		status, body, err := jwtGateway.request(ctx, jwtGateway.httpAddr, jwtHTTPHost, false, token, false)
		Expect(err).NotTo(HaveOccurred())
		Expect(status).To(Equal(http.StatusOK), string(body))
		Expect(headerValue(jwtEchoHeaders(body), "X-Scope-OrgID")).To(Equal("customer-pass"))
	}, NodeTimeout(60*time.Second))

	It("rejects invalid credentials, missing required attributes, and denied original claims", func(ctx SpecContext) {
		adminAddress := jwtGateway.adminAddr

		issuerOne := func(claims map[string]any, key *rsa.PrivateKey) string {
			return jwtGateway.token("issuer-one", claims, key)
		}
		validClaims := func() map[string]any { return jwtTestClaims("customer-a") }
		missingExpiration := validClaims()
		delete(missingExpiration, "exp")
		expired := validClaims()
		expired["exp"] = time.Now().Add(-2 * time.Minute).Unix()
		wrongAudience := validClaims()
		wrongAudience["aud"] = "other-service"
		wrongIssuer := validClaims()
		wrongIssuer["iss"] = "https://unknown.jwt.test"
		unknownTenant := validClaims()
		unknownTenant["organization"].(map[string]any)["id"] = "unmapped-customer"
		deniedTenant := validClaims()
		deniedTenant["organization"].(map[string]any)["id"] = "customer-b"
		missingAuthorization := validClaims()
		delete(missingAuthorization["organization"].(map[string]any), "id")
		missingRequired := validClaims()
		delete(missingRequired, "sub")
		unsafeHeader := validClaims()
		unsafeHeader["sub"] = "writer-17\r\nInjected: yes"
		cases := []struct {
			name, token string
			status      int
		}{
			{name: "missing bearer", status: http.StatusUnauthorized},
			{name: "malformed bearer", token: "not-a-jwt", status: http.StatusUnauthorized},
			{name: "wrong signature", token: issuerOne(validClaims(), jwtGateway.wrongKey), status: http.StatusUnauthorized},
			{name: "wrong issuer", token: issuerOne(wrongIssuer, nil), status: http.StatusUnauthorized},
			// Envoy 1.39.1 rejects a validly signed token with an untrusted audience as 403.
			{name: "wrong audience", token: issuerOne(wrongAudience, nil), status: http.StatusForbidden},
			{name: "expired", token: issuerOne(expired, nil), status: http.StatusUnauthorized},
			{name: "missing expiration", token: issuerOne(missingExpiration, nil), status: http.StatusUnauthorized},
			{name: "tenant claim has no grant", token: issuerOne(unknownTenant, nil), status: http.StatusForbidden},
			{name: "another issuer's grant cannot be borrowed", token: issuerOne(deniedTenant, nil), status: http.StatusForbidden},
			{name: "missing authorization claim", token: issuerOne(missingAuthorization, nil), status: http.StatusForbidden},
			{name: "required header attribute is missing", token: issuerOne(missingRequired, nil), status: http.StatusForbidden},
			{name: "required header attribute is unsafe", token: issuerOne(unsafeHeader, nil), status: http.StatusForbidden},
		}
		for _, test := range cases {
			status, body := expectDeniedBeforeUpstream(ctx, adminAddress, "api-metrics", test.name, test.status, func() (int, []byte, error) {
				return jwtGateway.request(ctx, jwtGateway.httpAddr, jwtHTTPHost, false, test.token, false)
			})
			if status != test.status {
				writeTestOutput("%s response status=%d body=%s\n", test.name, status, body)
			}
			Expect(status).To(Equal(test.status), test.name+": "+string(body))
		}
	}, NodeTimeout(60*time.Second))

	It("requires a scalar nonempty value for a required output while optional attributes are unset", func(ctx SpecContext) {
		adminAddress := jwtGateway.adminAddr
		claimsForSubject := func(subject any) map[string]any {
			return map[string]any{
				"organization": map[string]any{"id": "customer-a"},
				"sub":          subject,
				"aud":          "gateway-test",
				"exp":          time.Now().Add(5 * time.Minute).Unix(),
			}
		}

		validToken := jwtGateway.token("issuer-one", claimsForSubject("writer-17"), nil)
		status, body := expectUpstreamRequestDelta(ctx, adminAddress, "api-metrics", "optional attributes omitted", 1, func() (int, []byte, error) {
			return jwtGateway.requestPath(ctx, jwtGateway.httpAddr, jwtHTTPHost, false, "/required-writer", validToken, false)
		})
		Expect(status).To(Equal(http.StatusOK), string(body))
		echo, err := decodeHTTPBinEcho(body)
		Expect(err).NotTo(HaveOccurred())
		Expect(echo.Method).To(Equal(http.MethodGet))
		Expect(echo.URL).To(HaveSuffix("/anything"))
		Expect(headerValue(echo.Headers, "X-Writer-ID")).To(Equal("writer-17"))
		Expect(headerValue(echo.Headers, "X-Scope-OrgID")).To(BeEmpty())
		Expect(headerValue(echo.Headers, "X-Chain")).To(BeEmpty())
		Expect(headerValue(echo.Headers, "X-Order")).To(BeEmpty())
		Expect(headerValue(echo.Headers, "X-Literal")).To(BeEmpty())

		for _, test := range []struct {
			name    string
			subject any
			status  int
		}{
			{name: "null", subject: nil, status: http.StatusUnauthorized},
			{name: "empty", subject: "", status: http.StatusForbidden},
			{name: "number", subject: 17, status: http.StatusUnauthorized},
			{name: "list", subject: []string{"writer-17"}, status: http.StatusUnauthorized},
		} {
			token := jwtGateway.token("issuer-one", claimsForSubject(test.subject), nil)
			expectDeniedBeforeUpstream(ctx, adminAddress, "api-metrics", "required output "+test.name, test.status, func() (int, []byte, error) {
				return jwtGateway.requestPath(ctx, jwtGateway.httpAddr, jwtHTTPHost, false, "/required-writer", token, false)
			})
		}
	}, SpecTimeout(90*time.Second))

	It("isolates JWT issuers by server", func(ctx SpecContext) {
		for _, test := range []struct {
			issuer, tenant, host string
			status               int
		}{{"issuer-two", "customer-a", jwtHTTPHost, http.StatusForbidden}, {"issuer-two", "customer-b", jwtIssuerOneHost, http.StatusUnauthorized}} {
			claims := jwtTestClaims(test.tenant)
			token := jwtGateway.token(test.issuer, claims, nil)
			status, body, err := jwtGateway.request(ctx, jwtGateway.httpAddr, test.host, false, token, false)
			Expect(err).NotTo(HaveOccurred())
			Expect(status).To(Equal(test.status), test.issuer+" at "+test.host+": "+string(body))
		}
	}, NodeTimeout(60*time.Second))

	registerJWTRequestMetricSpecs()

	It("reloads mapping changes through ECDS without changing authorization or the Pod", func(ctx SpecContext) {
		claims := jwtTestClaims("customer-a")
		claims["sub"] = "writer-17"
		claims["exp"] = time.Now().Add(30 * time.Minute).Unix()
		token := jwtGateway.token("issuer-one", claims, nil)
		status, body, err := jwtGateway.request(ctx, jwtGateway.httpAddr, jwtHTTPHost, false, token, false)
		Expect(err).NotTo(HaveOccurred())
		Expect(status).To(Equal(http.StatusOK), "original identity mapping should be authorized: "+string(body))
		adminAddress := jwtGateway.adminAddr
		updatedMetricLabels := requestMetricLabels("metrics", http.StatusOK, "team-b", "writer-17")
		beforeUpdatedMetric, err := requestMetricCount(ctx, adminAddress, updatedMetricLabels)
		Expect(err).NotTo(HaveOccurred())

		selector := "app.kubernetes.io/name=auth-gateway"
		oldUID, err := env.PodUID(ctx, jwtNamespace, selector)
		Expect(err).NotTo(HaveOccurred())

		fixture, err := env.Fixture("jwt-gateway.yaml")
		Expect(err).NotTo(HaveOccurred())
		updatedConfig, err := config.Load(bytes.NewReader(fixture))
		Expect(err).NotTo(HaveOccurred())
		updatedConfig.Kubernetes.Namespace = jwtNamespace
		for i := range updatedConfig.Authenticators {
			updatedConfig.Authenticators[i].JWT.JWKS.URI = "https://jwks." + jwtNamespace + ".svc.cluster.local/" + updatedConfig.Authenticators[i].Name
			updatedConfig.Authenticators[i].JWT.JWKS.TrustedCA = jwtTrustedCA()
		}
		updatedConfig.Processing[0].Attributes["tenant_id"].Mappings["customer-a"] = "team-b"
		updatedResources, err := config.GenerateKubernetes(updatedConfig)
		Expect(err).NotTo(HaveOccurred())
		Expect(updatedResources.ConfigMap.Data).To(Equal(jwtGateway.resources.ConfigMap.Data), "mapping changes must not alter the Envoy bootstrap ConfigMap")
		Expect(updatedResources.ProcessingConfigMap).NotTo(BeNil())
		Expect(updatedResources.ProcessingConfigMap.Data["processing.yaml"]).NotTo(Equal(jwtGateway.resources.ProcessingConfigMap.Data["processing.yaml"]))
		manifest, err := yamlDocuments(updatedResources.ProcessingConfigMap)
		Expect(err).NotTo(HaveOccurred())
		timeE2EPhase("JWT mapping resource apply", func() {
			Expect(env.Apply(ctx, jwtNamespace, manifest)).To(Succeed())
		})

		timeE2EPhase("JWT mapping apply-to-observed reload", func() {
			Eventually(func() bool {
				_ = nudgeGatewayPod(ctx, jwtNamespace)
				status, body, err = jwtGateway.request(ctx, jwtGateway.httpAddr, jwtHTTPHost, false, token, false)
				return err == nil && status == http.StatusOK && headerValue(jwtEchoHeaders(body), "X-Scope-OrgID") == "team-b"
			}).WithContext(ctx).WithTimeout(3*time.Minute).WithPolling(time.Second).Should(BeTrue(), func() string {
				return fmt.Sprintf("ECDS mapping update did not change the output while preserving authorization: status=%d body=%s error=%v", status, body, err)
			})
		})
		timeE2EPhase("JWT mapping post-reload assertions", func() {
			afterUpdatedMetric, err := requestMetricCount(ctx, adminAddress, updatedMetricLabels)
			Expect(err).NotTo(HaveOccurred())
			Expect(afterUpdatedMetric).To(BeNumerically(">", beforeUpdatedMetric), "ECDS mapping update did not change the metric label")
			newUID, err := env.PodUID(ctx, jwtNamespace, selector)
			Expect(err).NotTo(HaveOccurred())
			Expect(newUID).To(Equal(oldUID), "an ECDS processing update must not replace the gateway Pod")
		})

	}, SpecTimeout(8*time.Minute))
})
