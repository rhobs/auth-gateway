//go:build e2e

package e2e

import (
	"net/http"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func registerAPIKeyDeniedSpecs(current func() *apiKeyE2E) {
	It("denies absent or unauthorized keys before the backend", func(ctx SpecContext) {
		gateway := current()
		for _, test := range []struct {
			name    string
			key     string
			headers http.Header
			status  int
		}{
			{name: "missing key", status: http.StatusUnauthorized},
			{name: "unknown key", key: "unknown-key", status: http.StatusUnauthorized},
			{name: "denied raw attribute", key: "key-denied", status: http.StatusForbidden},
			{name: "spoofed internal identity", headers: http.Header{
				"X-Auth-Gateway-API-Key-Client":          []string{"spoofed"},
				"X-Auth-Gateway-JWT-Verified-Issuer-One": []string{"https://issuer-one.jwt.test"},
			}, status: http.StatusUnauthorized},
		} {
			expectAPIKeyDenied(ctx, gateway, test.name, apiKeyOnlyHost, false, "", test.key, test.headers, test.status)
		}
	}, NodeTimeout(60*time.Second))
}

func registerSharedPathDeniedSpecs(current func() *apiKeyE2E) {
	It("denies missing, invalid, or unmatched shared-path credentials", func(ctx SpecContext) {
		gateway := current()
		for _, test := range []struct {
			name, tenant, token, key string
			status                   int
		}{
			{name: "both credentials", tenant: "client-a", token: gateway.token("client-a", "writer-a"), key: apiKeySharedSecretKey, status: http.StatusForbidden},
			{name: "no credential", tenant: "client-a", status: http.StatusForbidden},
			{name: "invalid JWT", tenant: "client-a", token: "broken.jwt", status: http.StatusUnauthorized},
			{name: "unknown key", tenant: "client-a", key: "unknown-key", status: http.StatusUnauthorized},
			{name: "JWT has wrong tenant", tenant: "client-a", token: gateway.token("client-b", "writer-b"), status: http.StatusForbidden},
			{name: "tenant not selected", tenant: "client-c", token: gateway.token("client-a", "writer-a"), status: http.StatusForbidden},
		} {
			status, body := expectUpstreamRequestDelta(ctx, gateway.adminAddr, "api-ingest", test.name, 0, func() (int, []byte, error) {
				return gateway.request(ctx, apiKeySharedHost, false, http.MethodPost, "/ingest", apiKeyRequestBody, test.token, test.key, http.Header{"X-Tenant": []string{test.tenant}})
			})
			Expect(status).To(Equal(test.status), test.name+": "+string(body))
		}
	}, NodeTimeout(2*time.Minute))
}

func registerIdentityDeniedSpecs(current func() (*apiKeyE2E, func(string, any, string) string)) {
	It("denies tenant impersonation, provider confusion, and permissions for another resource", func(ctx SpecContext) {
		gateway, token := current()
		for _, test := range []struct {
			name, tenant, issuer, credentialTenant, role, method, path string
			status                                                     int
		}{
			{"cross-tenant writer", "client-b", "issuer-one", "client-a", "writer", http.MethodPost, "/write", http.StatusForbidden},
			{"wrong external organization", "external-a", "issuer-two", "client-a", "writer", http.MethodPost, "/write", http.StatusForbidden},
			{"unselected writer provider", "client-a", "issuer-two", "client-a", "writer", http.MethodPost, "/write", http.StatusUnauthorized},
			{"writer cannot read", "client-a", "issuer-one", "client-a", "writer", http.MethodGet, "/read", http.StatusForbidden},
			{"reader cannot write", "client-a", "issuer-one", "client-a", "reader", http.MethodPost, "/write", http.StatusForbidden},
			{"other provider's reader role", "client-a", "issuer-two", "client-a", "reader", http.MethodGet, "/read", http.StatusForbidden},
			{"other listed read tenant", "client-b", "issuer-two", "client-a", "viewer", http.MethodGet, "/read", http.StatusForbidden},
			{"unlisted tenant", "client-c", "issuer-one", "client-c", "writer", http.MethodPost, "/write", http.StatusForbidden},
		} {
			cluster := "api-journey-read"
			if test.method == http.MethodPost {
				cluster = "api-journey-write"
			}
			expectDeniedBeforeUpstream(ctx, gateway.adminAddr, cluster, test.name, test.status, func() (int, []byte, error) {
				return gateway.request(ctx, accessJourneyHost, false, test.method, test.path, apiKeyRequestBody, token(test.issuer, test.credentialTenant, test.role), "", http.Header{"X-Tenant": []string{test.tenant}, "X-Environment": []string{"production"}, "X-Scope-OrgID": []string{test.tenant}})
			})
		}
	}, NodeTimeout(2*time.Minute))

	It("rejects missing selectors and ambiguous selected headers before authenticating", func(ctx SpecContext) {
		gateway, token := current()
		valid := token("issuer-one", "client-a", "writer")
		for _, test := range []struct {
			name     string
			headers  http.Header
			jwt, key string
			status   int
		}{
			{"missing environment", http.Header{"X-Tenant": []string{"client-a"}}, valid, "", http.StatusForbidden},
			{"wrong environment", http.Header{"X-Tenant": []string{"client-a"}, "X-Environment": []string{"staging"}}, valid, "", http.StatusForbidden},
			{"duplicate environment", http.Header{"X-Tenant": []string{"client-a"}, "X-Environment": []string{"production", "staging"}}, valid, "", http.StatusBadRequest},
			{"duplicate Authorization", http.Header{"X-Tenant": []string{"client-a"}, "X-Environment": []string{"production"}, "Authorization": []string{"Bearer " + valid, "Bearer invalid"}}, "", "", http.StatusBadRequest},
			{"duplicate API key", http.Header{"X-Tenant": []string{"key-a"}, "X-Environment": []string{"production"}, "X-Partner-Key": []string{"journey-key", "invalid"}}, "", "", http.StatusBadRequest},
		} {
			expectDeniedBeforeUpstream(ctx, gateway.adminAddr, "api-journey-write", test.name, test.status, func() (int, []byte, error) {
				return gateway.request(ctx, accessJourneyHost, false, http.MethodPost, "/write", apiKeyRequestBody, test.jwt, test.key, test.headers)
			})
		}
	}, NodeTimeout(2*time.Minute))
}
