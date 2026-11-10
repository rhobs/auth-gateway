//go:build e2e

package e2e

import (
	"net/http"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("API-key and JWT request decisions", Label("gateway", "api-key", "authentication", "authorization", "namespace-"+apiKeyBehaviorNS), Ordered, ContinueOnFailure, func() {
	var gateway *apiKeyE2E

	BeforeAll(func(ctx SpecContext) {
		DeferCleanup(func() { deleteNamespaceInBackground(apiKeyBehaviorNS) })
		var err error
		gateway, err = setupAPIKeyGateway(ctx, apiKeyBehaviorNS, false, baselineAPIKeyCredentials(), apiKeySharedSecretKey)
		Expect(err).NotTo(HaveOccurred())
	}, NodeTimeout(12*time.Minute))

	registerAPIKeySpecs(func() *apiKeyE2E { return gateway })
	registerAPIKeyDeniedSpecs(func() *apiKeyE2E { return gateway })
	registerMixedAuthSpecs(func() *apiKeyE2E { return gateway })
	registerSharedPathDeniedSpecs(func() *apiKeyE2E { return gateway })
})

func registerMixedAuthSpecs(current func() *apiKeyE2E) {
	It("serves one tenant and path with either selected credential", func(ctx SpecContext) {
		gateway := current()
		for _, test := range []struct {
			name, token, key, writer string
		}{
			{name: "JWT tenant", token: gateway.token("client-a", "writer-a"), writer: "writer-a"},
			{name: "key tenant", key: apiKeySharedSecretKey, writer: "writer-a"},
		} {
			status, body := expectUpstreamRequestDelta(ctx, gateway.adminAddr, "api-ingest", test.name, 1, func() (int, []byte, error) {
				return gateway.request(ctx, apiKeySharedHost, false, http.MethodPost, "/ingest", apiKeyRequestBody, test.token, test.key, http.Header{"X-Tenant": []string{"client-a"}})
			})
			Expect(status).To(Equal(http.StatusOK), test.name+": "+string(body))
			expectAPIKeyEcho(body, "client-a", test.writer)
		}
	}, NodeTimeout(2*time.Minute))

	It("rejects both credential headers on every path before the backend", func(ctx SpecContext) {
		gateway := current()
		before, err := requestMetricTotal(ctx, gateway.adminAddr)
		Expect(err).NotTo(HaveOccurred())
		for _, test := range []struct {
			name, host, path, token, key, cluster string
			tls, emptyHeaders                     bool
		}{
			{name: "key route", host: apiKeyOnlyHost, path: "/ingest", token: gateway.token("client-a", "writer-a"), key: apiKeySharedSecretKey, cluster: "api-ingest"},
			{name: "JWT route", host: apiKeySharedHost, path: "/ingest", token: "broken.jwt", key: apiKeySharedSecretKey, cluster: "api-ingest"},
			{name: "public route", host: apiKeyPublicHost, path: "/health", token: "broken.jwt", key: apiKeySharedSecretKey, cluster: "api-public"},
			{name: "unknown path", host: apiKeyOnlyHost, path: "/unknown", token: "broken.jwt", key: apiKeySharedSecretKey, cluster: "api-ingest"},
			{name: "empty header values", host: apiKeyOnlyHost, path: "/ingest", emptyHeaders: true, cluster: "api-ingest"},
			{name: "TLS route", host: apiKeyTLSHost, path: "/ingest", token: gateway.token("client-a", "writer-a"), key: apiKeySharedSecretKey, cluster: "api-ingest", tls: true},
		} {
			var headers http.Header
			if test.emptyHeaders {
				headers = http.Header{"Authorization": []string{""}, gateway.keyHeader: []string{""}}
			}
			status, body := expectUpstreamRequestDelta(ctx, gateway.adminAddr, test.cluster, test.name, 0, func() (int, []byte, error) {
				method := http.MethodPost
				if test.path == "/health" {
					method = http.MethodGet
				}
				return gateway.request(ctx, test.host, test.tls, method, test.path, "", test.token, test.key, headers)
			})
			Expect(status).To(Equal(http.StatusForbidden), test.name+": "+string(body))
		}
		after, err := requestMetricTotal(ctx, gateway.adminAddr)
		Expect(err).NotTo(HaveOccurred())
		Expect(after).To(Equal(before+4), "metered /ingest requests should count their 403 responses")
	}, Label("metrics"), NodeTimeout(2*time.Minute))
}
