//go:build e2e

package e2e

import (
	"fmt"
	"net/http"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
)

func registerAPIKeySpecs(current func() *apiKeyE2E) {
	It("uses one Secret across protected servers and forwards verified attributes", func(ctx SpecContext) {
		gateway := current()
		for _, host := range []string{apiKeyOnlyHost, apiKeyTLSHost} {
			status, body, err := gateway.request(ctx, host, host == apiKeyTLSHost, http.MethodPost, "/ingest", apiKeyRequestBody, "", apiKeySharedSecretKey, nil)
			Expect(err).NotTo(HaveOccurred(), host)
			Expect(status).To(Equal(http.StatusOK), host+": "+string(body))
			expectAPIKeyEcho(body, "client-a", "writer-a")
		}
		status, body, err := gateway.request(ctx, apiKeyPublicHost, false, http.MethodGet, "/health", "", "", apiKeySharedSecretKey, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(status).To(Equal(http.StatusOK), string(body))
		echo, err := decodeHTTPBinEcho(body)
		Expect(err).NotTo(HaveOccurred())
		Expect(echo.Method).To(Equal(http.MethodGet))
		Expect(echo.URL).To(HaveSuffix("/anything"))
		Expect(headerValue(echo.Headers, "X-Partner-Key")).To(BeEmpty())
	}, NodeTimeout(60*time.Second))

	It("counts source key attributes in response metrics", func(ctx SpecContext) {
		gateway := current()
		labels := requestMetricLabels("ingest", http.StatusOK, "client-a", "writer-a")
		before, err := requestMetricCount(ctx, gateway.adminAddr, labels)
		Expect(err).NotTo(HaveOccurred())
		status, body, err := gateway.request(ctx, apiKeyOnlyHost, false, http.MethodPost, "/ingest", apiKeyRequestBody, "", apiKeySharedSecretKey, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(status).To(Equal(http.StatusOK), string(body))
		expectAPIKeyEcho(body, "client-a", "writer-a")
		after, err := requestMetricCount(ctx, gateway.adminAddr, labels)
		Expect(err).NotTo(HaveOccurred())
		Expect(after).To(Equal(before + 1))
	}, NodeTimeout(60*time.Second))
}

var _ = Describe("API-key Secret projection", Label("gateway", "api-key", "authentication", "namespace-"+apiKeyProjectionNS), Ordered, func() {
	var gateway *apiKeyE2E

	BeforeAll(func(ctx SpecContext) {
		DeferCleanup(func() { deleteNamespaceInBackground(apiKeyProjectionNS) })
		var err error
		gateway, err = setupAPIKeyGateway(ctx, apiKeyProjectionNS, false, baselineAPIKeyCredentials(), apiKeySharedSecretKey)
		Expect(err).NotTo(HaveOccurred())
	}, NodeTimeout(12*time.Minute))

	It("rotates the projected key set without replacing the gateway", func(ctx SpecContext) {
		oldUID, err := gatewayPodUID(ctx, apiKeyProjectionNS)
		Expect(err).NotTo(HaveOccurred())

		Expect(gateway.applySecret(ctx, []gatewayapi.APIKeyCredential{
			{Key: "key-b", Attributes: map[string]string{"tenant_id": "client-b", "writer_id": "writer-b"}},
		})).To(Succeed())
		var status int
		var body []byte
		Eventually(func() bool {
			_ = nudgeGatewayPod(ctx, apiKeyProjectionNS)
			status, body, err = gateway.request(ctx, apiKeyOnlyHost, false, http.MethodPost, "/ingest", apiKeyRequestBody, "", "key-b", nil)
			if err != nil || status != http.StatusOK || headerValue(jwtEchoHeaders(body), "X-Scope-OrgID") != "client-b" {
				return false
			}
			status, body, err = gateway.request(ctx, apiKeyOnlyHost, false, http.MethodPost, "/ingest", apiKeyRequestBody, "", apiKeySharedSecretKey, nil)
			return err == nil && status == http.StatusUnauthorized
		}).WithContext(ctx).WithTimeout(4*time.Minute).WithPolling(time.Second).Should(BeTrue(), func() string {
			return fmt.Sprintf("Secret rotation did not replace the accepted key: HTTP %d: %s (error: %v)", status, body, err)
		})
		status, body, err = gateway.request(ctx, apiKeyTLSHost, true, http.MethodPost, "/ingest", apiKeyRequestBody,
			"", "key-b", nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(status).To(Equal(http.StatusOK), string(body))
		expectAPIKeyEcho(body, "client-b", "writer-b")

		currentUID, err := gatewayPodUID(ctx, apiKeyProjectionNS)
		Expect(err).NotTo(HaveOccurred())
		Expect(currentUID).To(Equal(oldUID), "a projected Secret rotation must not replace the gateway Pod")
	}, SpecTimeout(12*time.Minute))
})

var _ = Describe("API-key namespace isolation", Label("gateway", "api-key", "authentication", "namespace-"+apiKeyIsolatedNS), Ordered, func() {
	var gateway *apiKeyE2E

	BeforeAll(func(ctx SpecContext) {
		DeferCleanup(func() { deleteNamespaceInBackground(apiKeyIsolatedNS) })
		var err error
		gateway, err = setupAPIKeyGatewayWithShape(ctx, apiKeyIsolatedNS, true, []gatewayapi.APIKeyCredential{
			{Key: "isolated-key", Attributes: map[string]string{"tenant_id": "client-b", "writer_id": "writer-b"}},
		}, "isolated-key", func(c *gatewayapi.Config) {
			c.Authenticators[0].APIKey.Header = ""
		})
		Expect(err).NotTo(HaveOccurred())
	}, NodeTimeout(8*time.Minute))

	It("defaults to X-API-Key with independent namespace contents", func(ctx SpecContext) {
		status, body, err := gateway.request(ctx, apiKeyOnlyHost, false, http.MethodPost, "/ingest", apiKeyRequestBody, "", "isolated-key", nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(status).To(Equal(http.StatusOK), string(body))
		expectAPIKeyEcho(body, "client-b", "writer-b")
		status, body, err = gateway.request(ctx, apiKeyOnlyHost, false, http.MethodPost, "/ingest", apiKeyRequestBody, "", apiKeySharedSecretKey, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(status).To(Equal(http.StatusUnauthorized), string(body))
	}, NodeTimeout(60*time.Second))
})
