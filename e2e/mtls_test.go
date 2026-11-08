//go:build e2e

package e2e

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var mtlsNamespace = e2eNamespace("auth-gateway-mtls-e2e")

var _ = Describe("Client-certificate authentication", Label("gateway", "tls", "mtls", "authentication", "authorization", "namespace-"+mtlsNamespace), Ordered, ContinueOnFailure, func() {
	var gateway *mtlsE2E

	BeforeAll(func(ctx SpecContext) {
		DeferCleanup(func() { deleteNamespaceInBackground(mtlsNamespace) })
		var err error
		gateway, err = setupMTLSGateway(ctx, mtlsNamespace)
		Expect(err).NotTo(HaveOccurred())
	}, NodeTimeout(12*time.Minute))
	BeforeEach(func(ctx SpecContext) {
		gateway.address = env.ForwardWithCleanup(ctx, mtlsNamespace, "service/auth-gateway", 443)
	})

	It("forwards a verified URI and DNS SAN identity in forwarded headers", func(ctx SpecContext) {
		status, body := expectUpstreamRequestDelta(ctx, gateway.adminAddr, "api-ingest", "verified client certificate", 1, func() (int, []byte, error) {
			return gateway.request(ctx, mtlsOnlyHost, &gateway.allowed, "", "", http.MethodPost, "/ingest", mtlsPayload, mtlsRequestHeaders())
		})
		Expect(status).To(Equal(http.StatusOK), string(body))
		expectMTLSEcho(body, mtlsAllowedURI)
	}, NodeTimeout(60*time.Second))

	It("rejects missing or untrusted certificates during the required TLS handshake", func(ctx SpecContext) {
		for _, test := range []struct {
			name        string
			certificate *tls.Certificate
		}{
			{name: "missing certificate"},
			{name: "untrusted certificate", certificate: &gateway.untrusted},
		} {
			expectMTLSHandshakeDenied(ctx, gateway, test.name, mtlsOnlyHost, test.certificate, "", "", mtlsRequestHeaders())
		}
	}, NodeTimeout(60*time.Second))

	It("uses SAN grants and request-header selection, while a CA-only grant accepts a SAN-less certificate", func(ctx SpecContext) {
		for _, test := range []struct {
			name        string
			certificate *tls.Certificate
			headers     http.Header
		}{
			{name: "ungranted SAN", certificate: &gateway.denied, headers: mtlsRequestHeaders()},
			{name: "missing request header", certificate: &gateway.allowed},
			{name: "SAN-less certificate without a SAN grant", certificate: &gateway.noSAN, headers: mtlsRequestHeaders()},
		} {
			expectMTLSDenied(ctx, gateway, test.name, mtlsOnlyHost, test.certificate, "", "", test.headers, http.StatusForbidden)
		}
		status, body := expectUpstreamRequestDelta(ctx, gateway.adminAddr, "api-probe", "CA-only grant", 1, func() (int, []byte, error) {
			return gateway.request(ctx, mtlsTrustHost, &gateway.noSAN, "", "", http.MethodPost, "/trust", "", nil)
		})
		Expect(status).To(Equal(http.StatusOK), string(body))
		echo, err := decodeHTTPBinEcho(body)
		Expect(err).NotTo(HaveOccurred())
		Expect(echo.Method).To(Equal(http.MethodPost))
		Expect(echo.URL).To(HaveSuffix("/anything"))
		Expect(echo.Data).To(BeEmpty())
	}, NodeTimeout(60*time.Second))

	It("rejects multiple SANs and literal URI commas before forwarding", func(ctx SpecContext) {
		for _, test := range []struct {
			name        string
			certificate *tls.Certificate
		}{
			{name: "multiple URI SANs", certificate: &gateway.multiURI},
			{name: "multiple DNS SANs", certificate: &gateway.multiDNS},
			{name: "literal URI comma", certificate: &gateway.commaURI},
		} {
			expectMTLSDenied(ctx, gateway, test.name, mtlsOnlyHost, test.certificate, "", "", mtlsRequestHeaders(), http.StatusForbidden)
		}

	}, NodeTimeout(90*time.Second))

	It("does not allow bearer headers to replace a required certificate", func(ctx SpecContext) {
		expectMTLSHandshakeDenied(ctx, gateway, "bearer without certificate", mtlsOnlyHost, nil, "unrelated.jwt", "", mtlsRequestHeaders())
		status, body := expectUpstreamRequestDelta(ctx, gateway.adminAddr, "api-ingest", "certificate with unrelated bearer", 1, func() (int, []byte, error) {
			return gateway.request(ctx, mtlsOnlyHost, &gateway.allowed, "unrelated.jwt", "", http.MethodPost, "/ingest", mtlsPayload, mtlsRequestHeaders())
		})
		Expect(status).To(Equal(http.StatusOK), string(body))
		expectMTLSEcho(body, mtlsAllowedURI)
	}, NodeTimeout(60*time.Second))

	It("reloads a projected client CA without replacing the gateway Pod", func(ctx SpecContext) {
		const clientCAUpdateStat = "listener.0.0.0.0_8080.server_ssl_socket_factory.ssl_context_update_by_sds"
		updatesBefore, err := envoyCounter(ctx, gateway.adminAddr, clientCAUpdateStat)
		Expect(err).NotTo(HaveOccurred())
		oldUID, err := gatewayPodUID(ctx, mtlsNamespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(gateway.applyClientCA(ctx, gateway.caB)).To(Succeed())
		Eventually(func() (uint64, error) {
			return envoyCounter(ctx, gateway.adminAddr, clientCAUpdateStat)
		}).WithContext(ctx).WithTimeout(2*time.Minute).WithPolling(250*time.Millisecond).Should(
			BeNumerically(">", updatesBefore), "Envoy did not accept the updated client CA from SDS",
		)
		var status int
		var body []byte
		Eventually(func() bool {
			_ = nudgeGatewayPod(ctx, mtlsNamespace)
			status, body, err = requestMTLSWithFreshForward(ctx, gateway, mtlsOnlyHost, &gateway.rotated, "", "", http.MethodPost, "/ingest", mtlsPayload, mtlsRequestHeaders())
			return err == nil && status == http.StatusOK && headerValue(jwtEchoHeaders(body), "X-Scope-OrgID") == mtlsAllowedURI
		}).WithContext(ctx).WithTimeout(2*time.Minute).WithPolling(time.Second).Should(BeTrue(), func() string {
			return fmt.Sprintf("rotated CA was not accepted: HTTP %d, body %s, error %v", status, body, err)
		})
		expectMTLSHandshakeDenied(ctx, gateway, "old CA after rotation", mtlsOnlyHost, &gateway.allowed, "", "", mtlsRequestHeaders())
		newUID, err := gatewayPodUID(ctx, mtlsNamespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(newUID).To(Equal(oldUID))
	}, SpecTimeout(5*time.Minute))
})

func expectMTLSDenied(ctx context.Context, gateway *mtlsE2E, name, host string, certificate *tls.Certificate, token, key string, headers http.Header, status int) {
	expectDeniedBeforeUpstream(ctx, gateway.adminAddr, "api-ingest", name, status, func() (int, []byte, error) {
		return gateway.request(ctx, host, certificate, token, key, http.MethodPost, "/ingest", mtlsPayload, headers)
	})
}

func expectMTLSHandshakeDenied(ctx context.Context, gateway *mtlsE2E, name, host string, certificate *tls.Certificate, token, key string, headers http.Header) {
	before, err := upstreamRequestCount(ctx, gateway.adminAddr, "api-ingest")
	Expect(err).NotTo(HaveOccurred(), name)
	// A TLS handshake reset can close a Kubernetes port forward. Give each
	// expected reset its own forward so later requests keep their connection.
	requestGateway := *gateway
	address, stopForward, err := env.Forward(ctx, gateway.namespace, "service/auth-gateway", 443)
	Expect(err).NotTo(HaveOccurred(), name)
	if err != nil {
		return
	}
	defer stopForward()
	requestGateway.address = address
	_, _, err = requestGateway.request(ctx, host, certificate, token, key, http.MethodPost, "/ingest", mtlsPayload, headers)
	Expect(err).To(HaveOccurred(), name)
	after, err := upstreamRequestCount(ctx, gateway.adminAddr, "api-ingest")
	Expect(err).NotTo(HaveOccurred(), name)
	Expect(after).To(Equal(before), name+" reached the backend")
}

func requestMTLSWithFreshForward(ctx context.Context, gateway *mtlsE2E, host string, certificate *tls.Certificate, token, key, method, requestPath, body string, headers http.Header) (int, []byte, error) {
	address, stopForward, err := env.Forward(ctx, gateway.namespace, "service/auth-gateway", 443)
	if err != nil {
		return 0, nil, err
	}
	defer stopForward()
	requestGateway := *gateway
	requestGateway.address = address
	return requestGateway.request(ctx, host, certificate, token, key, method, requestPath, body, headers)
}
