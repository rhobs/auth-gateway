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

	It("forwards a verified URI and DNS SAN identity with mapped headers", func(ctx SpecContext) {
		status, body := expectUpstreamRequestDelta(ctx, gateway.adminAddr, "api-ingest", "verified client certificate", 1, func() (int, []byte, error) {
			return gateway.request(ctx, mtlsOnlyHost, &gateway.allowed, "", "", http.MethodPost, "/ingest", mtlsPayload, mtlsRequestHeaders())
		})
		Expect(status).To(Equal(http.StatusOK), string(body))
		expectMTLSEcho(body, "team-a")
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

	It("uses raw SAN and request-header grants, while a CA-only grant accepts a SAN-less certificate", func(ctx SpecContext) {
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
			return gateway.request(ctx, mtlsTrustHost, &gateway.noSAN, "", "", http.MethodGet, "/trust", "", nil)
		})
		Expect(status).To(Equal(http.StatusOK), string(body))
		echo, err := decodeHTTPBinEcho(body)
		Expect(err).NotTo(HaveOccurred())
		Expect(echo.Method).To(Equal(http.MethodGet))
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
		expectMTLSDenied(ctx, gateway, "multiple SANs with a valid JWT", mtlsMixedHost, &gateway.multiURI,
			gateway.token(mtlsSecondURI), "", mtlsRequestHeaders(), http.StatusForbidden)
	}, NodeTimeout(90*time.Second))

	It("uses JWT, then mTLS, then API key on mixed any_of servers", func(ctx SpecContext) {
		for _, test := range []struct {
			name        string
			certificate *tls.Certificate
			token       string
			key         string
			tenant      string
		}{
			{name: "JWT without a certificate", token: gateway.token(mtlsSecondURI), tenant: "team-b"},
			{name: "key without a certificate", key: mtlsAllowedKey, tenant: "team-a"},
			{name: "invalid JWT and valid key", token: "broken.jwt", key: mtlsAllowedKey, tenant: "team-a"},
			{name: "JWT before key", token: gateway.token(mtlsSecondURI), key: mtlsAllowedKey, tenant: "team-b"},
			{name: "mTLS before invalid key", certificate: &gateway.allowed, key: "wrong-key", tenant: "team-a"},
			{name: "JWT before mTLS and key", certificate: &gateway.allowed, token: gateway.token(mtlsSecondURI), key: mtlsAllowedKey, tenant: "team-b"},
			{name: "mTLS after invalid JWT", certificate: &gateway.allowed, token: "broken.jwt", tenant: "team-a"},
		} {
			status, body := expectUpstreamRequestDelta(ctx, gateway.adminAddr, "api-ingest", test.name, 1, func() (int, []byte, error) {
				return gateway.request(ctx, mtlsMixedHost, test.certificate, test.token, test.key, http.MethodPost, "/ingest", mtlsPayload, mtlsRequestHeaders())
			})
			Expect(status).To(Equal(http.StatusOK), test.name+": "+string(body))
			expectMTLSEcho(body, test.tenant)
		}
	}, NodeTimeout(90*time.Second))

	It("does not fall back from an authenticated identity without a grant", func(ctx SpecContext) {
		for _, test := range []struct {
			name        string
			certificate *tls.Certificate
			token       string
			key         string
		}{
			{name: "ungranted mTLS before key", certificate: &gateway.denied, key: mtlsAllowedKey},
			{name: "ungranted JWT before mTLS and key", certificate: &gateway.allowed, token: gateway.token(mtlsDeniedURI), key: mtlsAllowedKey},
			{name: "ungranted JWT without a certificate", token: gateway.token(mtlsDeniedURI)},
		} {
			expectMTLSDenied(ctx, gateway, test.name, mtlsMixedHost, test.certificate, test.token, test.key, mtlsRequestHeaders(), http.StatusForbidden)
		}
	}, NodeTimeout(60*time.Second))

	It("returns 401 when no credential is accepted on optional-certificate hosts", func(ctx SpecContext) {
		for _, test := range []struct {
			name    string
			host    string
			token   string
			key     string
			headers http.Header
		}{
			{name: "JWT plus mTLS without a credential", host: mtlsJWTCertHost},
			{name: "JWT plus mTLS with invalid JWT", host: mtlsJWTCertHost, token: "broken.jwt"},
			{name: "three methods without a credential", host: mtlsMixedHost},
			{name: "spoofed peer identity", host: mtlsJWTCertHost, headers: http.Header{
				"X-Auth-Gateway-MTLS-Fingerprint": []string{"abcdef"},
				"X-Auth-Gateway-MTLS-URI-SAN":     []string{mtlsAllowedURI},
			}},
		} {
			expectMTLSDenied(ctx, gateway, test.name, test.host, nil, test.token, test.key, test.headers, http.StatusUnauthorized)
		}
	}, NodeTimeout(60*time.Second))

	It("requires all credentials and equal nonempty raw attributes on all_of", func(ctx SpecContext) {
		status, body := expectUpstreamRequestDelta(ctx, gateway.adminAddr, "api-ingest", "all credentials", 1, func() (int, []byte, error) {
			return gateway.request(ctx, mtlsAllHost, &gateway.allowed, gateway.token(mtlsAllowedURI), mtlsAllowedKey,
				http.MethodPost, "/ingest", mtlsPayload, mtlsRequestHeaders())
		})
		Expect(status).To(Equal(http.StatusOK), string(body))
		expectMTLSEcho(body, "team-a")
		expectMTLSDenied(ctx, gateway, "missing JWT", mtlsAllHost, &gateway.allowed, "", mtlsAllowedKey, mtlsRequestHeaders(), http.StatusUnauthorized)
		expectMTLSDenied(ctx, gateway, "missing key", mtlsAllHost, &gateway.allowed, gateway.token(mtlsAllowedURI), "", mtlsRequestHeaders(), http.StatusUnauthorized)
		expectMTLSDenied(ctx, gateway, "shared attribute mismatch", mtlsAllHost, &gateway.allowed, gateway.token(mtlsSecondURI), mtlsAllowedKey,
			mtlsRequestHeaders(), http.StatusForbidden)
		expectMTLSHandshakeDenied(ctx, gateway, "missing certificate for all_of", mtlsAllHost, nil, gateway.token(mtlsAllowedURI), mtlsAllowedKey, mtlsRequestHeaders())
	}, NodeTimeout(90*time.Second))

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
			return err == nil && status == http.StatusOK && headerValue(jwtEchoHeaders(body), "X-Scope-OrgID") == "team-a"
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
