//go:build e2e

package e2e

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Server TLS", Label("gateway", "tls", "namespace-"+tlsNamespace), Ordered, func() {
	BeforeAll(func(ctx SpecContext) {
		setupGateway(ctx, tlsNamespace, true)
	}, NodeTimeout(12*time.Minute))

	It("serves each HTTPS hostname only through its own TLS chain", func(ctx SpecContext) {
		By("not serving TLS hosts on plaintext HTTP")
		for _, host := range []string{httpsHost, queryHTTPSHost} {
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+httpAddress+"/upstream-health", nil)
			Expect(err).NotTo(HaveOccurred())
			request.Host = host
			httpResponse, err := testClient.Do(request)
			Expect(err).NotTo(HaveOccurred())
			Expect(httpResponse.Body.Close()).To(Succeed())
			Expect(httpResponse.StatusCode).To(Equal(http.StatusNotFound))
		}

		By("serving each hostname's certificate and bound API")
		for _, host := range []string{httpsHost, queryHTTPSHost} {
			tlsResponse, err := requestHTTPS(ctx, httpsAddress, host, host, "/upstream-health", routingRootCAs)
			Expect(err).NotTo(HaveOccurred())
			Expect(tlsResponse.status).To(Equal(http.StatusOK))
			Expect(tlsResponse.certificate.DNSNames).To(ContainElement(host))
		}

		By("rejecting authorities that do not match the SNI-selected server")
		for _, hosts := range [][2]string{
			{httpsHost, httpHost},
			{httpsHost, queryHTTPSHost},
			{queryHTTPSHost, httpsHost},
		} {
			wrongHost, err := requestHTTPS(ctx, httpsAddress, hosts[0], hosts[1], "/upstream-health", routingRootCAs)
			Expect(err).NotTo(HaveOccurred())
			Expect(wrongHost.status).To(Equal(http.StatusNotFound))
		}

		By("rejecting unconfigured SNI even when a certificate covers that hostname")
		// Keep the expected connection reset from closing the forward reused by later specs.
		unknownAddress := env.ForwardWithCleanup(ctx, tlsNamespace, "service/auth-gateway", 443)
		_, err := requestHTTPS(ctx, unknownAddress, unknownHost, unknownHost, "/upstream-health", routingRootCAs)
		Expect(err).To(HaveOccurred())
		var verificationError *tls.CertificateVerificationError
		Expect(errors.As(err, &verificationError)).To(BeFalse(), "Envoy should reject the connection before certificate verification")
	}, SpecTimeout(30*time.Second))

	It("exposes routes and method fallbacks only for bound APIs", func(ctx SpecContext) {
		const path = "/metrics/api/v1/receive"
		payload := []byte("TLS remote-write payload")
		requestHeaders := http.Header{
			"Content-Type":     []string{"application/octet-stream"},
			"X-E2E-TLS-Header": []string{"forwarded"},
		}
		write, err := requestHTTPSWithMethodAndBody(ctx, httpsAddress, httpsHost, httpsHost, http.MethodPost, path,
			payload, requestHeaders, routingRootCAs)
		Expect(err).NotTo(HaveOccurred())
		Expect(write.status).To(Equal(http.StatusOK))
		echo, err := decodeHTTPBinEcho(write.body)
		Expect(err).NotTo(HaveOccurred())
		Expect(echo.Method).To(Equal(http.MethodPost))
		Expect(echo.URL).To(HaveSuffix("/anything/api/v1/receive"))
		Expect(echo.Data).To(Equal("data:application/octet-stream;base64," + base64.StdEncoding.EncodeToString(payload)))
		Expect(headerValue(echo.Headers, "Content-Type")).To(Equal("application/octet-stream"))
		Expect(headerValue(echo.Headers, "X-E2E-TLS-Header")).To(Equal("forwarded"))

		wrongMethod, err := requestHTTPS(ctx, httpsAddress, httpsHost, httpsHost, path, routingRootCAs)
		Expect(err).NotTo(HaveOccurred())
		Expect(wrongMethod.status).To(Equal(http.StatusMethodNotAllowed))
		Expect(wrongMethod.allow).To(Equal("POST"))

		for _, method := range []string{http.MethodGet, http.MethodPost} {
			unbound, err := requestHTTPSWithMethod(ctx, httpsAddress, queryHTTPSHost, queryHTTPSHost, method, path, routingRootCAs)
			Expect(err).NotTo(HaveOccurred())
			Expect(unbound.status).To(Equal(http.StatusNotFound))
			Expect(unbound.allow).To(BeEmpty())
		}
	}, SpecTimeout(30*time.Second))

	It("reloads a renewed server certificate without restarting Envoy", func(ctx SpecContext) {
		initialTLS, err := requestHTTPS(ctx, httpsAddress, httpsHost, httpsHost, "/upstream-health", routingRootCAs)
		Expect(err).NotTo(HaveOccurred())
		Expect(initialTLS.status).To(Equal(http.StatusOK))
		initialQueryTLS, err := requestHTTPS(ctx, httpsAddress, queryHTTPSHost, queryHTTPSHost, "/upstream-health", routingRootCAs)
		Expect(err).NotTo(HaveOccurred())
		Expect(initialQueryTLS.status).To(Equal(http.StatusOK))
		initialPodUID, err := gatewayPodUID(ctx, tlsNamespace)
		Expect(err).NotTo(HaveOccurred())

		By("asking cert-manager to renew the server certificate")
		Expect(env.RenewCertificate(ctx, tlsNamespace, "auth-gateway-server")).To(Succeed())

		var rotatedTLS *httpsResult
		initialSerial := initialTLS.certificate.SerialNumber.String()
		Eventually(func() error {
			result, err := requestHTTPS(ctx, httpsAddress, httpsHost, httpsHost, "/upstream-health", routingRootCAs)
			if err != nil {
				return err
			}
			if result.certificate.SerialNumber.String() == initialSerial {
				return fmt.Errorf("certificate serial %s has not rotated", initialSerial)
			}
			rotatedTLS = result
			return nil
		}).WithContext(ctx).WithTimeout(4 * time.Minute).WithPolling(500 * time.Millisecond).Should(Succeed())

		Expect(rotatedTLS.status).To(Equal(http.StatusOK))
		Expect(rotatedTLS.certificate.DNSNames).To(ContainElement(httpsHost))
		Expect(rotatedTLS.certificate.NotAfter).To(BeTemporally(">", initialTLS.certificate.NotAfter))
		Expect(rotatedTLS.certificate.RawSubjectPublicKeyInfo).NotTo(Equal(initialTLS.certificate.RawSubjectPublicKeyInfo), "cert-manager should rotate the private key")

		rotatedPodUID, err := gatewayPodUID(ctx, tlsNamespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(rotatedPodUID).To(Equal(initialPodUID), "the gateway Pod should not restart during certificate rotation")
		queryTLS, err := requestHTTPS(ctx, httpsAddress, queryHTTPSHost, queryHTTPSHost, "/upstream-health", routingRootCAs)
		Expect(err).NotTo(HaveOccurred())
		Expect(queryTLS.status).To(Equal(http.StatusOK))
		Expect(queryTLS.certificate.Raw).To(Equal(initialQueryTLS.certificate.Raw), "renewing one server certificate should leave the other unchanged")
	}, SpecTimeout(5*time.Minute))
})
