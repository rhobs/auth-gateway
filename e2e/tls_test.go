//go:build e2e

package e2e

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Server TLS", Label("gateway", "tls"), Ordered, func() {
	BeforeAll(func(ctx SpecContext) {
		setupGateway(ctx, tlsNamespace, true)
	}, NodeTimeout(18*time.Minute))

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
			tlsResponse, err := requestHTTPS(ctx, httpsAddress, host, host, "/upstream-health", rootCAs)
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
			wrongHost, err := requestHTTPS(ctx, httpsAddress, hosts[0], hosts[1], "/upstream-health", rootCAs)
			Expect(err).NotTo(HaveOccurred())
			Expect(wrongHost.status).To(Equal(http.StatusNotFound))
		}

		By("rejecting unconfigured SNI even when a certificate covers that hostname")
		// Use a separate port-forward for the expected TLS reset.
		unknownAddress := env.ForwardWithCleanup(ctx, tlsNamespace, "service/auth-gateway", 443)
		_, err := requestHTTPS(ctx, unknownAddress, unknownHost, unknownHost, "/upstream-health", rootCAs)
		Expect(err).To(HaveOccurred())
		var verificationError *tls.CertificateVerificationError
		Expect(errors.As(err, &verificationError)).To(BeFalse(), "Envoy should reject the connection before certificate verification")
	}, SpecTimeout(30*time.Second))

	It("exposes routes and method fallbacks only for bound APIs", func(ctx SpecContext) {
		const path = "/metrics/api/v1/receive"
		write, err := requestHTTPSWithMethod(ctx, httpsAddress, httpsHost, httpsHost, http.MethodPost, path, rootCAs)
		Expect(err).NotTo(HaveOccurred())
		Expect(write.status).To(Equal(http.StatusOK))

		wrongMethod, err := requestHTTPS(ctx, httpsAddress, httpsHost, httpsHost, path, rootCAs)
		Expect(err).NotTo(HaveOccurred())
		Expect(wrongMethod.status).To(Equal(http.StatusMethodNotAllowed))
		Expect(wrongMethod.allow).To(Equal("POST"))

		for _, method := range []string{http.MethodGet, http.MethodPost} {
			unbound, err := requestHTTPSWithMethod(ctx, httpsAddress, queryHTTPSHost, queryHTTPSHost, method, path, rootCAs)
			Expect(err).NotTo(HaveOccurred())
			Expect(unbound.status).To(Equal(http.StatusNotFound))
			Expect(unbound.allow).To(BeEmpty())
		}
	}, SpecTimeout(30*time.Second))

	It("reloads a renewed server certificate without restarting Envoy", func(ctx SpecContext) {
		initialTLS, err := requestHTTPS(ctx, httpsAddress, httpsHost, httpsHost, "/upstream-health", rootCAs)
		Expect(err).NotTo(HaveOccurred())
		Expect(initialTLS.status).To(Equal(http.StatusOK))
		initialQueryTLS, err := requestHTTPS(ctx, httpsAddress, queryHTTPSHost, queryHTTPSHost, "/upstream-health", rootCAs)
		Expect(err).NotTo(HaveOccurred())
		Expect(initialQueryTLS.status).To(Equal(http.StatusOK))
		initialPodUID, err := gatewayPodUID(ctx, tlsNamespace)
		Expect(err).NotTo(HaveOccurred())

		By("asking cert-manager to renew the server certificate")
		Expect(env.RenewCertificate(ctx, tlsNamespace, "auth-gateway-server")).To(Succeed())

		var rotatedTLS *httpsResult
		initialSerial := initialTLS.certificate.SerialNumber.String()
		Eventually(func() error {
			result, err := requestHTTPS(ctx, httpsAddress, httpsHost, httpsHost, "/upstream-health", rootCAs)
			if err != nil {
				return err
			}
			if result.certificate.SerialNumber.String() == initialSerial {
				return fmt.Errorf("certificate serial %s has not rotated", initialSerial)
			}
			rotatedTLS = result
			return nil
		}).WithContext(ctx).WithTimeout(8 * time.Minute).WithPolling(500 * time.Millisecond).Should(Succeed())

		Expect(rotatedTLS.status).To(Equal(http.StatusOK))
		Expect(rotatedTLS.certificate.DNSNames).To(ContainElement(httpsHost))
		Expect(rotatedTLS.certificate.NotAfter).To(BeTemporally(">", initialTLS.certificate.NotAfter))
		Expect(rotatedTLS.certificate.RawSubjectPublicKeyInfo).NotTo(Equal(initialTLS.certificate.RawSubjectPublicKeyInfo), "cert-manager should rotate the private key")

		rotatedPodUID, err := gatewayPodUID(ctx, tlsNamespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(rotatedPodUID).To(Equal(initialPodUID), "the gateway Pod should not restart during certificate rotation")
		queryTLS, err := requestHTTPS(ctx, httpsAddress, queryHTTPSHost, queryHTTPSHost, "/upstream-health", rootCAs)
		Expect(err).NotTo(HaveOccurred())
		Expect(queryTLS.status).To(Equal(http.StatusOK))
		Expect(queryTLS.certificate.Raw).To(Equal(initialQueryTLS.certificate.Raw), "renewing one server certificate should leave the other unchanged")
	}, SpecTimeout(9*time.Minute))
})
