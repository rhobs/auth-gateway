//go:build e2e

package e2e

import (
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

	It("serves HTTPS only for the configured TLS host", func(ctx SpecContext) {
		By("not serving the TLS host on plaintext HTTP")
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+httpAddress+"/upstream-health", nil)
		Expect(err).NotTo(HaveOccurred())
		request.Host = httpsHost
		httpResponse, err := testClient.Do(request)
		Expect(err).NotTo(HaveOccurred())
		defer httpResponse.Body.Close()
		Expect(httpResponse.StatusCode).To(Equal(http.StatusNotFound))

		By("serving a certificate trusted by the test CA")
		tlsResponse, err := requestHTTPS(ctx, httpsAddress, httpsHost, httpsHost, "/upstream-health", rootCAs)
		Expect(err).NotTo(HaveOccurred())
		Expect(tlsResponse.status).To(Equal(http.StatusOK))
		Expect(tlsResponse.certificate.DNSNames).To(ContainElement(httpsHost))

		By("rejecting the HTTP host on the HTTPS listener")
		wrongHost, err := requestHTTPS(ctx, httpsAddress, httpsHost, httpHost, "/upstream-health", rootCAs)
		Expect(err).NotTo(HaveOccurred())
		Expect(wrongHost.status).To(Equal(http.StatusNotFound))
	}, SpecTimeout(30*time.Second))

	It("reloads a renewed server certificate without restarting Envoy", func(ctx SpecContext) {
		initialTLS, err := requestHTTPS(ctx, httpsAddress, httpsHost, httpsHost, "/upstream-health", rootCAs)
		Expect(err).NotTo(HaveOccurred())
		Expect(initialTLS.status).To(Equal(http.StatusOK))
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
	}, SpecTimeout(9*time.Minute))
})
