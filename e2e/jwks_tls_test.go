//go:build e2e

package e2e

import (
	"net/http"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("JWKS certificate verification", Label("gateway", "jwt", "tls", "production"), Ordered, func() {
	const namespace = "auth-gateway-jwks-tls-e2e"
	var gateway *jwtE2E
	BeforeAll(func(ctx SpecContext) {
		DeferCleanup(func(ctx SpecContext) { Expect(env.DeleteNamespace(ctx, namespace)).To(Succeed()) }, NodeTimeout(3*time.Minute))
		var err error
		gateway, err = setupJWTGateway(ctx, namespace, "jwt-jwks-lifecycle.yaml")
		Expect(err).NotTo(HaveOccurred())
	}, NodeTimeout(12*time.Minute))

	It("rejects a trusted wrong hostname and an untrusted root, then recovers", func(ctx SpecContext) {
		selector := "app.kubernetes.io/name=auth-gateway"
		uid, err := env.PodUID(ctx, namespace, selector)
		Expect(err).NotTo(HaveOccurred())
		admin := env.ForwardWithCleanup(ctx, namespace, "deployment/auth-gateway", 9901)
		token := gateway.token("issuer-one", jwtTestClaims("customer-a"), nil)
		wrongHost, err := gateway.certs.withDNSNames([]string{"wrong.example.test"})
		Expect(err).NotTo(HaveOccurred())
		untrusted, err := makeJWTTestCertificates([]string{"jwks." + namespace + ".svc.cluster.local"})
		Expect(err).NotTo(HaveOccurred())
		for i, certificates := range []*jwtTestCertificates{wrongHost, untrusted} {
			revision := []string{"wrong-host", "untrusted-root"}[i]
			Expect(updateJWTJWKSServer(ctx, namespace, certificates, gateway.keys, nil, revision)).To(Succeed())
			Eventually(func() int {
				status, _, err := gateway.request(ctx, gateway.httpAddr, jwtLifecycleHost, false, token, false)
				Expect(err).NotTo(HaveOccurred())
				return status
			}).WithContext(ctx).WithTimeout(45*time.Second).WithPolling(500*time.Millisecond).Should(BeNumerically(">=", 400), revision)
			before, err := jwtUpstreamRequests(ctx, admin, "api-metrics")
			Expect(err).NotTo(HaveOccurred())
			for range 5 {
				status, _, err := gateway.request(ctx, gateway.httpAddr, jwtLifecycleHost, false, token, false)
				Expect(err).NotTo(HaveOccurred())
				Expect(status).To(BeNumerically(">=", 400), revision)
			}
			after, err := jwtUpstreamRequests(ctx, admin, "api-metrics")
			Expect(err).NotTo(HaveOccurred())
			Expect(after).To(Equal(before), "TLS verification failures must not forward requests")
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+admin+"/ready", nil)
			Expect(err).NotTo(HaveOccurred())
			response, err := testClient.Do(request)
			Expect(err).NotTo(HaveOccurred())
			Expect(response.Body.Close()).To(Succeed())
			Expect(response.StatusCode).To(Equal(http.StatusOK), "issuer failure must not remove a ready gateway")
		}
		Expect(updateJWTJWKSServer(ctx, namespace, gateway.certs, gateway.keys, nil, "correct-identity")).To(Succeed())
		Eventually(func() int {
			status, _, err := gateway.request(ctx, gateway.httpAddr, jwtLifecycleHost, false, token, false)
			Expect(err).NotTo(HaveOccurred())
			return status
		}).WithContext(ctx).WithTimeout(30 * time.Second).WithPolling(500 * time.Millisecond).Should(Equal(http.StatusOK))
		currentUID, err := env.PodUID(ctx, namespace, selector)
		Expect(err).NotTo(HaveOccurred())
		Expect(currentUID).To(Equal(uid))
	}, SpecTimeout(8*time.Minute))
})
