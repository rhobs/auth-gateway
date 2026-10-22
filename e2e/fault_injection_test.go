//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/rhobs/auth-gateway/config"
)

const faultInjectionHost = "fault.auth-gateway.test"

var faultInjectionNamespace = e2eNamespace("fault-injection-e2e")

var _ = Describe("Fault injection", Label("gateway", "fault-injection", "namespace-"+faultInjectionNamespace), Ordered, func() {
	var gatewayConfig config.Config
	var gatewayAddress, adminAddress, metricsAddress string

	BeforeAll(func(ctx SpecContext) {
		DeferCleanup(func() { deleteNamespaceInBackground(faultInjectionNamespace) })
		Expect(resetE2ENamespace(ctx, faultInjectionNamespace)).To(Succeed())

		backend, err := env.Fixture("httpbin.yaml")
		Expect(err).NotTo(HaveOccurred())
		Expect(env.Apply(ctx, faultInjectionNamespace, backend)).To(Succeed())

		fixture, err := env.Fixture("fault-injection.yaml")
		Expect(err).NotTo(HaveOccurred())
		gatewayConfig, err = config.Load(bytes.NewReader(fixture))
		Expect(err).NotTo(HaveOccurred())
		gatewayConfig.Kubernetes.Namespace = faultInjectionNamespace
		Expect(applyFaultInjectionGateway(ctx, gatewayConfig)).To(Succeed())
		for _, deployment := range []string{"httpbin", "auth-gateway"} {
			Expect(env.WaitForDeployment(ctx, faultInjectionNamespace, deployment, 4*time.Minute)).To(Succeed())
		}

		gatewayAddress = env.ForwardWithCleanup(ctx, faultInjectionNamespace, "service/auth-gateway", 80)
		adminAddress = env.ForwardEnvoyAdminWithCleanup(ctx, faultInjectionNamespace)
		metricsAddress = env.ForwardWithCleanup(ctx, faultInjectionNamespace, "service/auth-gateway", 8889)
	}, NodeTimeout(9*time.Minute))

	It("aborts both methods without forwarding and counts their 503 responses", func(ctx SpecContext) {
		labels := map[string]string{"api": "injected", "http_status_code": "503"}
		before, err := requestMetricCount(ctx, adminAddress, labels)
		Expect(err).NotTo(HaveOccurred())
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			var payload []byte
			if method == http.MethodPost {
				payload = []byte("test SLO fault")
			}
			status, body := expectDeniedBeforeUpstream(ctx, adminAddress, "api-injected", method+" injected request", http.StatusServiceUnavailable, func() (int, []byte, error) {
				return requestFaultInjection(ctx, gatewayAddress, method, "/injected/probe", payload)
			})
			Expect(status).To(Equal(http.StatusServiceUnavailable), string(body))
		}
		after, err := requestMetricCount(ctx, adminAddress, labels)
		Expect(err).NotTo(HaveOccurred())
		Expect(after).To(Equal(before + 2))
		Eventually(func() error {
			return checkExportedRequestMetric(ctx, metricsAddress, "gateway_http_requests_total", labels)
		}).WithContext(ctx).WithTimeout(15 * time.Second).WithPolling(250 * time.Millisecond).Should(Succeed())
	}, NodeTimeout(60*time.Second))

	It("forwards requests to the sibling API", func(ctx SpecContext) {
		payload := []byte("healthy API request")
		status, body := expectUpstreamRequestDelta(ctx, adminAddress, "api-healthy", "healthy request", 1, func() (int, []byte, error) {
			return requestFaultInjection(ctx, gatewayAddress, http.MethodPost, "/healthy/probe?source=e2e", payload)
		})
		Expect(status).To(Equal(http.StatusOK), string(body))
		expectFaultInjectionEcho(body, http.MethodPost, "/anything/healthy/probe?source=e2e", payload)
	}, NodeTimeout(60*time.Second))

	It("stops aborting after a configuration change and explicit rollout", func(ctx SpecContext) {
		originalUID, err := gatewayPodUID(ctx, faultInjectionNamespace)
		Expect(err).NotTo(HaveOccurred())

		gatewayConfig.APIs[0].FaultInjection.Enabled = false
		Expect(applyFaultInjectionGateway(ctx, gatewayConfig)).To(Succeed())
		currentUID, err := gatewayPodUID(ctx, faultInjectionNamespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(currentUID).To(Equal(originalUID), "updating the bootstrap ConfigMap must not replace the Pod")

		Expect(env.RestartDeployment(ctx, faultInjectionNamespace, "auth-gateway", 4*time.Minute)).To(Succeed())
		newUID, err := gatewayPodUID(ctx, faultInjectionNamespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(newUID).NotTo(Equal(originalUID), "the rollout must replace the Pod")
		gatewayAddress = env.ForwardWithCleanup(ctx, faultInjectionNamespace, "service/auth-gateway", 80)
		adminAddress = env.ForwardEnvoyAdminWithCleanup(ctx, faultInjectionNamespace)

		payload := []byte("faults disabled")
		status, body := expectUpstreamRequestDelta(ctx, adminAddress, "api-injected", "injection disabled", 1, func() (int, []byte, error) {
			return requestFaultInjection(ctx, gatewayAddress, http.MethodPost, "/injected/probe?source=disabled", payload)
		})
		Expect(status).To(Equal(http.StatusOK), string(body))
		expectFaultInjectionEcho(body, http.MethodPost, "/anything/injected/probe?source=disabled", payload)
	}, NodeTimeout(7*time.Minute))
})

func applyFaultInjectionGateway(ctx context.Context, gatewayConfig config.Config) error {
	resources, err := config.GenerateKubernetes(gatewayConfig)
	if err != nil {
		return err
	}
	manifest, err := resources.YAML()
	if err != nil {
		return err
	}
	return env.Apply(ctx, faultInjectionNamespace, manifest)
}

func requestFaultInjection(ctx context.Context, address, method, path string, payload []byte) (int, []byte, error) {
	request, err := http.NewRequestWithContext(ctx, method, "http://"+address+path, bytes.NewReader(payload))
	if err != nil {
		return 0, nil, err
	}
	request.Host = faultInjectionHost
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("X-Fault-Test", "forwarded")
	response, err := testClient.Do(request)
	if err != nil {
		return 0, nil, err
	}
	body, err := readAndCloseResponseBody(response, 1<<20)
	return response.StatusCode, body, err
}

func expectFaultInjectionEcho(body []byte, method, path string, payload []byte) {
	echo, err := decodeHTTPBinEcho(body)
	Expect(err).NotTo(HaveOccurred())
	Expect(echo.Method).To(Equal(method))
	Expect(echo.URL).To(HaveSuffix(path))
	Expect(echo.Data).To(Equal("data:application/octet-stream;base64," + base64.StdEncoding.EncodeToString(payload)))
	Expect(headerValue(echo.Headers, "Content-Type")).To(Equal("application/octet-stream"))
	Expect(headerValue(echo.Headers, "X-Fault-Test")).To(Equal("forwarded"))
}
