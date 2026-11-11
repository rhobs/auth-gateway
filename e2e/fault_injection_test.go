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
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	gatewayconfig "github.com/rhobs/auth-gateway/pkg/gateway"
	"sigs.k8s.io/yaml"
)

const (
	faultInjectionHost      = "fault.auth-gateway.test"
	faultInjectionPlainHost = "fault-plain.auth-gateway.test"
)

var faultInjectionNamespace = e2eNamespace("fault-injection-e2e")

var _ = Describe("Fault injection", Label("gateway", "fault-injection", "namespace-"+faultInjectionNamespace), Ordered, func() {
	var gatewayConfig gatewayapi.Config
	var gatewayAddress, adminAddress, metricsAddress string

	BeforeAll(func(ctx SpecContext) {
		DeferCleanup(func() { deleteNamespaceInBackground(faultInjectionNamespace) })
		Expect(resetE2ENamespace(ctx, faultInjectionNamespace)).To(Succeed())

		backend, err := env.Fixture("httpbin.yaml")
		Expect(err).NotTo(HaveOccurred())
		Expect(env.Apply(ctx, faultInjectionNamespace, backend)).To(Succeed())

		fixture, err := env.Fixture("fault-injection.yaml")
		Expect(err).NotTo(HaveOccurred())
		gatewayConfig, err = gatewayconfig.Load(bytes.NewReader(fixture))
		Expect(err).NotTo(HaveOccurred())
		gatewayConfig.Kubernetes.Namespace = faultInjectionNamespace
		secret, err := gatewayconfig.APIKeySecret(faultInjectionNamespace, gatewayConfig.Authenticators[0], []gatewayapi.APIKeyCredential{
			{Key: "key-a", Attributes: map[string]string{"tenant_id": "tenant-a", "writer_id": "writer-a"}},
			{Key: "key-b", Attributes: map[string]string{"tenant_id": "tenant-b", "writer_id": "writer-a"}},
			{Key: "key-c", Attributes: map[string]string{"tenant_id": "tenant-c", "writer_id": "writer-a"}},
			{Key: "key-writer-b", Attributes: map[string]string{"tenant_id": "tenant-a", "writer_id": "writer-b"}},
			{Key: "key-denied", Attributes: map[string]string{"tenant_id": "tenant-denied", "writer_id": "writer-a"}},
			{Key: "key-no-writer", Attributes: map[string]string{"tenant_id": "tenant-a"}},
		})
		Expect(err).NotTo(HaveOccurred())
		secretManifest, err := yaml.Marshal(secret)
		Expect(err).NotTo(HaveOccurred())
		Expect(env.Apply(ctx, faultInjectionNamespace, secretManifest)).To(Succeed())
		Expect(applyFaultInjectionGateway(ctx, gatewayConfig)).To(Succeed())
		for _, deployment := range []string{"httpbin", "auth-gateway"} {
			Expect(env.WaitForDeployment(ctx, faultInjectionNamespace, deployment, 4*time.Minute)).To(Succeed())
		}

		gatewayAddress = env.ForwardWithCleanup(ctx, faultInjectionNamespace, "service/auth-gateway", 80)
		adminAddress = env.ForwardEnvoyAdminWithCleanup(ctx, faultInjectionNamespace)
		metricsAddress = env.ForwardWithCleanup(ctx, faultInjectionNamespace, "service/auth-gateway", 8889)
	}, NodeTimeout(9*time.Minute))

	It("aborts selected methods and counts the injected failures with their authenticated tenant", func(ctx SpecContext) {
		labels := requestMetricLabels("injected", http.StatusServiceUnavailable, "tenant-a", "writer-a")
		before, err := requestMetricCount(ctx, adminAddress, labels)
		Expect(err).NotTo(HaveOccurred())
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			var payload []byte
			if method == http.MethodPost {
				payload = []byte("test SLO fault")
			}
			status, body := expectDeniedBeforeUpstream(ctx, adminAddress, "api-injected", method+" injected request", http.StatusServiceUnavailable, func() (int, []byte, error) {
				return requestFaultInjection(ctx, gatewayAddress, method, "/injected/probe", payload, faultInjectionHeaders("key-a", "true"))
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

	It("requires the configured header trigger", func(ctx SpecContext) {
		for _, trigger := range []string{"", "false"} {
			payload := []byte("request without a matching trigger")
			headers := faultInjectionHeaders("key-a", trigger)
			headers.Set("X-Envoy-Fault-Abort-Request", "599")
			headers.Set("X-Envoy-Fault-Abort-Request-Percentage", "100")
			status, body := expectUpstreamRequestDelta(ctx, adminAddress, "api-injected", "unmatched trigger", 1, func() (int, []byte, error) {
				return requestFaultInjection(ctx, gatewayAddress, http.MethodPost, "/injected/probe?source=trigger", payload, headers)
			})
			Expect(status).To(Equal(http.StatusOK), string(body))
			expectFaultInjectionEcho(body, http.MethodPost, "/anything/injected/probe?source=trigger", payload, "tenant-a")
		}
	}, NodeTimeout(60*time.Second))

	It("does not let request headers select another authenticated tenant", func(ctx SpecContext) {
		payload := []byte("another tenant")
		headers := faultInjectionHeaders("key-b", "true")
		headers.Set("X-Scope-OrgID", "tenant-a")
		headers.Set("X-Auth-Gateway-API-Key-Client", "tenant-a")
		status, body := expectUpstreamRequestDelta(ctx, adminAddress, "api-injected", "other tenant", 1, func() (int, []byte, error) {
			return requestFaultInjection(ctx, gatewayAddress, http.MethodPost, "/injected/probe?source=tenant", payload, headers)
		})
		Expect(status).To(Equal(http.StatusOK), string(body))
		expectFaultInjectionEcho(body, http.MethodPost, "/anything/injected/probe?source=tenant", payload, "tenant-b")
	}, NodeTimeout(60*time.Second))

	It("matches any listed tenant value", func(ctx SpecContext) {
		expectDeniedBeforeUpstream(ctx, adminAddress, "api-injected", "second selected tenant", http.StatusServiceUnavailable, func() (int, []byte, error) {
			return requestFaultInjection(ctx, gatewayAddress, http.MethodGet, "/injected/probe", nil, faultInjectionHeaders("key-c", "true"))
		})
	}, NodeTimeout(60*time.Second))

	It("accepts another trigger value and any present verified writer", func(ctx SpecContext) {
		expectDeniedBeforeUpstream(ctx, adminAddress, "api-injected", "alternate trigger and writer", http.StatusServiceUnavailable, func() (int, []byte, error) {
			return requestFaultInjection(ctx, gatewayAddress, http.MethodGet, "/injected/probe", nil, faultInjectionHeaders("key-writer-b", "canary"))
		})
	}, NodeTimeout(60*time.Second))

	It("requires every selected attribute to be present", func(ctx SpecContext) {
		payload := []byte("no writer attribute")
		status, body := expectUpstreamRequestDelta(ctx, adminAddress, "api-injected", "missing selector attribute", 1, func() (int, []byte, error) {
			return requestFaultInjection(ctx, gatewayAddress, http.MethodPost, "/injected/probe?source=missing", payload, faultInjectionHeaders("key-no-writer", "true"))
		})
		Expect(status).To(Equal(http.StatusOK), string(body))
		expectFaultInjectionEcho(body, http.MethodPost, "/anything/injected/probe?source=missing", payload, "tenant-a")
	}, NodeTimeout(60*time.Second))

	It("preserves authentication and authorization denials when the trigger matches", func(ctx SpecContext) {
		for _, test := range []struct {
			key    string
			tenant string
			writer string
			status int
		}{
			{key: "", tenant: "__unattributed__", writer: "__unattributed__", status: http.StatusUnauthorized},
			{key: "wrong", tenant: "__unattributed__", writer: "__unattributed__", status: http.StatusUnauthorized},
			{key: "key-denied", tenant: "tenant-denied", writer: "writer-a", status: http.StatusForbidden},
		} {
			labels := requestMetricLabels("injected", test.status, test.tenant, test.writer)
			before, err := requestMetricCount(ctx, adminAddress, labels)
			Expect(err).NotTo(HaveOccurred())
			expectDeniedBeforeUpstream(ctx, adminAddress, "api-injected", "denied credentials", test.status, func() (int, []byte, error) {
				return requestFaultInjection(ctx, gatewayAddress, http.MethodGet, "/injected/probe", nil, faultInjectionHeaders(test.key, "true"))
			})
			after, err := requestMetricCount(ctx, adminAddress, labels)
			Expect(err).NotTo(HaveOccurred())
			Expect(after).To(Equal(before + 1))
		}
	}, NodeTimeout(60*time.Second))

	It("counts backend and injected 503 replies in the same request counter", func(ctx SpecContext) {
		labels := requestMetricLabels("injected", http.StatusServiceUnavailable, "tenant-a", "writer-a")
		before, err := requestMetricCount(ctx, adminAddress, labels)
		Expect(err).NotTo(HaveOccurred())
		beforeTotal, err := requestMetricTotal(ctx, adminAddress)
		Expect(err).NotTo(HaveOccurred())
		for i, test := range []struct {
			name          string
			path          string
			trigger       string
			upstreamDelta uint64
		}{
			{name: "backend error", path: "/injected/backend-error", upstreamDelta: 1},
			{name: "injected error", path: "/injected/probe", trigger: "true"},
		} {
			status, body := expectUpstreamRequestDelta(ctx, adminAddress, "api-injected", test.name, test.upstreamDelta, func() (int, []byte, error) {
				return requestFaultInjection(ctx, gatewayAddress, http.MethodGet, test.path, nil, faultInjectionHeaders("key-a", test.trigger))
			})
			Expect(status).To(Equal(http.StatusServiceUnavailable), string(body))
			after, err := requestMetricCount(ctx, adminAddress, labels)
			Expect(err).NotTo(HaveOccurred())
			Expect(after).To(Equal(before+uint64(i)+1), test.name)
		}
		afterTotal, err := requestMetricTotal(ctx, adminAddress)
		Expect(err).NotTo(HaveOccurred())
		Expect(afterTotal).To(Equal(beforeTotal + 2))
	}, NodeTimeout(60*time.Second))

	It("does not inject or meter gateway fallback routes", func(ctx SpecContext) {
		before, err := requestMetricTotal(ctx, adminAddress)
		Expect(err).NotTo(HaveOccurred())
		for _, test := range []struct {
			method string
			path   string
			status int
		}{
			{method: http.MethodGet, path: "/unknown", status: http.StatusNotFound},
			{method: http.MethodDelete, path: "/injected/probe", status: http.StatusMethodNotAllowed},
		} {
			expectDeniedBeforeUpstream(ctx, adminAddress, "api-injected", "fallback route", test.status, func() (int, []byte, error) {
				return requestFaultInjection(ctx, gatewayAddress, test.method, test.path, nil, faultInjectionHeaders("key-a", "true"))
			})
		}
		after, err := requestMetricTotal(ctx, adminAddress)
		Expect(err).NotTo(HaveOccurred())
		Expect(after).To(Equal(before))
	}, NodeTimeout(60*time.Second))

	It("forwards requests to the sibling API", func(ctx SpecContext) {
		payload := []byte("healthy API request")
		status, body := expectUpstreamRequestDelta(ctx, adminAddress, "api-healthy", "healthy request", 1, func() (int, []byte, error) {
			return requestFaultInjection(ctx, gatewayAddress, http.MethodPost, "/healthy/probe?source=e2e", payload, faultInjectionHeaders("key-a", "true"))
		})
		Expect(status).To(Equal(http.StatusOK), string(body))
		expectFaultInjectionEcho(body, http.MethodPost, "/anything/healthy/probe?source=e2e", payload, "tenant-a")
	}, NodeTimeout(60*time.Second))

	It("forwards the same API on another server without a fault policy", func(ctx SpecContext) {
		payload := []byte("same API, different server")
		status, body := expectUpstreamRequestDelta(ctx, adminAddress, "api-injected", "unconfigured server binding", 1, func() (int, []byte, error) {
			return requestFaultInjectionToHost(ctx, gatewayAddress, faultInjectionPlainHost, http.MethodPost, "/injected/probe?source=other-server", payload, faultInjectionHeaders("key-a", "true"))
		})
		Expect(status).To(Equal(http.StatusOK), string(body))
		expectFaultInjectionEcho(body, http.MethodPost, "/anything/injected/probe?source=other-server", payload, "tenant-a")
	}, NodeTimeout(60*time.Second))

	It("stops aborting after a configuration change and explicit rollout", func(ctx SpecContext) {
		originalUID, err := gatewayPodUID(ctx, faultInjectionNamespace)
		Expect(err).NotTo(HaveOccurred())

		gatewayConfig.Servers[0].APIs[0].FaultInjection.Enabled = false
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
			return requestFaultInjection(ctx, gatewayAddress, http.MethodPost, "/injected/probe?source=disabled", payload, faultInjectionHeaders("key-a", "true"))
		})
		Expect(status).To(Equal(http.StatusOK), string(body))
		expectFaultInjectionEcho(body, http.MethodPost, "/anything/injected/probe?source=disabled", payload, "tenant-a")
	}, NodeTimeout(7*time.Minute))
})

func applyFaultInjectionGateway(ctx context.Context, gatewayConfig gatewayapi.Config) error {
	resources, err := gatewayconfig.GenerateKubernetes(gatewayConfig)
	if err != nil {
		return err
	}
	manifest, err := resources.YAML()
	if err != nil {
		return err
	}
	return env.Apply(ctx, faultInjectionNamespace, manifest)
}

func faultInjectionHeaders(key, trigger string) http.Header {
	headers := make(http.Header)
	if key != "" {
		headers.Set("X-Partner-Key", key)
	}
	if trigger != "" {
		headers.Set("X-Inject-Fault", trigger)
	}
	return headers
}

func requestFaultInjection(ctx context.Context, address, method, path string, payload []byte, headers http.Header) (int, []byte, error) {
	return requestFaultInjectionToHost(ctx, address, faultInjectionHost, method, path, payload, headers)
}

func requestFaultInjectionToHost(ctx context.Context, address, host, method, path string, payload []byte, headers http.Header) (int, []byte, error) {
	request, err := http.NewRequestWithContext(ctx, method, "http://"+address+path, bytes.NewReader(payload))
	if err != nil {
		return 0, nil, err
	}
	request.Host = host
	request.Header = headers.Clone()
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("X-Fault-Test", "forwarded")
	response, err := testClient.Do(request)
	if err != nil {
		return 0, nil, err
	}
	body, err := readAndCloseResponseBody(response, 1<<20)
	return response.StatusCode, body, err
}

func expectFaultInjectionEcho(body []byte, method, path string, payload []byte, tenant string) {
	echo, err := decodeHTTPBinEcho(body)
	Expect(err).NotTo(HaveOccurred())
	Expect(echo.Method).To(Equal(method))
	Expect(echo.URL).To(HaveSuffix(path))
	Expect(echo.Data).To(Equal("data:application/octet-stream;base64," + base64.StdEncoding.EncodeToString(payload)))
	Expect(headerValue(echo.Headers, "Content-Type")).To(Equal("application/octet-stream"))
	Expect(headerValue(echo.Headers, "X-Fault-Test")).To(Equal("forwarded"))
	Expect(headerValue(echo.Headers, "X-Scope-OrgID")).To(Equal(tenant))
	Expect(headerValue(echo.Headers, "X-Partner-Key")).To(BeEmpty())
}
