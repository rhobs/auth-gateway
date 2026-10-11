//go:build e2e

package e2e

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type httpCase struct {
	method           string
	path             string
	host             string
	wantStatus       int
	wantUpstreamPath string
	upstreamCluster  string
	forwardedHeaders map[string]string
}

var _ = Describe("HTTP routing and metrics", Label("gateway", "routing", "metrics", "namespace-"+routingNamespace), Ordered, func() {
	BeforeAll(func(ctx SpecContext) {
		setupGateway(ctx, routingNamespace, false)
	}, NodeTimeout(9*time.Minute))

	DescribeTable("HTTP request handling", func(ctx SpecContext, test httpCase) {
		var body []byte
		var allowHeader string
		if test.method == http.MethodPost {
			body = []byte("remote-write test payload")
		}
		send := func() (int, []byte, error) {
			request, err := http.NewRequestWithContext(ctx, test.method, "http://"+httpAddress+test.path, bytes.NewReader(body))
			if err != nil {
				return 0, nil, err
			}
			request.Host = test.host
			request.Header.Set("Content-Type", "application/octet-stream")
			for name, value := range test.forwardedHeaders {
				request.Header.Set(name, value)
			}
			response, err := testClient.Do(request)
			if err != nil {
				return 0, nil, err
			}
			allowHeader = response.Header.Get("Allow")
			responseBody, err := readAndCloseResponseBody(response, 1<<20)
			return response.StatusCode, responseBody, err
		}
		var status int
		var responseBody []byte
		if test.wantStatus >= http.StatusBadRequest {
			Expect(test.upstreamCluster).NotTo(BeEmpty(), "denied cases must identify the expected upstream")
			status, responseBody = expectDeniedBeforeUpstream(ctx, routingAdminAddress, test.upstreamCluster, test.path, test.wantStatus, send)
		} else {
			var err error
			status, responseBody, err = send()
			Expect(err).NotTo(HaveOccurred())
			Expect(status).To(Equal(test.wantStatus), string(responseBody))
		}
		Expect(status).To(Equal(test.wantStatus), string(responseBody))
		switch test.wantStatus {
		case http.StatusMethodNotAllowed:
			Expect(allowHeader).To(Equal("POST"))
		case http.StatusNotFound:
			Expect(allowHeader).To(BeEmpty())
		}
		if test.wantUpstreamPath == "" {
			return
		}

		echoed, err := decodeHTTPBinEcho(responseBody)
		Expect(err).NotTo(HaveOccurred())
		Expect(echoed.Method).To(Equal(test.method))
		Expect(echoed.URL).To(HaveSuffix(test.wantUpstreamPath))
		Expect(headerValue(echoed.Headers, "Content-Type")).To(Equal("application/octet-stream"))
		for name, value := range test.forwardedHeaders {
			Expect(headerValue(echoed.Headers, name)).To(Equal(value), "upstream header "+name)
		}
		if len(body) == 0 {
			Expect(echoed.Data).To(BeEmpty())
		} else {
			wantData := "data:application/octet-stream;base64," + base64.StdEncoding.EncodeToString(body)
			Expect(echoed.Data).To(Equal(wantData))
		}
	},
		Entry("forwards metrics", httpCase{method: http.MethodPost, path: "/metrics/api/v1/receive", host: httpHost, wantStatus: http.StatusOK, wantUpstreamPath: "/anything/api/v1/receive"}),
		Entry("rewrites a regex path and preserves the query", httpCase{
			method:           http.MethodGet,
			path:             "/metrics/api/v1/query_range?x=1",
			host:             httpHost,
			wantStatus:       http.StatusOK,
			wantUpstreamPath: "/anything/api/v1/query_range?x=1",
			forwardedHeaders: map[string]string{"X-Routing-Case": "regex"},
		}),
		Entry("rewrites a prefix path", httpCase{
			method:           http.MethodGet,
			path:             "/logs/otlp/v1/logs",
			host:             httpHost,
			wantStatus:       http.StatusOK,
			wantUpstreamPath: "/anything/otlp/v1/logs",
			forwardedHeaders: map[string]string{"X-Routing-Case": "prefix"},
		}),
		Entry("accepts multiple methods on one route", httpCase{
			method:           http.MethodGet,
			path:             "/multi-method/status",
			host:             httpHost,
			wantStatus:       http.StatusOK,
			wantUpstreamPath: "/anything/multi-method/status",
		}),
		Entry("accepts POST on a route that also accepts GET", httpCase{
			method:           http.MethodPost,
			path:             "/multi-method/ingest",
			host:             httpHost,
			wantStatus:       http.StatusOK,
			wantUpstreamPath: "/anything/multi-method/ingest",
		}),
		Entry("uses the first declared matching route", httpCase{
			method:           http.MethodGet,
			path:             "/routes/order/specific",
			host:             httpHost,
			wantStatus:       http.StatusOK,
			wantUpstreamPath: "/anything/first/specific",
		}),
		Entry("rejects a regex path that does not match", httpCase{
			method:          http.MethodGet,
			path:            "/metrics/api/v1/queryXrange",
			host:            httpHost,
			wantStatus:      http.StatusNotFound,
			upstreamCluster: "api-metrics",
		}),
		Entry("rejects a prefix path without the trailing slash", httpCase{
			method:          http.MethodGet,
			path:            "/logs/otlp",
			host:            httpHost,
			wantStatus:      http.StatusNotFound,
			upstreamCluster: "api-metrics",
		}),
		Entry("rejects other methods", httpCase{method: http.MethodGet, path: "/metrics/api/v1/receive", host: httpHost, wantStatus: http.StatusMethodNotAllowed, upstreamCluster: "api-metrics"}),
		Entry("rejects unknown paths", httpCase{method: http.MethodPost, path: "/unknown", host: httpHost, wantStatus: http.StatusNotFound, upstreamCluster: "api-metrics"}),
		Entry("serves the query host's bound API", httpCase{method: http.MethodGet, path: "/upstream-health", host: queryHTTPHost, wantStatus: http.StatusOK, wantUpstreamPath: "/anything"}),
		Entry("rejects an API not bound to the query host", httpCase{method: http.MethodPost, path: "/metrics/api/v1/receive", host: queryHTTPHost, wantStatus: http.StatusNotFound, upstreamCluster: "api-metrics"}),
		Entry("omits method fallbacks for unbound APIs", httpCase{method: http.MethodGet, path: "/metrics/api/v1/receive", host: queryHTTPHost, wantStatus: http.StatusNotFound, upstreamCluster: "api-metrics"}),
		Entry("returns not found for a server with no APIs", httpCase{method: http.MethodGet, path: "/upstream-health", host: "empty.auth-gateway.test", wantStatus: http.StatusNotFound, upstreamCluster: "api-upstream-health"}),
		Entry("rejects unknown hosts", httpCase{method: http.MethodPost, path: "/metrics/api/v1/receive", host: unknownHost, wantStatus: http.StatusNotFound, upstreamCluster: "api-metrics"}),
	)

	It("exposes scraped Envoy metrics", func(ctx SpecContext) {
		Eventually(func() error {
			return checkPrometheusMetrics(ctx, metricsAddress)
		}).WithContext(ctx).WithTimeout(70 * time.Second).WithPolling(500 * time.Millisecond).Should(Succeed())

		_, stop, err := env.Forward(ctx, routingNamespace, "service/auth-gateway", 9901)
		if err == nil {
			stop()
		}
		Expect(err).To(MatchError(`service "auth-gateway" has no port 9901`), "the gateway Service must not expose Envoy's admin port")
	}, NodeTimeout(90*time.Second))

	It("omits the metrics sidecar and Service port when metrics are disabled", func(ctx SpecContext) {
		manifest := generatedGatewayManifestWithMetrics(routingNamespace, false, false)
		Expect(env.Apply(ctx, routingNamespace, manifest)).To(Succeed())
		Expect(env.WaitForDeployment(ctx, routingNamespace, "auth-gateway", 4*time.Minute)).To(Succeed())

		Eventually(func() ([]string, error) {
			_, containers, err := env.PodContainerNames(ctx, routingNamespace, gatewayPodSelector)
			return containers, err
		}).WithContext(ctx).WithTimeout(30 * time.Second).WithPolling(time.Second).Should(ConsistOf("envoy"))

		_, stop, err := env.Forward(ctx, routingNamespace, "service/auth-gateway", 8889)
		if err == nil {
			stop()
		}
		Expect(err).To(MatchError(`service "auth-gateway" has no port 8889`), "the Service must not expose the collector metrics port")
	}, NodeTimeout(5*time.Minute))
})
