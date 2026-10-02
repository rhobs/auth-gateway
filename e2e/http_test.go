//go:build e2e

package e2e

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type httpCase struct {
	method      string
	path        string
	host        string
	wantStatus  int
	inspectEcho bool
}

var _ = Describe("HTTP routing and metrics", Label("gateway", "routing", "metrics"), Ordered, func() {
	BeforeAll(func(ctx SpecContext) {
		setupGateway(ctx, routingNamespace, false)
	}, NodeTimeout(12*time.Minute))

	DescribeTable("HTTP request handling", func(ctx SpecContext, test httpCase) {
		body := []byte("remote-write test payload")
		request, err := http.NewRequestWithContext(ctx, test.method, "http://"+httpAddress+test.path, bytes.NewReader(body))
		Expect(err).NotTo(HaveOccurred())
		request.Host = test.host
		request.Header.Set("Content-Type", "application/octet-stream")
		response, err := testClient.Do(request)
		Expect(err).NotTo(HaveOccurred())
		defer response.Body.Close()
		responseBody, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		Expect(err).NotTo(HaveOccurred())
		Expect(response.StatusCode).To(Equal(test.wantStatus), string(responseBody))
		if test.wantStatus == http.StatusMethodNotAllowed {
			Expect(response.Header.Get("Allow")).To(Equal("POST"))
		} else if test.wantStatus == http.StatusNotFound {
			Expect(response.Header.Get("Allow")).To(BeEmpty())
		}
		if !test.inspectEcho {
			return
		}

		var echoed struct {
			Method string `json:"method"`
			URL    string `json:"url"`
			Data   string `json:"data"`
		}
		Expect(json.Unmarshal(responseBody, &echoed)).To(Succeed())
		Expect(echoed.Method).To(Equal(http.MethodPost))
		Expect(echoed.URL).To(HaveSuffix("/anything/api/v1/receive"))
		wantData := "data:application/octet-stream;base64," + base64.StdEncoding.EncodeToString(body)
		Expect(echoed.Data).To(Equal(wantData))
	},
		Entry("forwards metrics", httpCase{method: http.MethodPost, path: "/metrics/api/v1/receive", host: httpHost, wantStatus: http.StatusOK, inspectEcho: true}),
		Entry("rejects other methods", httpCase{method: http.MethodGet, path: "/metrics/api/v1/receive", host: httpHost, wantStatus: http.StatusMethodNotAllowed}),
		Entry("rejects unknown paths", httpCase{method: http.MethodPost, path: "/unknown", host: httpHost, wantStatus: http.StatusNotFound}),
		Entry("serves the query host's bound API", httpCase{method: http.MethodGet, path: "/upstream-health", host: queryHTTPHost, wantStatus: http.StatusOK}),
		Entry("rejects an API not bound to the query host", httpCase{method: http.MethodPost, path: "/metrics/api/v1/receive", host: queryHTTPHost, wantStatus: http.StatusNotFound}),
		Entry("omits method fallbacks for unbound APIs", httpCase{method: http.MethodGet, path: "/metrics/api/v1/receive", host: queryHTTPHost, wantStatus: http.StatusNotFound}),
		Entry("rejects unknown hosts", httpCase{method: http.MethodPost, path: "/metrics/api/v1/receive", host: unknownHost, wantStatus: http.StatusNotFound}),
	)

	It("exposes scraped Envoy metrics", func(ctx SpecContext) {
		Eventually(func() error {
			return checkPrometheusMetrics(ctx, metricsAddress)
		}).WithContext(ctx).WithTimeout(70 * time.Second).WithPolling(500 * time.Millisecond).Should(Succeed())
	}, SpecTimeout(90*time.Second))
})
