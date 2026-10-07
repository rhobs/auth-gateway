//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const jwtMetricsNamespace = "auth-gateway-jwt-metrics-e2e"

type requestMetricSample struct {
	labels string
	count  uint64
}

var _ = Describe("Per-API request metrics", Label("gateway", "jwt", "metrics"), Ordered, func() {
	var gateway *jwtE2E
	var adminAddress string
	var collectorAddress string

	BeforeAll(func(ctx SpecContext) {
		DeferCleanup(func(ctx SpecContext) { Expect(env.DeleteNamespace(ctx, jwtMetricsNamespace)).To(Succeed()) }, NodeTimeout(3*time.Minute))
		var err error
		gateway, err = setupJWTGateway(ctx, jwtMetricsNamespace, "jwt-gateway.yaml")
		Expect(err).NotTo(HaveOccurred())
		adminAddress = env.ForwardWithCleanup(ctx, jwtMetricsNamespace, "deployment/auth-gateway", 9901)
		collectorAddress = env.ForwardWithCleanup(ctx, jwtMetricsNamespace, "service/auth-gateway", 8889)
	}, NodeTimeout(12*time.Minute))

	It("counts a successful request with mapped labels", func(ctx SpecContext) {
		labels := requestMetricLabels("metrics", http.StatusOK, "team-a", "writer-17")
		before, err := requestMetricCount(ctx, adminAddress, labels)
		Expect(err).NotTo(HaveOccurred())

		token := gateway.token("issuer-one", jwtTestClaims("customer-a"), nil)
		status, body, err := gateway.request(ctx, gateway.httpAddr, jwtHTTPHost, false, token, false)
		Expect(err).NotTo(HaveOccurred())
		Expect(status).To(Equal(http.StatusOK), string(body))
		var echo struct {
			Method  string              `json:"method"`
			URL     string              `json:"url"`
			Data    string              `json:"data"`
			Headers map[string][]string `json:"headers"`
		}
		Expect(json.Unmarshal(body, &echo)).To(Succeed())
		Expect(echo.Method).To(Equal(http.MethodGet))
		Expect(echo.URL).To(HaveSuffix("/anything"))
		Expect(echo.Data).To(BeEmpty())
		Expect(headerValue(echo.Headers, "X-Scope-OrgID")).To(Equal("team-a"))
		Expect(headerValue(echo.Headers, "X-Writer-ID")).To(Equal("writer-17"))
		Expect(headerValue(echo.Headers, "Authorization")).To(BeEmpty())

		after, err := requestMetricCount(ctx, adminAddress, labels)
		Expect(err).NotTo(HaveOccurred())
		Expect(after).To(Equal(before + 1))
		Eventually(func() error {
			return checkExportedRequestMetric(ctx, collectorAddress, "gateway_http_requests_total", labels)
		}).WithContext(ctx).WithTimeout(15 * time.Second).WithPolling(250 * time.Millisecond).Should(Succeed())
	}, NodeTimeout(60*time.Second))

	It("counts an RBAC denial with a mapped tenant and missing writer", func(ctx SpecContext) {
		labels := requestMetricLabels("metrics", http.StatusForbidden, "team-a", "__unattributed__")
		before, err := requestMetricCount(ctx, adminAddress, labels)
		Expect(err).NotTo(HaveOccurred())
		upstreamBefore, err := jwtUpstreamRequests(ctx, adminAddress, "api-metrics")
		Expect(err).NotTo(HaveOccurred())

		claims := jwtTestClaims("customer-a")
		delete(claims, "sub")
		token := gateway.token("issuer-two", claims, nil)
		status, body, err := gateway.request(ctx, gateway.httpAddr, jwtHTTPHost, false, token, false)
		Expect(err).NotTo(HaveOccurred())
		Expect(status).To(Equal(http.StatusForbidden), string(body))
		upstreamAfter, err := jwtUpstreamRequests(ctx, adminAddress, "api-metrics")
		Expect(err).NotTo(HaveOccurred())
		Expect(upstreamAfter).To(Equal(upstreamBefore), "RBAC denial reached the backend")

		after, err := requestMetricCount(ctx, adminAddress, labels)
		Expect(err).NotTo(HaveOccurred())
		Expect(after).To(Equal(before + 1))
	}, NodeTimeout(60*time.Second))

	It("uses fallback labels for an invalid JWT", func(ctx SpecContext) {
		labels := requestMetricLabels("metrics", http.StatusUnauthorized, "__unattributed__", "__unattributed__")
		before, err := requestMetricCount(ctx, adminAddress, labels)
		Expect(err).NotTo(HaveOccurred())
		upstreamBefore, err := jwtUpstreamRequests(ctx, adminAddress, "api-metrics")
		Expect(err).NotTo(HaveOccurred())

		token := gateway.token("issuer-one", jwtTestClaims("customer-a"), gateway.wrongKey)
		status, body, err := gateway.request(ctx, gateway.httpAddr, jwtHTTPHost, false, token, false)
		Expect(err).NotTo(HaveOccurred())
		Expect(status).To(Equal(http.StatusUnauthorized), string(body))
		upstreamAfter, err := jwtUpstreamRequests(ctx, adminAddress, "api-metrics")
		Expect(err).NotTo(HaveOccurred())
		Expect(upstreamAfter).To(Equal(upstreamBefore), "invalid JWT reached the backend")

		after, err := requestMetricCount(ctx, adminAddress, labels)
		Expect(err).NotTo(HaveOccurred())
		Expect(after).To(Equal(before + 1))
	}, NodeTimeout(60*time.Second))

	It("keeps the upstream response code", func(ctx SpecContext) {
		labels := requestMetricLabels("metrics", http.StatusTeapot, "team-a", "writer-17")
		before, err := requestMetricCount(ctx, adminAddress, labels)
		Expect(err).NotTo(HaveOccurred())
		upstreamBefore, err := jwtUpstreamRequests(ctx, adminAddress, "api-metrics")
		Expect(err).NotTo(HaveOccurred())

		token := gateway.token("issuer-one", jwtTestClaims("customer-a"), nil)
		status, body, err := gateway.requestPath(ctx, gateway.httpAddr, jwtHTTPHost, false, "/upstream-status", token, false)
		Expect(err).NotTo(HaveOccurred())
		Expect(status).To(Equal(http.StatusTeapot), string(body))
		upstreamAfter, err := jwtUpstreamRequests(ctx, adminAddress, "api-metrics")
		Expect(err).NotTo(HaveOccurred())
		Expect(upstreamAfter).To(Equal(upstreamBefore + 1))

		after, err := requestMetricCount(ctx, adminAddress, labels)
		Expect(err).NotTo(HaveOccurred())
		Expect(after).To(Equal(before + 1))
	}, NodeTimeout(60*time.Second))

	It("uses each API binding and excludes unmetered and fallback routes", func(ctx SpecContext) {
		token := gateway.token("issuer-one", jwtTestClaims("customer-a"), nil)
		statusOnly := requestMetricLabels("status-only", http.StatusOK, "__unattributed__", "__unattributed__")
		before, err := requestMetricCount(ctx, adminAddress, statusOnly)
		Expect(err).NotTo(HaveOccurred())
		status, body, err := gateway.requestPath(ctx, gateway.httpAddr, jwtHTTPHost, false, "/status-only", token, false)
		Expect(err).NotTo(HaveOccurred())
		Expect(status).To(Equal(http.StatusOK), string(body))
		var echo struct {
			Method string `json:"method"`
			URL    string `json:"url"`
		}
		Expect(json.Unmarshal(body, &echo)).To(Succeed())
		Expect(echo.Method).To(Equal(http.MethodGet))
		Expect(echo.URL).To(HaveSuffix("/anything"))
		after, err := requestMetricCount(ctx, adminAddress, statusOnly)
		Expect(err).NotTo(HaveOccurred())
		Expect(after).To(Equal(before + 1))

		totalBefore, err := requestMetricTotal(ctx, adminAddress)
		Expect(err).NotTo(HaveOccurred())
		status, body, err = gateway.requestPath(ctx, gateway.httpAddr, jwtHTTPHost, false, "/unmetered", token, false)
		Expect(err).NotTo(HaveOccurred())
		Expect(status).To(Equal(http.StatusOK), string(body))
		Expect(json.Unmarshal(body, &echo)).To(Succeed())
		Expect(echo.URL).To(HaveSuffix("/anything"))
		totalAfter, err := requestMetricTotal(ctx, adminAddress)
		Expect(err).NotTo(HaveOccurred())
		Expect(totalAfter).To(Equal(totalBefore), "unmetered API emitted a custom counter")

		status, body, err = gateway.requestPath(ctx, gateway.httpAddr, jwtHTTPHost, false, "/unknown", token, false)
		Expect(err).NotTo(HaveOccurred())
		Expect(status).To(Equal(http.StatusNotFound), string(body))
		status, body, err = gateway.requestMethodPath(ctx, gateway.httpAddr, jwtHTTPHost, false, http.MethodPost, "/protected", token, false)
		Expect(err).NotTo(HaveOccurred())
		Expect(status).To(Equal(http.StatusMethodNotAllowed), string(body))
		totalAfter, err = requestMetricTotal(ctx, adminAddress)
		Expect(err).NotTo(HaveOccurred())
		Expect(totalAfter).To(Equal(totalBefore), "gateway fallback route emitted a custom counter")
	}, NodeTimeout(60*time.Second))

	It("accepts a 128-byte printable label value", func(ctx SpecContext) {
		printable := make([]byte, 0, 128)
		for char := byte(32); char <= 126; char++ {
			if char != '|' {
				printable = append(printable, char)
			}
		}
		tenant := string(printable) + strings.Repeat("x", 128-len(printable))
		labels := requestMetricLabels("metrics", http.StatusForbidden, tenant, "writer-17")
		before, err := requestMetricCount(ctx, adminAddress, labels)
		Expect(err).NotTo(HaveOccurred())
		upstreamBefore, err := jwtUpstreamRequests(ctx, adminAddress, "api-metrics")
		Expect(err).NotTo(HaveOccurred())

		token := gateway.token("issuer-one", jwtTestClaims(tenant), nil)
		status, body, err := gateway.request(ctx, gateway.httpAddr, jwtHTTPHost, false, token, false)
		Expect(err).NotTo(HaveOccurred())
		Expect(status).To(Equal(http.StatusForbidden), string(body))
		upstreamAfter, err := jwtUpstreamRequests(ctx, adminAddress, "api-metrics")
		Expect(err).NotTo(HaveOccurred())
		Expect(upstreamAfter).To(Equal(upstreamBefore), "denied request reached the backend")

		after, err := requestMetricCount(ctx, adminAddress, labels)
		Expect(err).NotTo(HaveOccurred())
		Expect(after).To(Equal(before + 1))
	}, NodeTimeout(60*time.Second))

	It("replaces unsafe or oversized label values", func(ctx SpecContext) {
		labels := requestMetricLabels("metrics", http.StatusForbidden, "__unattributed__", "writer-17")
		for _, tenant := range []string{"unsafe|tenant", strings.Repeat("x", 129), "non-ASCII-\u00e9"} {
			before, err := requestMetricCount(ctx, adminAddress, labels)
			Expect(err).NotTo(HaveOccurred())
			upstreamBefore, err := jwtUpstreamRequests(ctx, adminAddress, "api-metrics")
			Expect(err).NotTo(HaveOccurred())
			token := gateway.token("issuer-one", jwtTestClaims(tenant), nil)
			status, body, err := gateway.request(ctx, gateway.httpAddr, jwtHTTPHost, false, token, false)
			Expect(err).NotTo(HaveOccurred())
			Expect(status).To(Equal(http.StatusForbidden), string(body))
			upstreamAfter, err := jwtUpstreamRequests(ctx, adminAddress, "api-metrics")
			Expect(err).NotTo(HaveOccurred())
			Expect(upstreamAfter).To(Equal(upstreamBefore), "denied request reached the backend")
			after, err := requestMetricCount(ctx, adminAddress, labels)
			Expect(err).NotTo(HaveOccurred())
			Expect(after).To(Equal(before+1), tenant)
		}
	}, NodeTimeout(60*time.Second))
})

func requestMetricLabels(api string, status int, tenant, writer string) map[string]string {
	return map[string]string{
		"api":              api,
		"http_status_code": strconv.Itoa(status),
		"tenant":           tenant,
		"writer":           writer,
	}
}

func requestMetricCount(ctx context.Context, adminAddress string, labels map[string]string) (uint64, error) {
	samples, err := envoyRequestMetricSamples(ctx, adminAddress)
	if err != nil {
		return 0, err
	}
	for _, sample := range samples {
		matched := true
		for name, value := range labels {
			if !strings.Contains(","+sample.labels+",", ","+name+"="+strconv.Quote(value)+",") {
				matched = false
				break
			}
		}
		if matched {
			return sample.count, nil
		}
	}
	return 0, nil
}

func requestMetricTotal(ctx context.Context, adminAddress string) (uint64, error) {
	samples, err := envoyRequestMetricSamples(ctx, adminAddress)
	if err != nil {
		return 0, err
	}
	var total uint64
	for _, sample := range samples {
		total += sample.count
	}
	return total, nil
}

func envoyRequestMetricSamples(ctx context.Context, adminAddress string) ([]requestMetricSample, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://"+adminAddress+"/stats/prometheus?filter=gateway_http_requests_total", nil)
	if err != nil {
		return nil, err
	}
	response, err := testClient.Do(request)
	if err != nil {
		return nil, err
	}
	body, err := readAndCloseResponseBody(response, 1<<20)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Envoy Prometheus stats returned HTTP %d: %s", response.StatusCode, body)
	}
	const prefix = "envoy_http_lua_gateway_http_requests_total{"
	var samples []requestMetricSample
	for _, line := range strings.Split(string(body), "\n") {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		labels, value, found := strings.Cut(strings.TrimPrefix(line, prefix), "} ")
		if !found {
			return nil, fmt.Errorf("malformed request metric sample: %q", line)
		}
		count, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parse request metric sample %q: %w", line, err)
		}
		samples = append(samples, requestMetricSample{labels: labels, count: count})
	}
	return samples, nil
}

func checkExportedRequestMetric(ctx context.Context, address, name string, labels map[string]string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+"/metrics", nil)
	if err != nil {
		return err
	}
	response, err := testClient.Do(request)
	if err != nil {
		return err
	}
	body, err := readAndCloseResponseBody(response, 1<<20)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("collector metrics returned HTTP %d: %s", response.StatusCode, body)
	}
	wantPrefix := name + "{"
	oldPrefix := "envoy_http_lua_" + wantPrefix
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, oldPrefix) {
			return fmt.Errorf("exported request metric still has Envoy's Lua prefix: %q", line)
		}
		if !strings.HasPrefix(line, wantPrefix) {
			continue
		}
		metricLabels, _, found := strings.Cut(strings.TrimPrefix(line, wantPrefix), "} ")
		if !found {
			return fmt.Errorf("malformed exported request metric sample: %q", line)
		}
		matched := true
		for labelName, value := range labels {
			if !strings.Contains(","+metricLabels+",", ","+labelName+"="+strconv.Quote(value)+",") {
				matched = false
				break
			}
		}
		if matched {
			return nil
		}
	}
	return fmt.Errorf("exported request metric %q with labels %v was not found", name, labels)
}
