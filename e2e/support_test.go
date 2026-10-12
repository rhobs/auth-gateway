//go:build e2e

package e2e

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/rhobs/auth-gateway/e2e/internal/framework"
	utilwait "k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/yaml"
)

var (
	env        *framework.Environment
	testClient = &http.Client{Timeout: 10 * time.Second}
)

const gatewayPodSelector = "app.kubernetes.io/name=auth-gateway"

type httpbinEcho struct {
	Method  string              `json:"method"`
	URL     string              `json:"url"`
	Data    string              `json:"data"`
	Headers map[string][]string `json:"headers"`
}

func decodeHTTPBinEcho(body []byte) (httpbinEcho, error) {
	var echo httpbinEcho
	if err := json.Unmarshal(body, &echo); err != nil {
		return httpbinEcho{}, fmt.Errorf("decode httpbin response: %w", err)
	}
	return echo, nil
}

func gatewayPodUID(ctx context.Context, namespace string) (string, error) {
	return env.PodUID(ctx, namespace, gatewayPodSelector)
}

// nudgeGatewayPod is a best-effort call to speed up ECDS/SDS reload polling: it
// forces the kubelet to immediately recompute the gateway Pod's mounted
// Secret/ConfigMap volumes instead of waiting for its periodic resync. Errors are
// for the caller to decide whether to ignore, since the normal poll still
// succeeds without it, just slower.
func nudgeGatewayPod(ctx context.Context, namespace string) error {
	return env.NudgePods(ctx, namespace, gatewayPodSelector)
}

func resetE2ENamespace(ctx context.Context, namespace string) error {
	if err := env.DeleteNamespace(ctx, namespace); err != nil {
		return err
	}
	return env.CreateNamespace(ctx, namespace)
}

func waitForSuccessfulRequest(ctx context.Context, name string, timeout, interval time.Duration, send func(context.Context) error) error {
	var lastErr error
	err := utilwait.PollUntilContextTimeout(ctx, interval, timeout, true, func(ctx context.Context) (bool, error) {
		lastErr = send(ctx)
		return lastErr == nil, nil
	})
	if err != nil {
		if lastErr != nil {
			return fmt.Errorf("wait for %s: %w (last attempt: %v)", name, err, lastErr)
		}
		return fmt.Errorf("wait for %s: %w", name, err)
	}
	return nil
}

func headerValue(headers map[string][]string, name string) string {
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return strings.Join(value, ",")
		}
	}
	return ""
}

func jwtEchoHeaders(body []byte) map[string][]string {
	echo, err := decodeHTTPBinEcho(body)
	if err != nil {
		return nil
	}
	return echo.Headers
}

func upstreamRequestCount(ctx context.Context, adminAddress, clusterName string) (uint64, error) {
	path := "/stats?filter=cluster." + clusterName + ".upstream_rq_total"
	body, err := env.EnvoyAdminGet(ctx, adminAddress, path)
	if err != nil {
		return 0, err
	}
	wanted := "cluster." + clusterName + ".upstream_rq_total"
	for _, line := range strings.Split(string(body), "\n") {
		name, value, found := strings.Cut(line, ":")
		if !found || strings.TrimSpace(name) != wanted {
			continue
		}
		count, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("parse Envoy stat %q: %w", wanted, err)
		}
		return count, nil
	}
	return 0, fmt.Errorf("Envoy stats do not include %q: %s", wanted, body)
}

func expectUpstreamRequestDelta(ctx context.Context, adminAddress, clusterName, name string, wantDelta uint64, send func() (int, []byte, error)) (int, []byte) {
	before, err := upstreamRequestCount(ctx, adminAddress, clusterName)
	Expect(err).NotTo(HaveOccurred(), name)
	status, body, err := send()
	Expect(err).NotTo(HaveOccurred(), name)
	after, err := upstreamRequestCount(ctx, adminAddress, clusterName)
	Expect(err).NotTo(HaveOccurred(), name)
	Expect(after).To(Equal(before+wantDelta), name+" upstream request count changed unexpectedly")
	return status, body
}

func expectDeniedBeforeUpstream(ctx context.Context, adminAddress, clusterName, name string, wantStatus int, send func() (int, []byte, error)) (int, []byte) {
	status, body := expectUpstreamRequestDelta(ctx, adminAddress, clusterName, name, 0, send)
	Expect(status).To(Equal(wantStatus), name+": "+string(body))
	return status, body
}

func newTestTLSClient(rootCAs *x509.CertPool, serverName string) *http.Client {
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:    rootCAs,
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
	}}
	return &http.Client{Transport: transport, Timeout: 10 * time.Second}
}

func yamlDocuments(objects ...any) ([]byte, error) {
	var output strings.Builder
	for i, object := range objects {
		data, err := yaml.Marshal(object)
		if err != nil {
			return nil, err
		}
		if i > 0 {
			output.WriteString("---\n")
		}
		output.Write(data)
	}
	return []byte(output.String()), nil
}

func readAndCloseResponseBody(response *http.Response, limit int64) ([]byte, error) {
	body, readErr := io.ReadAll(io.LimitReader(response.Body, limit))
	if readErr != nil {
		readErr = fmt.Errorf("read response body: %w", readErr)
	}
	closeErr := response.Body.Close()
	if closeErr != nil {
		closeErr = fmt.Errorf("close response body: %w", closeErr)
	}
	return body, errors.Join(readErr, closeErr)
}

func writeTestOutput(format string, args ...any) {
	if _, err := fmt.Fprintf(GinkgoWriter, format, args...); err != nil {
		log.Printf(format, args...)
		log.Printf("write Ginkgo output: %v", err)
	}
}
