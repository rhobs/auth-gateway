//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhobs/auth-gateway/config"
)

const (
	testNamespace = "auth-gateway-e2e"
	httpHost      = "auth.auth-gateway.test"
	httpsHost     = "tls.auth-gateway.test"
)

func TestGatewayProtocolsAndCertificateRotation(t *testing.T) {
	clusterContext := os.Getenv("AUTH_GATEWAY_E2E_CONTEXT")
	if clusterContext == "" {
		clusterContext = "kind-auth-gateway-e2e"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()

	if _, err := runKubectl(ctx, clusterContext, "", "delete", "namespace", testNamespace, "--ignore-not-found", "--wait=true", "--timeout=120s"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cleanupCancel()
		if t.Failed() {
			logTestState(t, cleanupCtx, clusterContext)
		}
		if _, err := runKubectl(cleanupCtx, clusterContext, "", "delete", "namespace", testNamespace, "--ignore-not-found", "--wait=true", "--timeout=120s"); err != nil {
			t.Errorf("delete test namespace: %v", err)
		}
	})
	if _, err := runKubectl(ctx, clusterContext, "", "create", "namespace", testNamespace); err != nil {
		t.Fatal(err)
	}

	fixtures := filepath.Join("fixtures")
	certificates, err := os.ReadFile(filepath.Join(fixtures, "certificates.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := apply(ctx, clusterContext, testNamespace, certificates); err != nil {
		t.Fatal(err)
	}
	for _, resource := range []string{"issuer/auth-gateway-ca", "certificate/auth-gateway-server"} {
		if _, err := runKubectl(ctx, clusterContext, testNamespace, "wait", "--for=condition=Ready", resource, "--timeout=240s"); err != nil {
			t.Fatal(err)
		}
	}

	backend, err := os.ReadFile(filepath.Join(fixtures, "httpbin.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := apply(ctx, clusterContext, testNamespace, backend); err != nil {
		t.Fatal(err)
	}

	input, err := os.Open(filepath.Join(fixtures, "gateway.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	gatewayConfig, err := config.Load(input)
	if err != nil {
		t.Fatal(err)
	}
	resources, err := config.GenerateKubernetes(gatewayConfig)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := resources.YAML()
	if err != nil {
		t.Fatal(err)
	}
	if err := apply(ctx, clusterContext, testNamespace, manifest); err != nil {
		t.Fatal(err)
	}
	for _, deployment := range []string{"httpbin", "auth-gateway"} {
		if _, err := runKubectl(ctx, clusterContext, testNamespace, "rollout", "status", "deployment/"+deployment, "--timeout=240s"); err != nil {
			t.Fatal(err)
		}
	}

	address, stop, err := startPortForward(ctx, clusterContext, testNamespace, "service/auth-gateway", 80)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)
	readinessCtx, readinessCancel := context.WithTimeout(ctx, 15*time.Second)
	defer readinessCancel()
	if err := waitForUpstream(readinessCtx, address, httpHost); err != nil {
		t.Fatal(err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	body := []byte("remote-write test payload")
	tests := []struct {
		name       string
		method     string
		path       string
		host       string
		wantStatus int
	}{
		{name: "forward metrics", method: http.MethodPost, path: "/metrics/api/v1/receive", host: httpHost, wantStatus: http.StatusOK},
		{name: "reject other methods", method: http.MethodGet, path: "/metrics/api/v1/receive", host: httpHost, wantStatus: http.StatusMethodNotAllowed},
		{name: "reject unknown paths", method: http.MethodPost, path: "/unknown", host: httpHost, wantStatus: http.StatusNotFound},
		{name: "do not serve HTTPS host over HTTP", method: http.MethodGet, path: "/upstream-health", host: httpsHost, wantStatus: http.StatusNotFound},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, err := http.NewRequestWithContext(ctx, test.method, "http://"+address+test.path, bytes.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			request.Host = test.host
			request.Header.Set("Content-Type", "application/octet-stream")
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			responseBody, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != test.wantStatus {
				t.Fatalf("status = %d, want %d: %s", response.StatusCode, test.wantStatus, responseBody)
			}
			if test.name != "forward metrics" {
				if test.wantStatus == http.StatusMethodNotAllowed && response.Header.Get("Allow") != "POST" {
					t.Fatalf("Allow header = %q, want POST", response.Header.Get("Allow"))
				}
				return
			}
			var echoed struct {
				Method string `json:"method"`
				URL    string `json:"url"`
				Data   string `json:"data"`
			}
			if err := json.Unmarshal(responseBody, &echoed); err != nil {
				t.Fatalf("decode upstream response: %v", err)
			}
			if echoed.Method != http.MethodPost {
				t.Errorf("upstream method = %q", echoed.Method)
			}
			if !strings.HasSuffix(echoed.URL, "/anything/api/v1/receive") {
				t.Errorf("upstream URL = %q", echoed.URL)
			}
			wantData := "data:application/octet-stream;base64," + base64.StdEncoding.EncodeToString(body)
			if echoed.Data != wantData {
				t.Errorf("upstream body = %q", echoed.Data)
			}
		})
	}

	httpsAddress, stopHTTPS, err := startPortForward(ctx, clusterContext, testNamespace, "service/auth-gateway", 443)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stopHTTPS)
	caPEM, err := readSecretKey(ctx, clusterContext, testNamespace, "auth-gateway-e2e-ca", "tls.crt")
	if err != nil {
		t.Fatal(err)
	}
	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM(caPEM) {
		t.Fatal("failed to load cert-manager test CA")
	}

	initialTLS, err := requestHTTPS(ctx, httpsAddress, httpsHost, httpsHost, "/upstream-health", rootCAs)
	if err != nil {
		t.Fatal(err)
	}
	if initialTLS.status != http.StatusOK || !containsString(initialTLS.certificate.DNSNames, httpsHost) {
		t.Fatalf("initial HTTPS response status = %d, certificate DNS names = %v", initialTLS.status, initialTLS.certificate.DNSNames)
	}
	wrongHTTPSHost, err := requestHTTPS(ctx, httpsAddress, httpsHost, httpHost, "/upstream-health", rootCAs)
	if err != nil {
		t.Fatal(err)
	}
	if wrongHTTPSHost.status != http.StatusNotFound {
		t.Fatalf("HTTPS request with HTTP Host header status = %d, want 404", wrongHTTPSHost.status)
	}

	initialPodUID, err := gatewayPodUID(ctx, clusterContext, testNamespace)
	if err != nil {
		t.Fatal(err)
	}
	if err := renewCertificate(ctx, os.Getenv("AUTH_GATEWAY_E2E_CMCTL"), clusterContext, testNamespace, "auth-gateway-server"); err != nil {
		t.Fatal(err)
	}
	rotationCtx, rotationCancel := context.WithTimeout(ctx, 8*time.Minute)
	defer rotationCancel()
	rotatedTLS, err := waitForTLSRotation(rotationCtx, httpsAddress, rootCAs, httpsHost, initialTLS.certificate.SerialNumber.String())
	if err != nil {
		t.Fatal(err)
	}
	if rotatedTLS.status != http.StatusOK || !containsString(rotatedTLS.certificate.DNSNames, httpsHost) {
		t.Fatalf("rotated HTTPS response status = %d, certificate DNS names = %v", rotatedTLS.status, rotatedTLS.certificate.DNSNames)
	}
	if !rotatedTLS.certificate.NotAfter.After(initialTLS.certificate.NotAfter) {
		t.Fatalf("rotated certificate expiration = %s, want after initial expiration %s", rotatedTLS.certificate.NotAfter, initialTLS.certificate.NotAfter)
	}
	if bytes.Equal(rotatedTLS.certificate.RawSubjectPublicKeyInfo, initialTLS.certificate.RawSubjectPublicKeyInfo) {
		t.Fatal("cert-manager renewed the certificate without rotating its private key")
	}
	rotatedPodUID, err := gatewayPodUID(ctx, clusterContext, testNamespace)
	if err != nil {
		t.Fatal(err)
	}
	if rotatedPodUID != initialPodUID {
		t.Fatalf("gateway pod UID changed during server certificate rotation: %q -> %q", initialPodUID, rotatedPodUID)
	}

	metricsAddress, stopMetrics, err := startPortForward(ctx, clusterContext, testNamespace, "service/auth-gateway", 8889)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stopMetrics)
	metricsCtx, metricsCancel := context.WithTimeout(ctx, 70*time.Second)
	defer metricsCancel()
	if err := waitForPrometheusMetrics(metricsCtx, metricsAddress); err != nil {
		t.Fatal(err)
	}
}

func waitForUpstream(ctx context.Context, address, host string) error {
	client := &http.Client{Timeout: 2 * time.Second}
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	lastResult := "no response"
	for {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+"/upstream-health", nil)
		if err != nil {
			return err
		}
		request.Host = host
		response, err := client.Do(request)
		if err == nil {
			body, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
			_ = response.Body.Close()
			if readErr != nil {
				lastResult = readErr.Error()
			} else if response.StatusCode == http.StatusOK {
				return nil
			} else {
				lastResult = fmt.Sprintf("HTTP %d: %s", response.StatusCode, body)
			}
		} else {
			lastResult = err.Error()
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("upstream readiness check failed: %s: %w", lastResult, ctx.Err())
		case <-ticker.C:
		}
	}
}

type httpsResult struct {
	status      int
	certificate *x509.Certificate
	body        []byte
}

func requestHTTPS(ctx context.Context, address, serverName, requestHost, requestPath string, rootCAs *x509.CertPool) (*httpsResult, error) {
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:    rootCAs,
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+address+requestPath, nil)
	if err != nil {
		return nil, err
	}
	request.Host = requestHost
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if response.TLS == nil || len(response.TLS.PeerCertificates) == 0 {
		return nil, fmt.Errorf("HTTPS response did not include the peer certificate")
	}
	return &httpsResult{
		status:      response.StatusCode,
		certificate: response.TLS.PeerCertificates[0],
		body:        body,
	}, nil
}

func renewCertificate(ctx context.Context, cmctlPath, clusterContext, namespace, name string) error {
	if cmctlPath == "" {
		cmctlPath = "cmctl"
	}
	args := []string{"renew", "--context", clusterContext, "--namespace", namespace, name}
	output, err := exec.CommandContext(ctx, cmctlPath, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("cmctl %s: %w\n%s", strings.Join(args, " "), err, output)
	}
	return nil
}

func waitForTLSRotation(ctx context.Context, address string, rootCAs *x509.CertPool, host, initialSerial string) (*httpsResult, error) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	lastResult := "certificate has not rotated"
	for {
		result, err := requestHTTPS(ctx, address, host, host, "/upstream-health", rootCAs)
		if err != nil {
			lastResult = err.Error()
		} else if result.certificate.SerialNumber.String() != initialSerial {
			return result, nil
		} else {
			lastResult = fmt.Sprintf("certificate serial %s has not been renewed", result.certificate.SerialNumber)
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("server certificate rotation failed: %s: %w", lastResult, ctx.Err())
		case <-ticker.C:
		}
	}
}

func readSecretKey(ctx context.Context, clusterContext, namespace, name, key string) ([]byte, error) {
	output, err := runKubectl(ctx, clusterContext, namespace, "get", "secret", name, "-o", "json")
	if err != nil {
		return nil, err
	}
	var secret struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(output, &secret); err != nil {
		return nil, fmt.Errorf("decode Secret %q: %w", name, err)
	}
	encoded, ok := secret.Data[key]
	if !ok {
		return nil, fmt.Errorf("Secret %q has no %q data key", name, key)
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode Secret %q key %q: %w", name, key, err)
	}
	return decoded, nil
}

func gatewayPodUID(ctx context.Context, clusterContext, namespace string) (string, error) {
	output, err := runKubectl(ctx, clusterContext, namespace, "get", "pods", "-l", "app.kubernetes.io/instance=auth-gateway", "-o", "json")
	if err != nil {
		return "", err
	}
	var pods struct {
		Items []struct {
			Metadata struct {
				UID string `json:"uid"`
			} `json:"metadata"`
		} `json:"items"`
	}
	if err := json.Unmarshal(output, &pods); err != nil {
		return "", fmt.Errorf("decode gateway Pods: %w", err)
	}
	if len(pods.Items) != 1 || pods.Items[0].Metadata.UID == "" {
		return "", fmt.Errorf("expected one gateway Pod, got %d", len(pods.Items))
	}
	return pods.Items[0].Metadata.UID, nil
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func waitForPrometheusMetrics(ctx context.Context, address string) error {
	client := &http.Client{Timeout: 2 * time.Second}
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	lastResult := "no response"
	for {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+"/metrics", nil)
		if err != nil {
			return err
		}
		response, err := client.Do(request)
		if err == nil {
			body, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
			_ = response.Body.Close()
			if readErr != nil {
				lastResult = readErr.Error()
			} else if response.StatusCode == http.StatusOK && bytes.Contains(body, []byte("envoy_server_live")) {
				return nil
			} else {
				lastResult = fmt.Sprintf("HTTP %d did not include Envoy metrics", response.StatusCode)
			}
		} else {
			lastResult = err.Error()
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("Prometheus metrics scrape failed: %s: %w", lastResult, ctx.Err())
		case <-ticker.C:
		}
	}
}

func apply(ctx context.Context, clusterContext, namespace string, manifest []byte) error {
	args := []string{"--context", clusterContext, "--namespace", namespace, "apply", "--server-side", "--field-manager=auth-gateway-e2e", "-f", "-"}
	command := exec.CommandContext(ctx, "kubectl", args...)
	command.Stdin = bytes.NewReader(manifest)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("kubectl apply: %w\n%s", err, output)
	}
	return nil
}

func runKubectl(ctx context.Context, clusterContext, namespace string, args ...string) ([]byte, error) {
	commandArgs := []string{"--context", clusterContext, "--request-timeout=20s"}
	if namespace != "" {
		commandArgs = append(commandArgs, "--namespace", namespace)
	}
	commandArgs = append(commandArgs, args...)
	output, err := exec.CommandContext(ctx, "kubectl", commandArgs...).CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("kubectl %s: %w\n%s", strings.Join(commandArgs, " "), err, output)
	}
	return output, nil
}

func logTestState(t *testing.T, ctx context.Context, clusterContext string) {
	t.Helper()
	checks := []struct {
		name      string
		namespace string
		args      []string
	}{
		{name: "pods", namespace: testNamespace, args: []string{"get", "pods", "-o", "wide"}},
		{name: "services", namespace: testNamespace, args: []string{"get", "services", "-o", "wide"}},
		{name: "endpoints", namespace: testNamespace, args: []string{"get", "endpoints", "httpbin", "-o", "wide"}},
		{name: "events", namespace: testNamespace, args: []string{"get", "events", "--sort-by=.lastTimestamp"}},
		{name: "envoy logs", namespace: testNamespace, args: []string{"logs", "deployment/auth-gateway", "-c", "envoy", "--tail=40"}},
		{name: "collector logs", namespace: testNamespace, args: []string{"logs", "deployment/auth-gateway", "-c", "metrics", "--tail=40"}},
	}
	for _, check := range checks {
		output, err := runKubectl(ctx, clusterContext, check.namespace, check.args...)
		if err != nil {
			t.Logf("%s: %v", check.name, err)
			continue
		}
		t.Logf("%s:\n%s", check.name, output)
	}
	address, stop, err := startPortForward(ctx, clusterContext, testNamespace, "deployment/auth-gateway", 9901)
	if err != nil {
		t.Logf("Envoy cluster state: start port-forward: %v", err)
		return
	}
	defer stop()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+"/clusters?format=json", nil)
	if err != nil {
		t.Logf("Envoy cluster state: create request: %v", err)
		return
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Logf("Envoy cluster state: request admin API: %v", err)
		return
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		t.Logf("Envoy cluster state: read admin response: %v", err)
		return
	}
	t.Logf("Envoy cluster state (HTTP %d):\n%s", response.StatusCode, data)
}

func startPortForward(ctx context.Context, clusterContext, namespace, resource string, remotePort int) (string, func(), error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	localPort := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		return "", nil, err
	}

	processContext, cancel := context.WithCancel(context.Background())
	args := []string{"--context", clusterContext, "--namespace", namespace, "port-forward", "--address=127.0.0.1", resource, fmt.Sprintf("%d:%d", localPort, remotePort)}
	command := exec.CommandContext(processContext, "kubectl", args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		cancel()
		return "", nil, err
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	stop := func() {
		cancel()
		<-done
	}

	address := fmt.Sprintf("127.0.0.1:%d", localPort)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		connection, err := net.DialTimeout("tcp", address, 200*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return address, stop, nil
		}
		select {
		case processErr := <-done:
			cancel()
			return "", nil, fmt.Errorf("kubectl port-forward: %v\n%s%s", processErr, stdout.String(), stderr.String())
		case <-ctx.Done():
			stop()
			return "", nil, ctx.Err()
		case <-ticker.C:
		}
	}
}
