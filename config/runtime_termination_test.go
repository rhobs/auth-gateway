//go:build envoyruntime

package config

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
)

func TestEnvoyTerminationCompletesActiveRequest(t *testing.T) {
	started := make(chan struct{})
	backend := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/slow" {
			writer.WriteHeader(http.StatusOK)
			return
		}
		close(started)
		select {
		case <-time.After(8 * time.Second):
			_, _ = io.WriteString(writer, "completed eight-second request")
		case <-request.Context().Done():
		}
	})
	harness, container, grace := runtimeTerminationStart(t, backend)
	result := make(chan runtimeTerminationResponse, 1)
	go func() { result <- runtimeTerminationRequest(harness, "/slow") }()
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("slow request did not reach the backend")
	}

	terminationStarted := time.Now()
	terminated := runtimeTerminationStop(harness.envoyName, container, grace)
	select {
	case response := <-result:
		if response.err != nil || response.status != http.StatusOK || response.body != "completed eight-second request" {
			t.Fatalf("active request during termination: status=%d body=%q error=%v, want a complete 200 response", response.status, response.body, response.err)
		}
		t.Logf("eight-second request completed %s after termination began", time.Since(terminationStarted).Round(time.Millisecond))
	case <-time.After(grace):
		t.Fatal("active request did not complete within the termination budget")
	}
	runtimeTerminationAssertStopped(t, terminated, terminationStarted, grace)
}

func TestEnvoyTerminationClosesNewHTTPConnections(t *testing.T) {
	backend := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, "accepted during drain")
	})
	harness, container, grace := runtimeTerminationStart(t, backend)
	terminationStarted := time.Now()
	terminated := runtimeTerminationStop(harness.envoyName, container, grace)
	runtimeLiveAwait(t, harness, "Envoy readiness failure", time.Time{}, func() (bool, string) {
		output, err := runtimeTerminationProbe(harness.envoyName, container)
		var exit *exec.ExitError
		return errors.As(err, &exit) && exit.ExitCode() == 1, fmt.Sprintf("probe error=%v output=%s", err, output)
	})
	if elapsed := time.Since(terminationStarted); elapsed >= 5*time.Second {
		t.Fatalf("readiness failed after %s, want failure before the propagation delay ends", elapsed)
	}
	// Allow the propagation delay and explicit drain request to complete.
	time.Sleep(6 * time.Second)
	transport := &http.Transport{Proxy: nil}
	t.Cleanup(transport.CloseIdleConnections)
	fresh := &runtimeLiveHarness{address: harness.address, httpClient: &http.Client{Transport: transport, Timeout: 3 * time.Second}}
	for range 2 {
		response := runtimeTerminationRequest(fresh, "/during-drain")
		if response.err != nil || response.status != http.StatusOK || response.body != "accepted during drain" || !response.closeConnection {
			t.Fatalf("new connection during drain: status=%d body=%q close=%t error=%v, want 200 with Connection: close",
				response.status, response.body, response.closeConnection, response.err)
		}
	}
	runtimeTerminationAssertStopped(t, terminated, terminationStarted, grace)
	if response := runtimeTerminationRequest(fresh, "/after-termination"); response.err == nil {
		t.Fatalf("request after termination returned %d, want a connection failure", response.status)
	}
}

func TestEnvoyTerminationBoundsActiveStream(t *testing.T) {
	backend := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/stream" {
			writer.WriteHeader(http.StatusOK)
			return
		}
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			if _, err := io.WriteString(writer, "stream chunk\n"); err != nil {
				return
			}
			if err := http.NewResponseController(writer).Flush(); err != nil {
				return
			}
			select {
			case <-request.Context().Done():
				return
			case <-ticker.C:
			}
		}
	})
	harness, container, grace := runtimeTerminationStart(t, backend)
	request, err := http.NewRequest(http.MethodGet, "http://"+harness.address+"/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "termination.runtime.test"
	response, err := harness.httpClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = response.Body.Close() })
	reader := bufio.NewReader(response.Body)
	if first, err := reader.ReadString('\n'); err != nil || first != "stream chunk\n" || response.StatusCode != http.StatusOK {
		t.Fatalf("initial stream response: status=%d first=%q error=%v", response.StatusCode, first, err)
	}
	streamEnded := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, reader)
		streamEnded <- err
	}()

	terminationStarted := time.Now()
	terminated := runtimeTerminationStop(harness.envoyName, container, grace)
	select {
	case err := <-streamEnded:
		if err == nil || errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("stream ended with %v, want truncation when Envoy terminates", err)
		}
		if elapsed := time.Since(terminationStarted); elapsed < 25*time.Second || elapsed >= grace {
			t.Fatalf("stream ended after %s, want the full propagation and drain periods within %s", elapsed, grace)
		}
		t.Logf("over-budget stream was truncated after %s: %v", time.Since(terminationStarted).Round(time.Millisecond), err)
	case <-time.After(grace):
		t.Fatal("stream outlived the termination budget")
	}
	runtimeTerminationAssertStopped(t, terminated, terminationStarted, grace)
}

func runtimeTerminationStart(t *testing.T, backend http.Handler) (*runtimeLiveHarness, corev1.Container, time.Duration) {
	t.Helper()
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &httptest.Server{Listener: listener, Config: &http.Server{Handler: backend, ReadHeaderTimeout: 5 * time.Second}}
	server.Start()
	t.Cleanup(server.Close)

	c, err := Load(strings.NewReader(`version: 1
listener:
  max_stream_duration: 2m
servers:
  - hostname: termination.runtime.test
    apis: [backend]
apis:
  - name: backend
    upstream: {address: host.docker.internal, port: 8080}
    timeouts: {response_timeout: 2m}
    routes:
      - methods: [GET]
        path: {prefix: /}
kubernetes:
  name: termination-gateway
  namespace: runtime
  envoy_concurrency: 1
observability:
  metrics: {enabled: false}
`))
	if err != nil {
		t.Fatal(err)
	}
	c.APIs[0].Upstream.Port = uint32(listener.Addr().(*net.TCPAddr).Port)
	resources, err := GenerateKubernetes(c)
	if err != nil {
		t.Fatal(err)
	}
	configDir := runtimeDirectory(t)
	for name, contents := range resources.ConfigMap.Data {
		runtimeWrite(t, filepath.Join(configDir, name), []byte(contents))
	}
	pod := resources.Deployment.Spec.Template.Spec
	container := pod.Containers[0]
	address, envoyName := runtimeLiveStartEnvoyWithArgs(t, configDir,
		[]string{"--add-host", "host.docker.internal:host-gateway", "--read-only", "--cap-drop=ALL", "--security-opt", "no-new-privileges"}, container.Args)
	transport := &http.Transport{Proxy: nil}
	t.Cleanup(transport.CloseIdleConnections)
	grace := time.Duration(*pod.TerminationGracePeriodSeconds) * time.Second
	harness := &runtimeLiveHarness{address: address, envoyName: envoyName,
		httpClient: &http.Client{Transport: transport, Timeout: grace + 10*time.Second}}
	runtimeLiveAwait(t, harness, "termination gateway", time.Time{}, func() (bool, string) {
		response := runtimeTerminationRequest(harness, "/ready")
		if response.err != nil || response.status != http.StatusOK {
			return false, fmt.Sprintf("status=%d error=%v", response.status, response.err)
		}
		output, err := runtimeTerminationProbe(envoyName, container)
		return err == nil, fmt.Sprintf("probe error=%v output=%s", err, output)
	})
	return harness, container, grace
}

type runtimeTerminationResponse struct {
	status          int
	body            string
	closeConnection bool
	err             error
}

func runtimeTerminationRequest(harness *runtimeLiveHarness, path string) runtimeTerminationResponse {
	request, err := http.NewRequest(http.MethodGet, "http://"+harness.address+path, nil)
	if err != nil {
		return runtimeTerminationResponse{err: err}
	}
	request.Host = "termination.runtime.test"
	response, err := harness.httpClient.Do(request)
	if err != nil {
		return runtimeTerminationResponse{err: err}
	}
	body, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if readErr != nil {
		return runtimeTerminationResponse{status: response.StatusCode, err: readErr}
	}
	return runtimeTerminationResponse{status: response.StatusCode, body: string(body), closeConnection: response.Close, err: closeErr}
}

func runtimeTerminationProbe(envoyName string, container corev1.Container) ([]byte, error) {
	args := append([]string{"exec", envoyName}, container.ReadinessProbe.Exec.Command...)
	return runtimeLiveCommand(5*time.Second, "docker", args...)
}

type runtimeTerminationResult struct {
	output string
	err    error
}

func runtimeTerminationStop(envoyName string, container corev1.Container, grace time.Duration) <-chan runtimeTerminationResult {
	result := make(chan runtimeTerminationResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), grace)
		defer cancel()
		commands := [][]string{
			append([]string{"exec", envoyName}, container.Lifecycle.PreStop.Exec.Command...),
			{"kill", "--signal=TERM", envoyName},
			{"wait", envoyName},
		}
		for _, args := range commands {
			output, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
			if err != nil {
				result <- runtimeTerminationResult{output: string(output), err: fmt.Errorf("docker %s: %w", strings.Join(args, " "), err)}
				return
			}
			if args[0] == "exec" && len(output) != 0 {
				result <- runtimeTerminationResult{output: string(output), err: errors.New("pre-stop hook reported an admin request failure")}
				return
			}
			if args[0] == "wait" {
				result <- runtimeTerminationResult{output: strings.TrimSpace(string(output))}
			}
		}
	}()
	return result
}

func runtimeTerminationAssertStopped(t *testing.T, result <-chan runtimeTerminationResult, started time.Time, grace time.Duration) {
	t.Helper()
	select {
	case stopped := <-result:
		if stopped.err != nil || stopped.output != "0" {
			t.Fatalf("termination error=%v output=%q, want exit code 0 within %s", stopped.err, stopped.output, grace)
		}
		if elapsed := time.Since(started); elapsed >= grace {
			t.Fatalf("termination took %s, want less than %s", elapsed, grace)
		} else {
			t.Logf("Envoy exited after %s within its %s budget", elapsed.Round(time.Millisecond), grace)
		}
	case <-time.After(time.Until(started.Add(grace))):
		t.Fatalf("Envoy did not stop within %s", grace)
	}
}
