//go:build envoyruntime

package config

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const runtimeAdmissionBody = "admission-control-runtime-body"

func TestEnvoyAdmissionControlIsolatesAPIs(t *testing.T) {
	for _, failure := range []string{"http-error", "connection-reset"} {
		for _, failingAPI := range []string{"loki", "thanos"} {
			t.Run(failure+"/"+failingAPI, func(t *testing.T) {
				backend, port := runtimeAdmissionBackendStart(t, failingAPI, failure == "connection-reset")
				c := runtimeAdmissionConfig(t, port)
				files, err := Generate(c)
				if err != nil {
					t.Fatal(err)
				}
				configDir := runtimeDirectory(t)
				for _, file := range files.All() {
					runtimeLiveWriteGeneratedFile(t, configDir, file)
				}
				address, envoyName := runtimeLiveStartEnvoy(t, configDir,
					[]string{"--add-host", "host.docker.internal:host-gateway"}, []string{"--concurrency", "1"})
				transport := &http.Transport{Proxy: nil}
				t.Cleanup(transport.CloseIdleConnections)
				harness := &runtimeLiveHarness{address: address, envoyName: envoyName,
					httpClient: &http.Client{Transport: transport, Timeout: 4 * time.Second}}
				runtimeLiveAwait(t, harness, "admission gateway", time.Time{}, func() (bool, string) {
					request, err := http.NewRequest(http.MethodGet, "http://"+address+"/missing", nil)
					if err != nil {
						return false, err.Error()
					}
					request.Host = "admission.runtime.test"
					response, err := harness.httpClient.Do(request)
					if err != nil {
						return false, err.Error()
					}
					if err := response.Body.Close(); err != nil {
						return false, err.Error()
					}
					return response.StatusCode == http.StatusNotFound, response.Status
				})

				healthyAPI := "thanos"
				if failingAPI == healthyAPI {
					healthyAPI = "loki"
				}
				const attempts = 120
				var rejected int
				for index := range attempts {
					path := fmt.Sprintf("/%s/%d", failingAPI, index%2)
					id := fmt.Sprintf("failing-%d", index)
					status := runtimeAdmissionRequest(t, harness, id, http.MethodPost, path)
					if _, received := backend.request(id); received {
						runtimeAdmissionAssertForwarded(t, backend, id, path)
						want := http.StatusInternalServerError
						if failure == "connection-reset" {
							want = http.StatusServiceUnavailable
						}
						if status != want {
							t.Fatalf("forwarded failing request %s status = %d, want %d", id, status, want)
						}
					} else {
						if status != http.StatusServiceUnavailable {
							t.Fatalf("rejected request %s status = %d, want 503", id, status)
						}
						rejected++
					}
					path = fmt.Sprintf("/%s/%d", healthyAPI, index%2)
					id = fmt.Sprintf("healthy-%d", index)
					if status := runtimeAdmissionRequest(t, harness, id, http.MethodPost, path); status != http.StatusOK {
						t.Fatalf("healthy API %s request %d status = %d, want 200", healthyAPI, index, status)
					}
					runtimeAdmissionAssertForwarded(t, backend, id, path)
				}
				if rejected == 0 || rejected == attempts {
					t.Fatalf("admission rejections = %d/%d, want some requests shed and some forwarded", rejected, attempts)
				}

				for index := range 20 {
					id := fmt.Sprintf("disabled-%d", index)
					if status := runtimeAdmissionRequest(t, harness, id, http.MethodPost, "/disabled"); status != http.StatusOK {
						t.Fatalf("disabled API status = %d, want 200", status)
					}
					runtimeAdmissionAssertForwarded(t, backend, id, "/disabled")
					for _, fallback := range []struct {
						method string
						path   string
						status int
					}{{http.MethodGet, "/missing", http.StatusNotFound}, {http.MethodGet, "/loki/0", http.StatusMethodNotAllowed}} {
						id := fmt.Sprintf("fallback-%d-%d", fallback.status, index)
						if status := runtimeAdmissionRequest(t, harness, id, fallback.method, fallback.path); status != fallback.status {
							t.Fatalf("fallback %s status = %d, want %d", fallback.path, status, fallback.status)
						}
						if _, received := backend.request(id); received {
							t.Fatalf("fallback request %s reached the backend", id)
						}
					}
				}
				runtimeAdmissionAssertRejections(t, harness, backend, rejected)
				t.Logf("%s: shed %d/%d failing requests; all %d healthy requests returned 200", failingAPI, rejected, attempts, attempts)
			})
		}
	}
}

func runtimeAdmissionConfig(t *testing.T, port uint32) Config {
	t.Helper()
	input := `version: 1
servers:
  - hostname: admission.runtime.test
    apis: [loki, thanos, disabled]
apis:
  - name: loki
    admission_control:
      enabled: true
      sampling_window: 60s
      rps_threshold: 0
      max_rejection_probability: 80
    upstream: {address: host.docker.internal, port: 8080}
    routes:
      - methods: [POST]
        path: {exact: /loki/0}
      - methods: [POST]
        path: {exact: /loki/1}
  - name: thanos
    admission_control:
      enabled: true
      sampling_window: 60s
      rps_threshold: 0
      max_rejection_probability: 80
    upstream: {address: host.docker.internal, port: 8080}
    routes:
      - methods: [POST]
        path: {exact: /thanos/0}
      - methods: [POST]
        path: {exact: /thanos/1}
  - name: disabled
    admission_control: {enabled: false}
    upstream: {address: host.docker.internal, port: 8080}
    routes:
      - methods: [POST]
        path: {exact: /disabled}
`
	c, err := Load(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	for index := range c.APIs {
		c.APIs[index].Upstream.Port = port
	}
	return c
}

type runtimeAdmissionObservation struct {
	method  string
	path    string
	body    string
	envoyID string
}

type runtimeAdmissionBackend struct {
	mu         sync.Mutex
	failingAPI string
	reset      bool
	requests   map[string]runtimeAdmissionObservation
	envoyIDs   map[string]bool
}

func runtimeAdmissionBackendStart(t *testing.T, failingAPI string, reset bool) (*runtimeAdmissionBackend, uint32) {
	t.Helper()
	backend := &runtimeAdmissionBackend{failingAPI: failingAPI, reset: reset,
		requests: make(map[string]runtimeAdmissionObservation), envoyIDs: make(map[string]bool)}
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &httptest.Server{Listener: listener, Config: &http.Server{Handler: backend, ReadHeaderTimeout: 5 * time.Second}}
	server.Start()
	t.Cleanup(server.Close)
	return backend, uint32(listener.Addr().(*net.TCPAddr).Port)
}

func (b *runtimeAdmissionBackend) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	id := request.Header.Get("X-Admission-Test-ID")
	envoyID := request.Header.Get("X-Request-ID")
	b.mu.Lock()
	b.requests[id] = runtimeAdmissionObservation{method: request.Method, path: request.URL.Path, body: string(body), envoyID: envoyID}
	b.envoyIDs[envoyID] = true
	b.mu.Unlock()
	if strings.HasPrefix(request.URL.Path, "/"+b.failingAPI+"/") {
		if b.reset {
			connection, _, err := http.NewResponseController(writer).Hijack()
			if err != nil {
				http.Error(writer, err.Error(), http.StatusInternalServerError)
				return
			}
			_ = connection.Close()
			return
		}
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	writer.WriteHeader(http.StatusOK)
}

func (b *runtimeAdmissionBackend) request(id string) (runtimeAdmissionObservation, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	request, ok := b.requests[id]
	return request, ok
}

func (b *runtimeAdmissionBackend) receivedEnvoyID(id string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.envoyIDs[id]
}

func runtimeAdmissionRequest(t *testing.T, harness *runtimeLiveHarness, id, method, path string) int {
	t.Helper()
	request, err := http.NewRequest(method, "http://"+harness.address+path, strings.NewReader(runtimeAdmissionBody))
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "admission.runtime.test"
	request.Header.Set("X-Admission-Test-ID", id)
	response, err := harness.httpClient.Do(request)
	if err != nil {
		t.Fatalf("request %s: %v", id, err)
	}
	_, readErr := io.Copy(io.Discard, response.Body)
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil {
		t.Fatalf("read/close response %s: %v/%v", id, readErr, closeErr)
	}
	return response.StatusCode
}

func runtimeAdmissionAssertForwarded(t *testing.T, backend *runtimeAdmissionBackend, id, path string) {
	t.Helper()
	request, received := backend.request(id)
	if !received || request.method != http.MethodPost || request.path != path || request.body != runtimeAdmissionBody || request.envoyID == "" {
		t.Fatalf("backend request %s = %+v (received=%t), want POST %s with original body and request ID", id, request, received, path)
	}
}

func runtimeAdmissionAssertRejections(t *testing.T, harness *runtimeLiveHarness, backend *runtimeAdmissionBackend, want int) {
	t.Helper()
	runtimeLiveAwait(t, harness, "admission rejection access logs", time.Time{}, func() (bool, string) {
		var rejected int
		for line := range strings.SplitSeq(string(runtimeLiveOutput(t, "logs", harness.envoyName)), "\n") {
			var entry struct {
				Details   string `json:"response_code_details"`
				RequestID string `json:"request_id"`
			}
			if json.Unmarshal([]byte(line), &entry) != nil || entry.Details != "denied_by_admission_control" {
				continue
			}
			rejected++
			if entry.RequestID == "" || backend.receivedEnvoyID(entry.RequestID) {
				t.Fatalf("admission-rejected request %q reached the backend or has no request ID", entry.RequestID)
			}
		}
		return rejected == want, fmt.Sprintf("logged %d admission rejections, want %d", rejected, want)
	})
}
