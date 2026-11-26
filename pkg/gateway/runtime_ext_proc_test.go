//go:build envoyruntime

package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	envoytype "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type runtimeProcessor struct {
	extprocv3.UnimplementedExternalProcessorServer
	mu       sync.Mutex
	requests []*extprocv3.ProcessingRequest
}

func (p *runtimeProcessor) Process(stream extprocv3.ExternalProcessor_ProcessServer) error {
	var action string
	for {
		request, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		p.mu.Lock()
		p.requests = append(p.requests, request)
		p.mu.Unlock()
		response := &extprocv3.ProcessingResponse{}
		switch {
		case request.GetRequestHeaders() != nil:
			headers := make(map[string]string)
			for _, h := range request.GetRequestHeaders().GetHeaders().GetHeaders() {
				headers[h.Key] = string(h.RawValue)
			}
			action = headers["x-test-action"]
			if action == "error" {
				return status.Error(codes.Unavailable, "test failure")
			}
			if action == "reject" {
				response.Response = &extprocv3.ProcessingResponse_ImmediateResponse{ImmediateResponse: &extprocv3.ImmediateResponse{Status: &envoytype.HttpStatus{Code: envoytype.StatusCode_Forbidden}, Body: []byte("processor rejection")}}
			} else {
				common := &extprocv3.CommonResponse{}
				if action == "transform" || action == "path" || strings.HasPrefix(action, "mutate:") {
					name, value := "x-processed", "yes"
					if action == "path" {
						name, value = ":path", "/target?processed=yes"
						common.ClearRouteCache = true
					}
					if strings.HasPrefix(action, "mutate:") {
						name = strings.TrimPrefix(action, "mutate:")
					}
					common.HeaderMutation = &extprocv3.HeaderMutation{SetHeaders: []*core.HeaderValueOption{{Header: &core.HeaderValue{Key: name, RawValue: []byte(value)}}}}
				}
				if action == "resize" {
					common.HeaderMutation = &extprocv3.HeaderMutation{RemoveHeaders: []string{"content-length"}}
				}
				response.Response = &extprocv3.ProcessingResponse_RequestHeaders{RequestHeaders: &extprocv3.HeadersResponse{Response: common}}
			}
		case request.GetRequestBody() != nil:
			body := bytes.ToUpper(request.GetRequestBody().Body)
			if action == "resize" {
				body = append(body, '!')
			}
			response.Response = &extprocv3.ProcessingResponse_RequestBody{RequestBody: &extprocv3.BodyResponse{Response: &extprocv3.CommonResponse{BodyMutation: &extprocv3.BodyMutation{Mutation: &extprocv3.BodyMutation_Body{Body: body}}}}}
		case request.GetRequestTrailers() != nil:
			response.Response = &extprocv3.ProcessingResponse_RequestTrailers{RequestTrailers: &extprocv3.TrailersResponse{}}
		default:
			return status.Error(codes.InvalidArgument, "unexpected response processing")
		}
		if err := stream.Send(response); err != nil {
			return err
		}
	}
}

func (p *runtimeProcessor) snapshot() []*extprocv3.ProcessingRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]*extprocv3.ProcessingRequest(nil), p.requests...)
}

func TestEnvoyExternalProcessing(t *testing.T) {
	var backendRequests atomic.Int64
	backendListener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	backend := &httptest.Server{Listener: backendListener, Config: &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendRequests.Add(1)
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"path": r.URL.RequestURI(), "method": r.Method, "headers": r.Header, "body": string(body)})
	})}}
	backend.Start()
	t.Cleanup(backend.Close)
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	processor := &runtimeProcessor{}
	server := grpc.NewServer()
	extprocv3.RegisterExternalProcessorServer(server, processor)
	t.Cleanup(server.Stop)
	go func() { _ = server.Serve(listener) }()

	c := loadConfigCase(t, "ext-proc")
	c.Kubernetes = nil
	c.Listener.PerConnectionBufferLimitBytes = new(uint32(1024))
	c.Authenticators = c.Authenticators[1:]
	c.Servers[0].APIs[0].Access = c.Servers[0].APIs[0].Access[1:]
	c.APIs[0].Routes[0].Processing.ExtProc.RequestBodyBufferLimitBytes = new(uint64(8192))
	for i := range c.APIs {
		c.APIs[i].Upstream = gatewayapi.Upstream{Address: "host.docker.internal", Port: uint32(backendListener.Addr().(*net.TCPAddr).Port)}
	}
	for i := range c.ExtProcServices {
		c.ExtProcServices[i].Upstream = gatewayapi.Upstream{Address: "host.docker.internal", Port: uint32(listener.Addr().(*net.TCPAddr).Port), HTTPProtocol: "http2"}
		c.ExtProcServices[i].MessageTimeout = duration(2 * time.Second)
	}
	// A different route must remain unreachable after a processor changes :path.
	c.APIs = append(c.APIs, gatewayapi.API{Name: "other", Upstream: gatewayapi.Upstream{Address: "127.0.0.1", Port: 1}, Routes: []gatewayapi.Route{{Methods: []string{"POST"}, Path: gatewayapi.PathMatch{Expression: "equals", Value: &gatewayapi.MatchValue{Text: "/target"}}}}})
	c.Servers[0].APIs = append(c.Servers[0].APIs, gatewayapi.APIBinding{Name: "other", Public: true})
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	configDir := runtimeDirectory(t)
	for _, file := range files.All() {
		runtimeLiveWriteGeneratedFile(t, configDir, file)
	}
	credentials, err := GenerateAPIKeyECDS(c.Authenticators[0], []gatewayapi.APIKeyCredential{{Key: "runtime-process-key", Attributes: map[string]string{"client_id": "client-a"}}})
	if err != nil {
		t.Fatal(err)
	}
	runtimeLiveWriteGeneratedFile(t, configDir, GeneratedFile{Path: APIKeyECDSPath, Contents: credentials})
	address, envoyName := runtimeLiveStartEnvoy(t, configDir, []string{"--add-host", "host.docker.internal:host-gateway"}, []string{"--concurrency", "1"})
	transport := &http.Transport{Proxy: nil}
	t.Cleanup(transport.CloseIdleConnections)
	harness := &runtimeLiveHarness{address: address, envoyName: envoyName, httpClient: &http.Client{Transport: transport, Timeout: 5 * time.Second}}
	send := func(method, path, body, action, key string) (int, []byte) {
		request, err := http.NewRequest(method, "http://"+address+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Host = "processor.example.test"
		request.Header = http.Header{"X-Auth": {"key"}, "X-Api-Key": {key}, "X-Test-Action": {action}, "X-Subject": {"spoofed"}}
		response, err := harness.httpClient.Do(request)
		if err != nil {
			return 0, []byte(err.Error())
		}
		defer func() { _ = response.Body.Close() }()
		data, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, data
	}
	runtimeLiveAwait(t, harness, "unprocessed readiness", time.Time{}, func() (bool, string) {
		code, body := send("GET", "/unprocessed", "", "", "runtime-process-key")
		return code == 200, fmt.Sprintf("HTTP %d: %s", code, body)
	})
	for _, test := range []struct{ path, body, action, wantBody, wantPath string }{
		{"/buffered", "hello processor", "transform", "HELLO PROCESSOR", "/buffered"},
		{"/buffered", strings.Repeat("wide ", 600), "transform", strings.Repeat("WIDE ", 600), "/buffered"},
		{"/buffered", "hello", "resize", "HELLO!", "/buffered"},
		{"/streamed", strings.Repeat("stream ", 12000), "transform", strings.Repeat("STREAM ", 12000), "/streamed"},
		{"/buffered", "original", "path", "ORIGINAL", "/target?processed=yes"},
		{"/headers", "", "", "", "/headers"},
		{"/public", "", "", "", "/public"},
	} {
		t.Run(test.path+"/"+test.action, func(t *testing.T) {
			method := "GET"
			if test.body != "" {
				method = "POST"
			}
			before := len(processor.snapshot())
			code, data := send(method, test.path, test.body, test.action, "runtime-process-key")
			if code != 200 {
				t.Fatalf("HTTP %d: %s", code, data)
			}
			var echo struct {
				Path, Method, Body string
				Headers            http.Header
			}
			if err := json.Unmarshal(data, &echo); err != nil {
				t.Fatal(err)
			}
			if echo.Body != test.wantBody || echo.Path != test.wantPath || echo.Method != method || echo.Headers.Get("Authorization") != "" || echo.Headers.Get("X-Api-Key") != "" {
				t.Fatalf("unexpected upstream request: path=%s method=%s headers=%v body length=%d", echo.Path, echo.Method, echo.Headers, len(echo.Body))
			}
			if test.action == "transform" && echo.Headers.Get("X-Processed") != "yes" {
				t.Fatal("header mutation did not reach upstream")
			}
			seen := processor.snapshot()[before:]
			if len(seen) == 0 || seen[0].GetRequestHeaders() == nil {
				t.Fatal("processor did not receive headers")
			}
			headers := seen[0].GetRequestHeaders().GetHeaders().GetHeaders()
			for _, h := range headers {
				if h.Key == "authorization" || h.Key == "x-api-key" {
					t.Fatal("processor received credential")
				}
				if test.path == "/buffered" && h.Key == "x-subject" && string(h.RawValue) != "client-a" {
					t.Fatal("processor did not see managed header")
				}
			}
			values := seen[0].GetMetadataContext().GetFilterMetadata()[extProcInputMetadataName].AsMap()
			want := map[string]any{"subject": "client-a", "role": "metrics:read (100%)"}
			if test.path == "/public" {
				want = map[string]any{"audience": "public"}
			}
			assertConfigDiff(t, "processor attributes", want, values)
			if test.action != "" && len(seen[0].GetAttributes()) == 0 {
				t.Fatal("native request properties missing")
			}
			if test.body == "" && len(seen) != 1 {
				t.Fatal("headers-only processing sent additional stages")
			}
		})
	}
	for _, test := range []struct {
		method, path, action, key string
		status                    int
		reachesBackend            bool
	}{
		{"GET", "/headers", "reject", "runtime-process-key", 403, false},
		{"GET", "/headers", "error", "runtime-process-key", 200, true},
		{"POST", "/buffered", "reject", "runtime-process-key", 403, false},
		{"POST", "/buffered", "error", "runtime-process-key", 500, false},
		{"POST", "/buffered", "mutate:authorization", "runtime-process-key", 500, false},
		{"POST", "/buffered", "mutate:x-subject", "runtime-process-key", 500, false},
		{"POST", "/buffered", "mutate:x-envoy-retry-on", "runtime-process-key", 500, false},
		{"POST", "/buffered", "", "invalid", 401, false},
		{"GET", "/missing", "", "runtime-process-key", 404, false},
		{"GET", "/buffered", "", "runtime-process-key", 405, false},
	} {
		t.Run(test.path+"/"+test.action+"/"+test.key, func(t *testing.T) {
			before := backendRequests.Load()
			code, body := send(test.method, test.path, "", test.action, test.key)
			if code != test.status {
				t.Fatalf("HTTP %d: %s, want %d", code, body, test.status)
			}
			delta := backendRequests.Load() - before
			if (delta != 0) != test.reachesBackend {
				t.Fatalf("unexpected backend request delta: %d", delta)
			}
		})
	}
	before := len(processor.snapshot())
	for _, path := range []string{"/unprocessed", "/missing"} {
		_, _ = send("GET", path, "", "", "runtime-process-key")
	}
	if len(processor.snapshot()) != before {
		t.Fatal("unattached or local response route invoked processor")
	}
	if code, body := send("POST", "/buffered", strings.Repeat("x", 128*1024), "", "runtime-process-key"); code != 413 {
		t.Fatalf("oversized buffered request: HTTP %d, response bytes %d", code, len(body))
	}
}
