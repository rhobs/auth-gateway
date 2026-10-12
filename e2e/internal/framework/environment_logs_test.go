//go:build e2e

package framework

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func TestContainerLogsReadsTheRequestedContainer(t *testing.T) {
	tests := []struct {
		name          string
		tailLines     int64
		wantTailLines string
	}{
		{name: "bounded tail", tailLines: 12, wantTailLines: "12"},
		{name: "all available lines"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var gotRequest *http.Request
			client, err := kubernetes.NewForConfig(&rest.Config{
				Host: "https://kubernetes.example",
				Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
					gotRequest = request
					return &http.Response{
						StatusCode: http.StatusOK,
						Header:     make(http.Header),
						Body:       io.NopCloser(strings.NewReader("structured log line\n")),
						Request:    request,
					}, nil
				}),
			})
			if err != nil {
				t.Fatalf("create Kubernetes client: %v", err)
			}
			env := &Environment{client: client}

			logs, err := env.ContainerLogs(context.Background(), "test", "gateway", "envoy", test.tailLines)
			if err != nil {
				t.Fatalf("read container logs: %v", err)
			}
			if string(logs) != "structured log line\n" {
				t.Fatalf("container logs = %q", logs)
			}
			if gotRequest == nil {
				t.Fatal("ContainerLogs did not request the Pod log subresource")
			}
			if gotRequest.Method != http.MethodGet {
				t.Errorf("request method = %s, want %s", gotRequest.Method, http.MethodGet)
			}
			if gotRequest.URL.Path != "/api/v1/namespaces/test/pods/gateway/log" {
				t.Errorf("request path = %s", gotRequest.URL.Path)
			}
			if got := gotRequest.URL.Query().Get("container"); got != "envoy" {
				t.Errorf("container query = %q, want %q", got, "envoy")
			}
			if got := gotRequest.URL.Query().Get("tailLines"); got != test.wantTailLines {
				t.Errorf("tailLines query = %q, want %q", got, test.wantTailLines)
			}
		})
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (roundTripper roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTripper(request)
}
