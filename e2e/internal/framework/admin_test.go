//go:build e2e

package framework

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type adminRoundTripperFunc func(*http.Request) (*http.Response, error)

func (f adminRoundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func setDefaultHTTPClient(t *testing.T, client *http.Client) {
	t.Helper()
	previous := http.DefaultClient
	http.DefaultClient = client
	t.Cleanup(func() { http.DefaultClient = previous })
}

func TestEnvoyAdminGetRequestsTheGivenPath(t *testing.T) {
	var observed *http.Request
	setDefaultHTTPClient(t, &http.Client{Transport: adminRoundTripperFunc(func(request *http.Request) (*http.Response, error) {
		observed = request
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("cluster.test.upstream_rq_total: 3\n")),
			Request:    request,
		}, nil
	})})

	env := &Environment{}
	got, err := env.EnvoyAdminGet(context.Background(), "127.0.0.1:9901", "/stats?filter=cluster.test")
	if err != nil {
		t.Fatalf("EnvoyAdminGet() error = %v", err)
	}
	if observed == nil || observed.Method != http.MethodGet || observed.URL.Host != "127.0.0.1:9901" ||
		observed.URL.Path != "/stats" || observed.URL.Query().Get("filter") != "cluster.test" {
		t.Fatalf("Envoy admin request = %v, want GET /stats?filter=cluster.test", observed)
	}
	if want := "cluster.test.upstream_rq_total: 3\n"; string(got) != want {
		t.Fatalf("EnvoyAdminGet() body = %q, want %q", got, want)
	}
}

func TestEnvoyAdminGetReportsNonSuccessfulStatus(t *testing.T) {
	setDefaultHTTPClient(t, &http.Client{Transport: adminRoundTripperFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusServiceUnavailable,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("admin unavailable\n")),
			Request:    request,
		}, nil
	})})

	env := &Environment{}
	_, err := env.EnvoyAdminGet(context.Background(), "127.0.0.1:9901", "/stats")
	if err == nil || !strings.Contains(err.Error(), "HTTP 503: admin unavailable\n") {
		t.Fatalf("EnvoyAdminGet() error = %v, want HTTP 503 body", err)
	}
}
