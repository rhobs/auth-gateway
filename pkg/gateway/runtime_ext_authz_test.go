//go:build envoyruntime

package gateway

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

type runtimeBridgePolicy struct {
	authv3.UnimplementedAuthorizationServer
	requests chan *authv3.CheckRequest
}

func (p *runtimeBridgePolicy) Check(ctx context.Context, request *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	select {
	case p.requests <- request:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return &authv3.CheckResponse{Status: status.New(codes.OK, "").Proto(),
		HttpResponse: &authv3.CheckResponse_OkResponse{OkResponse: &authv3.OkHttpResponse{}}}, nil
}

func TestEnvoyExternalAuthorizationBridgeUsesRouteContext(t *testing.T) {
	backendListener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	backend := &httptest.Server{Listener: backendListener, Config: &http.Server{
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }),
		ReadHeaderTimeout: 5 * time.Second,
	}}
	backend.Start()
	t.Cleanup(backend.Close)

	certificate, key := runtimeCertificate(t)
	pair, err := tls.X509KeyPair(certificate, key)
	if err != nil {
		t.Fatal(err)
	}
	policyListener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	policy := &runtimeBridgePolicy{requests: make(chan *authv3.CheckRequest, 1)}
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12})))
	authv3.RegisterAuthorizationServer(server, policy)
	t.Cleanup(server.Stop)
	go func() { _ = server.Serve(policyListener) }()

	c := loadConfigCase(t, "ext-authz")
	service := c.ExtAuthzServices[0]
	service.Upstream.Address = "host.docker.internal"
	service.Upstream.Port = uint32(policyListener.Addr().(*net.TCPAddr).Port)
	service.Upstream.TLSConfig = &gatewayapi.UpstreamTLS{ServerName: "gateway.example.test", TrustedCA: &gatewayapi.TrustedCA{Filename: EnvoyConfigDirectory + "/policy-ca.pem"}}
	service.RequestHeaders = []string{"x-shared", "x-one", "x-two", "x-missing", "x-empty"}
	service.CredentialHeaders = nil
	c.Kubernetes, c.Authenticators, c.ExtAuthzServices, c.APIs = nil, nil, nil, nil
	c.Servers = []gatewayapi.Server{{Hostname: "gateway.example.test"}}
	for _, test := range []struct {
		name       string
		attributes []gatewayapi.AttributeSource
		fixed      []gatewayapi.AttributeSource
	}{
		{"one", []gatewayapi.AttributeSource{
			testTextAttribute("shared", "header", "X-Shared"),
			testTextAttribute("one_only", "header", "X-One"),
			testTextAttribute("missing", "header", "X-Missing"),
			testTextAttribute("empty", "header", "X-Empty"),
		}, []gatewayapi.AttributeSource{testTextAttribute("role", "fixed", "metrics:read (100%)")}},
		{"two", []gatewayapi.AttributeSource{
			testTextAttribute("shared", "header", "X-Shared"),
			testTextAttribute("two_only", "header", "X-Two"),
		}, nil},
		{"empty", nil, nil},
		{"public", nil, nil},
	} {
		c.APIs = append(c.APIs, gatewayapi.API{Name: test.name, Attributes: test.fixed,
			Upstream: gatewayapi.Upstream{Address: "host.docker.internal", Port: uint32(backendListener.Addr().(*net.TCPAddr).Port)},
			Routes:   []gatewayapi.Route{{Methods: []string{http.MethodGet}, Path: gatewayapi.PathMatch{Expression: "equals", Value: &gatewayapi.MatchValue{Text: "/" + test.name}}}},
		})
		binding := gatewayapi.APIBinding{Name: test.name, Public: test.name == "public"}
		if !binding.Public {
			selected := service
			selected.Name, selected.Attributes = test.name, test.attributes
			c.ExtAuthzServices = append(c.ExtAuthzServices, selected)
			binding.Access = []gatewayapi.Access{{Name: "default", Authorization: gatewayapi.Authorization{
				ExtAuthz: &gatewayapi.ExternalAuthorization{Service: test.name},
			}}}
		}
		c.Servers[0].APIs = append(c.Servers[0].APIs, binding)
	}
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	configDir := runtimeDirectory(t)
	for _, file := range files.All() {
		runtimeLiveWriteGeneratedFile(t, configDir, file)
	}
	runtimeWrite(t, filepath.Join(configDir, "policy-ca.pem"), certificate)
	address, envoyName := runtimeLiveStartEnvoy(t, configDir,
		[]string{"--add-host", "host.docker.internal:host-gateway"}, []string{"--concurrency", "1"})
	transport := &http.Transport{Proxy: nil}
	t.Cleanup(transport.CloseIdleConnections)
	harness := &runtimeLiveHarness{address: address, envoyName: envoyName,
		httpClient: &http.Client{Transport: transport, Timeout: 4 * time.Second}}
	send := func(path string) (int, string) {
		request, err := http.NewRequest(http.MethodGet, "http://"+address+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Host = "gateway.example.test"
		request.Header = http.Header{"X-Shared": {"shared-value"}, "X-One": {"first"}, "X-Two": {"second"}, "X-Empty": {""}}
		response, err := harness.httpClient.Do(request)
		if err != nil {
			return 0, err.Error()
		}
		body, readErr := io.ReadAll(response.Body)
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil {
			t.Fatalf("read/close response: %v/%v", readErr, closeErr)
		}
		return response.StatusCode, string(body)
	}
	runtimeLiveAwait(t, harness, "public route without bridge context", time.Time{}, func() (bool, string) {
		code, body := send("/public")
		return code == http.StatusOK && body == "ok", fmt.Sprintf("HTTP %d: %s", code, body)
	})
	for _, test := range []struct {
		path string
		want map[string]string
	}{
		{"/one", map[string]string{"shared": "shared-value", "one_only": "first", "role": "metrics:read (100%)"}},
		{"/two", map[string]string{"shared": "shared-value", "two_only": "second"}},
		{"/empty", map[string]string{}},
		{"/one", map[string]string{"shared": "shared-value", "one_only": "first", "role": "metrics:read (100%)"}},
	} {
		if code, body := send(test.path); code != http.StatusOK || body != "ok" {
			t.Fatalf("%s: HTTP %d: %s", test.path, code, body)
		}
		select {
		case check := <-policy.requests:
			if got := check.GetAttributes().GetRequest().GetHttp().GetPath(); got != test.path {
				t.Fatalf("Check path = %q, want %q", got, test.path)
			}
			got := make(map[string]string)
			for name, value := range check.GetAttributes().GetMetadataContext().GetFilterMetadata()[extAuthzInputMetadataName].GetFields() {
				got[name] = value.GetStringValue()
			}
			assertConfigDiff(t, test.path+" Check attributes", test.want, got)
		case <-time.After(time.Second):
			t.Fatalf("%s did not send an external Check request", test.path)
		}
	}
	if logs := runtimeLiveLogs(envoyName); strings.Contains(logs, "[error][lua]") {
		t.Fatalf("Lua bridge reported an error:\n%s", logs)
	}
}
