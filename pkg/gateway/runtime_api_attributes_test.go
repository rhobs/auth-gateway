//go:build envoyruntime

package gateway

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
)

func TestEnvoyForwardsFixedAuthenticatorAttributes(t *testing.T) {
	c := runtimeLiveConfig(t)
	c.APIs = c.APIs[:1]
	c.Servers = c.Servers[:1]
	c.Authenticators[0].Attributes = append(c.Authenticators[0].Attributes,
		gatewayapi.AttributeSource{Name: "auth_origin", FromSource: "fixed", Value: gatewayapi.AttributeValue{Text: "partner (100%)"}})
	c.APIs[0].Routes[0].Processing.RequestHeaders = append(c.APIs[0].Routes[0].Processing.RequestHeaders,
		gatewayapi.RequestHeaderMapping{Name: "X-Auth-Origin", FromAttribute: "auth_origin"})
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	configDir := runtimeDirectory(t)
	for _, file := range files.All() {
		runtimeLiveWriteGeneratedFile(t, configDir, file)
	}
	credentials, err := GenerateAPIKeyECDS(c.Authenticators[0], []gatewayapi.APIKeyCredential{{
		Key: "runtime-key", Attributes: map[string]string{"tenant_id": "client-a", "upstream_tenant": "team-a"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	runtimeLiveWriteGeneratedFile(t, configDir, GeneratedFile{Path: APIKeyECDSPath, Contents: credentials})
	harness := runtimeLiveStart(t, configDir, nil)
	runtimeLiveAwait(t, harness, "fixed authenticator attribute", time.Time{}, func() (bool, string) {
		response := harness.request(false, runtimeLiveKeyHost, "runtime-key", http.MethodPost, "/ingest", runtimeLiveBody)
		return runtimeLiveEchoMatches(response, http.StatusOK, "team-a", http.MethodPost, "/anything", runtimeLiveBody) &&
			runtimeLiveHeader(response.echo.Headers, "X-Auth-Origin") == "partner (100%)", response.describe()
	})
	denied := harness.request(false, runtimeLiveKeyHost, "invalid-key", http.MethodPost, "/ingest", runtimeLiveBody)
	if denied.err != nil || denied.status != http.StatusUnauthorized {
		t.Fatalf("invalid credential response = %s", denied.describe())
	}
}

func TestEnvoyForwardsFixedAPIAttributes(t *testing.T) {
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	backend := &httptest.Server{Listener: listener, Config: &http.Server{
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, r.Header.Get("X-Operation")) }),
		ReadHeaderTimeout: 5 * time.Second,
	}}
	backend.Start()
	t.Cleanup(backend.Close)

	c := loadConfigCase(t, "api-fixed-attributes")
	c.Kubernetes = nil
	c.APIs[0].Attributes[0].Value.Text = "health:read (100%)"
	for index := range c.APIs {
		c.APIs[index].Upstream.Address = "host.docker.internal"
		c.APIs[index].Upstream.Port = uint32(listener.Addr().(*net.TCPAddr).Port)
	}
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	configDir := runtimeDirectory(t)
	for _, file := range files.All() {
		runtimeLiveWriteGeneratedFile(t, configDir, file)
	}
	address, envoyName := runtimeLiveStartEnvoy(t, configDir,
		[]string{"--add-host", "host.docker.internal:host-gateway"}, nil)
	transport := &http.Transport{Proxy: nil}
	t.Cleanup(transport.CloseIdleConnections)
	harness := &runtimeLiveHarness{address: address, envoyName: envoyName,
		httpClient: &http.Client{Transport: transport, Timeout: 4 * time.Second}}

	for _, test := range []struct{ path, want string }{
		{"/metrics", "health:read (100%)"},
		{"/plain", ""},
	} {
		runtimeLiveAwait(t, harness, test.path, time.Time{}, func() (bool, string) {
			request, err := http.NewRequest(http.MethodGet, "http://"+address+test.path, nil)
			if err != nil {
				return false, err.Error()
			}
			request.Host = "gateway.example.test"
			response, err := harness.httpClient.Do(request)
			if err != nil {
				return false, err.Error()
			}
			body, readErr := io.ReadAll(response.Body)
			closeErr := response.Body.Close()
			if readErr != nil || closeErr != nil {
				return false, fmt.Sprintf("read/close: %v/%v", readErr, closeErr)
			}
			return response.StatusCode == http.StatusOK && string(body) == test.want,
				fmt.Sprintf("HTTP %d, X-Operation %q", response.StatusCode, body)
		})
	}
}
