//go:build envoyruntime

package config

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	runtimeLiveHTTPBinImage = "ghcr.io/mccutchen/go-httpbin:2.25.0"
	runtimeLiveBody         = "auth-gateway-runtime-request"
	runtimeLiveKeyHeader    = "X-Partner-Key"
	runtimeLiveKeyHost      = "key.runtime.test"
	runtimeLiveTLSHost      = "tls.runtime.test"
)

func TestEnvoyReloadsFileBasedResources(t *testing.T) {
	gatewayConfig := runtimeLiveConfig(t)
	initialFiles, err := Generate(gatewayConfig)
	if err != nil {
		t.Fatal(err)
	}
	if len(initialFiles.ServerCertificateResources) != 1 {
		t.Fatalf("generated runtime files = %#v, want one server SDS resource", initialFiles)
	}

	configDir := runtimeDirectory(t)
	if err := os.MkdirAll(filepath.Join(configDir, "api-keys"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, file := range initialFiles.All() {
		runtimeLiveWriteGeneratedFile(t, configDir, file)
	}

	certificates := runtimeLiveCertificates(t)
	rootCAs := x509.NewCertPool()
	for index, certificate := range certificates {
		rootCAs.AddCert(certificate.certificate)
		certPath, keyPath := runtimeLiveCertificatePaths(index + 1)
		runtimeLiveWriteGeneratedFile(t, configDir, GeneratedFile{Path: certPath, Contents: certificate.certificatePEM})
		runtimeLiveWriteGeneratedFile(t, configDir, GeneratedFile{Path: keyPath, Contents: certificate.privateKeyPEM})
	}

	initialKeys := []APIKeyCredential{{Key: "runtime-key-a", Attributes: map[string]string{"tenant_id": "client-a", "upstream_tenant": "team-a"}}}
	initialKeyFile, err := GenerateAPIKeyECDS(findAuthenticator(gatewayConfig, "partner-key"), initialKeys)
	if err != nil {
		t.Fatal(err)
	}
	runtimeLiveWriteGeneratedFile(t, configDir, GeneratedFile{Path: APIKeyECDSPath, Contents: initialKeyFile})

	harness := runtimeLiveStart(t, configDir, rootCAs)
	var initial runtimeLiveResponse
	runtimeLiveAwait(t, harness, "initial API-key request", time.Time{}, func() (bool, string) {
		initial = harness.request(false, runtimeLiveKeyHost, "runtime-key-a", http.MethodPost, "/ingest", runtimeLiveBody)
		return runtimeLiveEchoMatches(initial, http.StatusOK, "team-a", http.MethodPost, "/anything", runtimeLiveBody), initial.describe()
	})

	rotatedKeys := []APIKeyCredential{{Key: "runtime-key-b", Attributes: map[string]string{"tenant_id": "client-a", "upstream_tenant": "team-b"}}}
	rotatedKeyFile, err := GenerateAPIKeyECDS(findAuthenticator(gatewayConfig, "partner-key"), rotatedKeys)
	if err != nil {
		t.Fatal(err)
	}
	keyRotationAt := runtimeLiveAtomicReplace(t, harness, APIKeyECDSPath, rotatedKeyFile)
	runtimeLiveAwait(t, harness, "API-key ECDS rotation to runtime-key-b", keyRotationAt, func() (bool, string) {
		accepted := harness.request(false, runtimeLiveKeyHost, "runtime-key-b", http.MethodPost, "/ingest", runtimeLiveBody)
		stale := harness.request(false, runtimeLiveKeyHost, "runtime-key-a", http.MethodPost, "/ingest", runtimeLiveBody)
		acceptedOK := runtimeLiveEchoMatches(accepted, http.StatusOK, "team-b", http.MethodPost, "/anything", runtimeLiveBody)
		staleDenied := stale.status == http.StatusUnauthorized && stale.err == nil
		return acceptedOK && staleDenied, fmt.Sprintf("new key: %s; old key: %s", accepted.describe(), stale.describe())
	})

	emptyKeyFile, err := GenerateAPIKeyECDS(findAuthenticator(gatewayConfig, "partner-key"), nil)
	if err != nil {
		t.Fatal(err)
	}
	keyRevocationAt := runtimeLiveAtomicReplace(t, harness, APIKeyECDSPath, emptyKeyFile)
	runtimeLiveAwait(t, harness, "empty API-key ECDS revocation", keyRevocationAt, func() (bool, string) {
		revoked := harness.request(false, runtimeLiveKeyHost, "runtime-key-b", http.MethodPost, "/ingest", runtimeLiveBody)
		return revoked.status == http.StatusUnauthorized && revoked.err == nil, revoked.describe()
	})

	rotatedTLSFile, rotatedBootstrap, err := runtimeLiveTLSResource(gatewayConfig, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(initialFiles.EnvoyBootstrap.Contents, rotatedBootstrap) {
		t.Fatal("rotating the server SDS resource changed the Envoy bootstrap")
	}
	tlsRotationAt := runtimeLiveAtomicReplace(t, harness, rotatedTLSFile.Path, rotatedTLSFile.Contents)
	runtimeLiveAwait(t, harness, "server TLS SDS update to certificate 2", tlsRotationAt, func() (bool, string) {
		response := harness.request(true, runtimeLiveTLSHost, "", http.MethodGet, "/tls", "")
		return runtimeLiveTLSMatches(response, certificates[1].certificate.SerialNumber.Int64()), response.describe()
	})

}

func runtimeLiveConfig(t *testing.T) Config {
	t.Helper()
	certificatePath, keyPath := runtimeLiveCertificatePaths(1)
	input := fmt.Sprintf(`version: 1
authenticators:
  - name: partner-key
    api_key:
      secret: gateway-api-keys
      header: %s
    attributes:
      tenant_id: {credential: true}
      upstream_tenant: {credential: true}
authorization_policies:
  - name: key-writers
    grants:
      - authenticator: partner-key
        apis: [ingest]
        attributes:
          tenant_id: [client-a]
apis:
  - name: ingest
    upstream: {address: httpbin, port: 8080}
    routes:
      - methods: [POST]
        path: {exact: /ingest}
        rewrite: {path: /anything}
        processing:
          request_headers:
            - {name: X-Scope-OrgID, from_attribute: upstream_tenant}
  - name: tls-probe
    upstream: {address: httpbin, port: 8080}
    routes:
      - methods: [GET]
        path: {exact: /tls}
        rewrite: {path: /anything}
servers:
  - hostname: %s
    authentication: {any_of: [partner-key]}
    authorization: {any_of: [key-writers]}
    apis: [ingest]
  - hostname: %s
    tls_config:
      certificate: %s
      private_key: %s
    apis: [tls-probe]
`, runtimeLiveKeyHeader, runtimeLiveKeyHost, runtimeLiveTLSHost, certificatePath, keyPath)

	config, err := Load(strings.NewReader(input))
	if err != nil {
		t.Fatalf("load live runtime config: %v", err)
	}
	return config
}

func runtimeLiveStart(t *testing.T, configDir string, roots *x509.CertPool) *runtimeLiveHarness {
	t.Helper()
	nameSuffix := fmt.Sprintf("%d-%d", os.Getpid(), time.Now().UnixNano())
	networkName := "auth-gateway-runtime-" + nameSuffix
	httpbinName := "auth-gateway-httpbin-" + nameSuffix

	runtimeLiveDocker(t, "network", "create", networkName)
	t.Cleanup(func() { runtimeLiveDockerCleanup(t, "network", "rm", networkName) })
	runtimeLiveDocker(t, "run", "--detach", "--name", httpbinName, "--network", networkName, "--network-alias", "httpbin", runtimeLiveHTTPBinImage)
	t.Cleanup(func() { runtimeLiveDockerCleanup(t, "rm", "--force", httpbinName) })

	address, envoyName := runtimeLiveStartEnvoy(t, configDir, []string{"--network", networkName}, nil)
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	tlsTransport := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: &tls.Config{
		RootCAs: roots, ServerName: runtimeLiveTLSHost, MinVersion: tls.VersionTLS12,
	}}
	return &runtimeLiveHarness{
		address:    address,
		envoyName:  envoyName,
		httpClient: &http.Client{Transport: transport, Timeout: 4 * time.Second},
		tlsClient:  &http.Client{Transport: tlsTransport, Timeout: 4 * time.Second},
	}
}

func runtimeLiveStartEnvoy(t *testing.T, configDir string, dockerArgs, envoyArgs []string) (string, string) {
	t.Helper()
	envoyName := fmt.Sprintf("auth-gateway-envoy-%d-%d", os.Getpid(), time.Now().UnixNano())
	image := os.Getenv("AUTH_GATEWAY_RUNTIME_IMAGE")
	if image == "" {
		image = DefaultEnvoyImage
	}
	args := []string{"run", "--detach", "--user", "101:101", "--name", envoyName,
		"--publish", "127.0.0.1::8080/tcp", "--volume", configDir + ":" + EnvoyConfigDirectory}
	args = append(args, dockerArgs...)
	args = append(args, image, "--log-level", "info", "-c", EnvoyBootstrapPath)
	args = append(args, envoyArgs...)
	runtimeLiveDocker(t, args...)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("Envoy logs:\n%s", runtimeLiveLogs(envoyName))
		}
		runtimeLiveDockerCleanup(t, "rm", "--force", envoyName)
	})

	portOutput := runtimeLiveOutput(t, "port", envoyName, "8080/tcp")
	_, port, err := net.SplitHostPort(strings.TrimSpace(string(portOutput)))
	if err != nil {
		t.Fatalf("parse Envoy published port %q: %v", portOutput, err)
	}
	return net.JoinHostPort("127.0.0.1", port), envoyName
}

func runtimeLiveDocker(t *testing.T, args ...string) {
	t.Helper()
	output, err := runtimeLiveCommand(3*time.Minute, "docker", args...)
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, output)
	}
}

func runtimeLiveOutput(t *testing.T, args ...string) []byte {
	t.Helper()
	output, err := runtimeLiveCommand(20*time.Second, "docker", args...)
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, output)
	}
	return output
}

func runtimeLiveCommand(timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func runtimeLiveDockerCleanup(t *testing.T, args ...string) {
	t.Helper()
	output, err := runtimeLiveCommand(20*time.Second, "docker", args...)
	if err != nil && !strings.Contains(string(output), "No such") {
		t.Errorf("docker cleanup %s: %v\n%s", strings.Join(args, " "), err, output)
	}
}

func runtimeLiveWriteGeneratedFile(t *testing.T, configDir string, file GeneratedFile) {
	t.Helper()
	filename := runtimeLiveHostPath(t, configDir, file.Path)
	if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
		t.Fatal(err)
	}
	runtimeWrite(t, filename, file.Contents)
}

func runtimeLiveHostPath(t *testing.T, configDir, envoyPath string) string {
	t.Helper()
	relative := runtimeLiveRelativePath(t, envoyPath)
	return filepath.Join(configDir, relative)
}

func runtimeLiveContainerPath(t *testing.T, envoyPath string) string {
	t.Helper()
	return path.Join(EnvoyConfigDirectory, filepath.ToSlash(runtimeLiveRelativePath(t, envoyPath)))
}

func runtimeLiveRelativePath(t *testing.T, envoyPath string) string {
	t.Helper()
	relative, err := filepath.Rel(EnvoyConfigDirectory, filepath.FromSlash(envoyPath))
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		t.Fatalf("generated path %q is outside %q", envoyPath, EnvoyConfigDirectory)
	}
	return relative
}

func runtimeLiveAtomicReplace(t *testing.T, harness *runtimeLiveHarness, envoyPath string, contents []byte) time.Time {
	t.Helper()
	temporary, err := os.CreateTemp("", "auth-gateway-runtime-update-")
	if err != nil {
		t.Fatal(err)
	}
	temporaryName := temporary.Name()
	defer func() {
		if err := os.Remove(temporaryName); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Errorf("remove temporary update file %q: %v", temporaryName, err)
		}
	}()
	closeAfterFailure := func() {
		if err := temporary.Close(); err != nil {
			t.Errorf("close temporary update file %q: %v", temporaryName, err)
		}
	}
	if err := temporary.Chmod(0o644); err != nil {
		closeAfterFailure()
		t.Fatal(err)
	}
	if _, err := temporary.Write(contents); err != nil {
		closeAfterFailure()
		t.Fatal(err)
	}
	if err := temporary.Sync(); err != nil {
		closeAfterFailure()
		t.Fatal(err)
	}
	if err := temporary.Close(); err != nil {
		t.Fatal(err)
	}
	containerPath := runtimeLiveContainerPath(t, envoyPath)
	containerTemporary := path.Join(path.Dir(containerPath), "."+filepath.Base(temporaryName))
	runtimeLiveDocker(t, "cp", temporaryName, harness.envoyName+":"+containerTemporary)
	runtimeLiveDocker(t, "exec", "--user", "0:0", harness.envoyName, "mv", "-f", containerTemporary, containerPath)
	return time.Now()
}

func runtimeLiveTLSResource(base Config, certificateNumber int) (GeneratedFile, []byte, error) {
	config := base.clone()
	config.Servers[1].TLSConfig.Certificate, config.Servers[1].TLSConfig.PrivateKey = runtimeLiveCertificatePaths(certificateNumber)
	files, err := Generate(config)
	if err != nil {
		return GeneratedFile{}, nil, err
	}
	if len(files.ServerCertificateResources) != 1 {
		return GeneratedFile{}, nil, fmt.Errorf("generated %d TLS SDS resources, want one", len(files.ServerCertificateResources))
	}
	return files.ServerCertificateResources[0], files.EnvoyBootstrap.Contents, nil
}

func runtimeLiveCertificatePaths(number int) (string, string) {
	base := fmt.Sprintf("/etc/auth-gateway/runtime-certs/server-%d", number)
	return base + ".crt", base + ".key"
}

func runtimeLiveCertificates(t *testing.T) []runtimeLiveCertificate {
	t.Helper()
	certificates := make([]runtimeLiveCertificate, 2)
	for index := range certificates {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{
			SerialNumber:          big.NewInt(int64(index + 101)),
			Subject:               pkix.Name{CommonName: runtimeLiveTLSHost},
			DNSNames:              []string{runtimeLiveTLSHost},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		privateKey, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		certificates[index] = runtimeLiveCertificate{
			certificate:    certificate,
			certificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
			privateKeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKey}),
		}
	}
	return certificates
}

type runtimeLiveCertificate struct {
	certificate    *x509.Certificate
	certificatePEM []byte
	privateKeyPEM  []byte
}

type runtimeLiveHarness struct {
	address    string
	envoyName  string
	httpClient *http.Client
	tlsClient  *http.Client
}

type runtimeLiveResponse struct {
	status      int
	err         error
	echo        runtimeLiveEcho
	peerSerial  int64
	hasPeerCert bool
	rawResponse []byte
}

type runtimeLiveEcho struct {
	Method  string              `json:"method"`
	URL     string              `json:"url"`
	Data    string              `json:"data"`
	Headers map[string][]string `json:"headers"`
}

func (h *runtimeLiveHarness) request(secure bool, host, apiKey, method, path, body string) (result runtimeLiveResponse) {
	scheme := "http"
	client := h.httpClient
	if secure {
		scheme = "https"
		client = h.tlsClient
	}
	request, err := http.NewRequest(method, scheme+"://"+h.address+path, strings.NewReader(body))
	if err != nil {
		return runtimeLiveResponse{err: err}
	}
	request.Host = host
	if body != "" {
		request.Header.Set("Content-Type", "text/plain")
	}
	if apiKey != "" {
		request.Header.Set(runtimeLiveKeyHeader, apiKey)
	}
	if method == http.MethodPost {
		request.Header.Set("X-Scope-OrgID", "caller-controlled")
	}
	response, err := client.Do(request)
	if err != nil {
		return runtimeLiveResponse{err: err}
	}
	result = runtimeLiveResponse{status: response.StatusCode}
	defer func() {
		if err := response.Body.Close(); err != nil && result.err == nil {
			result.err = fmt.Errorf("close response body: %w", err)
		}
	}()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		result.err = err
		return result
	}
	result.rawResponse = data
	if response.TLS != nil && len(response.TLS.PeerCertificates) > 0 {
		result.peerSerial = response.TLS.PeerCertificates[0].SerialNumber.Int64()
		result.hasPeerCert = true
	}
	if response.StatusCode == http.StatusOK {
		if err := json.Unmarshal(data, &result.echo); err != nil {
			result.err = fmt.Errorf("decode httpbin response: %w", err)
		}
	}
	return result
}

func (response runtimeLiveResponse) describe() string {
	if response.err != nil {
		return fmt.Sprintf("HTTP %d, error %v, body %q", response.status, response.err, response.rawResponse)
	}
	if response.status != http.StatusOK {
		return fmt.Sprintf("HTTP %d, body %q", response.status, response.rawResponse)
	}
	return fmt.Sprintf("HTTP %d, method %q, URL %q, data %q, X-Scope-OrgID %q, peer certificate serial %d",
		response.status, response.echo.Method, response.echo.URL, response.echo.Data,
		runtimeLiveHeader(response.echo.Headers, "X-Scope-OrgID"), response.peerSerial)
}

func runtimeLiveHeader(headers map[string][]string, name string) string {
	for header, values := range headers {
		if strings.EqualFold(header, name) && len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

func runtimeLiveEchoMatches(response runtimeLiveResponse, status int, tenant, method, path, body string) bool {
	if response.err != nil || response.status != status {
		return false
	}
	parsedURL, err := url.Parse(response.echo.URL)
	return err == nil && response.echo.Method == method && parsedURL.Path == path && response.echo.Data == body &&
		runtimeLiveHeader(response.echo.Headers, "X-Scope-OrgID") == tenant
}

func runtimeLiveTLSMatches(response runtimeLiveResponse, serial int64) bool {
	if !runtimeLiveEchoMatches(response, http.StatusOK, "", http.MethodGet, "/anything", "") {
		return false
	}
	return response.hasPeerCert && response.peerSerial == serial
}

func runtimeLiveAwait(t *testing.T, harness *runtimeLiveHarness, label string, updatedAt time.Time, check func() (bool, string)) {
	t.Helper()
	startedAt := time.Now()
	deadline := time.Now().Add(30 * time.Second)
	var last string
	for {
		observed, detail := check()
		last = detail
		if observed {
			if updatedAt.IsZero() {
				t.Logf("%s became ready after %s", label, time.Since(startedAt).Round(time.Millisecond))
			} else {
				t.Logf("%s observed %s after atomic replacement", label, time.Since(updatedAt).Round(time.Millisecond))
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s was not observed after 30s: %s\nEnvoy logs:\n%s", label, last, runtimeLiveLogs(harness.envoyName))
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func runtimeLiveLogs(container string) string {
	output, err := runtimeLiveCommand(10*time.Second, "docker", "logs", "--tail", "80", container)
	if err != nil {
		return fmt.Sprintf("read logs: %v\n%s", err, output)
	}
	return string(output)
}
