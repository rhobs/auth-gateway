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
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
)

const (
	runtimeLiveHTTPBinImage = "ghcr.io/mccutchen/go-httpbin:2.25.0"
	runtimeLiveBody         = "auth-gateway-runtime-request"
	runtimeLiveKeyHeader    = "X-Partner-Key"
	runtimeLiveKeyHost      = "key.runtime.test"
	runtimeLiveTLSHost      = "tls.runtime.test"
	runtimeLiveBadResource  = "resources: [\n"
)

func TestEnvoyReloadsFileBasedResources(t *testing.T) {
	gatewayConfig := runtimeLiveConfig(t)
	initialFiles, err := Generate(gatewayConfig)
	if err != nil {
		t.Fatal(err)
	}
	if initialFiles.ProcessingConfig == nil || len(initialFiles.ServerCertificateResources) != 1 {
		t.Fatalf("generated runtime files = %#v, want processing and one server SDS resource", initialFiles)
	}

	configDir := runtimeDirectory(t)
	if err := os.MkdirAll(filepath.Join(configDir, "api-keys"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, file := range initialFiles.All() {
		if file.Path == EnvoyBootstrapPath {
			file.Contents = runtimeLiveBootstrapWithOpenAdmin(t, file.Contents)
		}
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

	initialKeys := []APIKeyCredential{{Key: "runtime-key-a", Attributes: map[string]string{"tenant_id": "client-a"}}}
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

	updatedProcessing := gatewayConfig.clone()
	updatedProcessing.Processing[0].Attributes["tenant_id"].Mappings["client-a"] = "team-b"
	processingFiles, err := Generate(updatedProcessing)
	if err != nil {
		t.Fatal(err)
	}
	if processingFiles.ProcessingConfig == nil {
		t.Fatal("updated processing configuration has no generated ECDS resource")
	}
	updatedAt := runtimeLiveAtomicReplace(t, harness, ProcessingConfigPath, processingFiles.ProcessingConfig.Contents)
	var mapped runtimeLiveResponse
	runtimeLiveAwait(t, harness, "processing ECDS update to team-b", updatedAt, func() (bool, string) {
		mapped = harness.request(false, runtimeLiveKeyHost, "runtime-key-a", http.MethodPost, "/ingest", runtimeLiveBody)
		return runtimeLiveEchoMatches(mapped, http.StatusOK, "team-b", http.MethodPost, "/anything", runtimeLiveBody), mapped.describe()
	})

	processingFailures, err := harness.updateFailures()
	if err != nil {
		t.Fatal(err)
	}
	badProcessingAt := runtimeLiveAtomicReplace(t, harness, ProcessingConfigPath, []byte(runtimeLiveBadResource))
	runtimeLiveAssertRetained(t, harness, "malformed processing ECDS update", badProcessingAt, processingFailures, func() (bool, string) {
		response := harness.request(false, runtimeLiveKeyHost, "runtime-key-a", http.MethodPost, "/ingest", runtimeLiveBody)
		return runtimeLiveEchoMatches(response, http.StatusOK, "team-b", http.MethodPost, "/anything", runtimeLiveBody), response.describe()
	})

	recoveredProcessing := gatewayConfig.clone()
	recoveredProcessing.Processing[0].Attributes["tenant_id"].Mappings["client-a"] = "team-c"
	recoveredFiles, err := Generate(recoveredProcessing)
	if err != nil {
		t.Fatal(err)
	}
	recoveryAt := runtimeLiveAtomicReplace(t, harness, ProcessingConfigPath, recoveredFiles.ProcessingConfig.Contents)
	var recovered runtimeLiveResponse
	runtimeLiveAwait(t, harness, "processing ECDS recovery to team-c", recoveryAt, func() (bool, string) {
		recovered = harness.request(false, runtimeLiveKeyHost, "runtime-key-a", http.MethodPost, "/ingest", runtimeLiveBody)
		return runtimeLiveEchoMatches(recovered, http.StatusOK, "team-c", http.MethodPost, "/anything", runtimeLiveBody), recovered.describe()
	})

	rotatedKeys := []APIKeyCredential{{Key: "runtime-key-b", Attributes: map[string]string{"tenant_id": "client-a"}}}
	rotatedKeyFile, err := GenerateAPIKeyECDS(findAuthenticator(gatewayConfig, "partner-key"), rotatedKeys)
	if err != nil {
		t.Fatal(err)
	}
	keyRotationAt := runtimeLiveAtomicReplace(t, harness, APIKeyECDSPath, rotatedKeyFile)
	runtimeLiveAwait(t, harness, "API-key ECDS rotation to runtime-key-b", keyRotationAt, func() (bool, string) {
		accepted := harness.request(false, runtimeLiveKeyHost, "runtime-key-b", http.MethodPost, "/ingest", runtimeLiveBody)
		stale := harness.request(false, runtimeLiveKeyHost, "runtime-key-a", http.MethodPost, "/ingest", runtimeLiveBody)
		acceptedOK := runtimeLiveEchoMatches(accepted, http.StatusOK, "team-c", http.MethodPost, "/anything", runtimeLiveBody)
		staleDenied := stale.status == http.StatusUnauthorized && stale.err == nil
		return acceptedOK && staleDenied, fmt.Sprintf("new key: %s; old key: %s", accepted.describe(), stale.describe())
	})

	apiKeyFailures, err := harness.updateFailures()
	if err != nil {
		t.Fatal(err)
	}
	badKeyAt := runtimeLiveAtomicReplace(t, harness, APIKeyECDSPath, []byte(runtimeLiveBadResource))
	runtimeLiveAssertRetained(t, harness, "malformed API-key ECDS update", badKeyAt, apiKeyFailures, func() (bool, string) {
		accepted := harness.request(false, runtimeLiveKeyHost, "runtime-key-b", http.MethodPost, "/ingest", runtimeLiveBody)
		unaccepted := harness.request(false, runtimeLiveKeyHost, "runtime-key-c", http.MethodPost, "/ingest", runtimeLiveBody)
		acceptedOK := runtimeLiveEchoMatches(accepted, http.StatusOK, "team-c", http.MethodPost, "/anything", runtimeLiveBody)
		unacceptedDenied := unaccepted.status == http.StatusUnauthorized && unaccepted.err == nil
		return acceptedOK && unacceptedDenied, fmt.Sprintf("last accepted key: %s; unaccepted key: %s", accepted.describe(), unaccepted.describe())
	})

	recoveredKeys := []APIKeyCredential{{Key: "runtime-key-c", Attributes: map[string]string{"tenant_id": "client-a"}}}
	recoveredKeyFile, err := GenerateAPIKeyECDS(findAuthenticator(gatewayConfig, "partner-key"), recoveredKeys)
	if err != nil {
		t.Fatal(err)
	}
	keyRecoveryAt := runtimeLiveAtomicReplace(t, harness, APIKeyECDSPath, recoveredKeyFile)
	runtimeLiveAwait(t, harness, "API-key ECDS recovery to runtime-key-c", keyRecoveryAt, func() (bool, string) {
		accepted := harness.request(false, runtimeLiveKeyHost, "runtime-key-c", http.MethodPost, "/ingest", runtimeLiveBody)
		stale := harness.request(false, runtimeLiveKeyHost, "runtime-key-b", http.MethodPost, "/ingest", runtimeLiveBody)
		acceptedOK := runtimeLiveEchoMatches(accepted, http.StatusOK, "team-c", http.MethodPost, "/anything", runtimeLiveBody)
		staleDenied := stale.status == http.StatusUnauthorized && stale.err == nil
		return acceptedOK && staleDenied, fmt.Sprintf("recovered key: %s; previous key: %s", accepted.describe(), stale.describe())
	})

	emptyKeyFile, err := GenerateAPIKeyECDS(findAuthenticator(gatewayConfig, "partner-key"), nil)
	if err != nil {
		t.Fatal(err)
	}
	keyRevocationAt := runtimeLiveAtomicReplace(t, harness, APIKeyECDSPath, emptyKeyFile)
	runtimeLiveAwait(t, harness, "empty API-key ECDS revocation", keyRevocationAt, func() (bool, string) {
		revoked := harness.request(false, runtimeLiveKeyHost, "runtime-key-c", http.MethodPost, "/ingest", runtimeLiveBody)
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

	tlsFailures, err := harness.updateFailures()
	if err != nil {
		t.Fatal(err)
	}
	badTLSAt := runtimeLiveAtomicReplace(t, harness, rotatedTLSFile.Path, []byte(runtimeLiveBadResource))
	runtimeLiveAssertRetained(t, harness, "malformed server TLS SDS update", badTLSAt, tlsFailures, func() (bool, string) {
		response := harness.request(true, runtimeLiveTLSHost, "", http.MethodGet, "/tls", "")
		return runtimeLiveTLSMatches(response, certificates[1].certificate.SerialNumber.Int64()), response.describe()
	})

	recoveredTLSFile, _, err := runtimeLiveTLSResource(gatewayConfig, 3)
	if err != nil {
		t.Fatal(err)
	}
	tlsRecoveryAt := runtimeLiveAtomicReplace(t, harness, recoveredTLSFile.Path, recoveredTLSFile.Contents)
	runtimeLiveAwait(t, harness, "server TLS SDS recovery to certificate 3", tlsRecoveryAt, func() (bool, string) {
		response := harness.request(true, runtimeLiveTLSHost, "", http.MethodGet, "/tls", "")
		return runtimeLiveTLSMatches(response, certificates[2].certificate.SerialNumber.Int64()), response.describe()
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
            - {name: X-Scope-OrgID, from_attribute: tenant_id}
  - name: tls-probe
    upstream: {address: httpbin, port: 8080}
    routes:
      - methods: [GET]
        path: {exact: /tls}
        rewrite: {path: /anything}
processing:
  - name: tenant-map
    type: attribute-mapper
    attributes:
      tenant_id:
        mappings: {client-a: team-a}
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
	envoyName := "auth-gateway-envoy-" + nameSuffix

	runtimeLiveDocker(t, "network", "create", networkName)
	t.Cleanup(func() { runtimeLiveDockerCleanup(t, "network", "rm", networkName) })
	runtimeLiveDocker(t, "run", "--detach", "--name", httpbinName, "--network", networkName, "--network-alias", "httpbin", runtimeLiveHTTPBinImage)
	t.Cleanup(func() { runtimeLiveDockerCleanup(t, "rm", "--force", httpbinName) })

	image := os.Getenv("AUTH_GATEWAY_RUNTIME_IMAGE")
	if image == "" {
		image = DefaultEnvoyImage
	}
	runtimeLiveDocker(t, "run", "--detach", "--user", "101:101", "--name", envoyName,
		"--network", networkName, "--publish", "127.0.0.1::8080/tcp", "--publish", "127.0.0.1::9901/tcp",
		"--volume", configDir+":"+EnvoyConfigDirectory, image,
		"--log-level", "info", "-c", EnvoyBootstrapPath)
	t.Cleanup(func() { runtimeLiveDockerCleanup(t, "rm", "--force", envoyName) })

	portOutput := runtimeLiveOutput(t, "port", envoyName, "8080/tcp")
	_, port, err := net.SplitHostPort(strings.TrimSpace(string(portOutput)))
	if err != nil {
		t.Fatalf("parse Envoy published port %q: %v", portOutput, err)
	}
	address := net.JoinHostPort("127.0.0.1", port)
	adminPortOutput := runtimeLiveOutput(t, "port", envoyName, "9901/tcp")
	_, adminPort, err := net.SplitHostPort(strings.TrimSpace(string(adminPortOutput)))
	if err != nil {
		t.Fatalf("parse Envoy published admin port %q: %v", adminPortOutput, err)
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	tlsTransport := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: &tls.Config{
		RootCAs: roots, ServerName: runtimeLiveTLSHost, MinVersion: tls.VersionTLS12,
	}}
	return &runtimeLiveHarness{
		address:    address,
		admin:      "http://" + net.JoinHostPort("127.0.0.1", adminPort),
		envoyName:  envoyName,
		httpClient: &http.Client{Transport: transport, Timeout: 4 * time.Second},
		tlsClient:  &http.Client{Transport: tlsTransport, Timeout: 4 * time.Second},
	}
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
	certificates := make([]runtimeLiveCertificate, 3)
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
	admin      string
	envoyName  string
	httpClient *http.Client
	tlsClient  *http.Client
}

func runtimeLiveBootstrapWithOpenAdmin(t *testing.T, contents []byte) []byte {
	t.Helper()
	bootstrap := decodeBootstrap(t, contents)
	if bootstrap.Admin == nil || bootstrap.Admin.Address == nil || bootstrap.Admin.Address.GetSocketAddress() == nil {
		t.Fatal("generated Envoy bootstrap has no admin socket address")
	}
	bootstrap.Admin.Address.GetSocketAddress().Address = "0.0.0.0"
	updated, err := protojson.Marshal(bootstrap)
	if err != nil {
		t.Fatalf("marshal test Envoy bootstrap: %v", err)
	}
	return updated
}

func (h *runtimeLiveHarness) updateFailures() (uint64, error) {
	response, err := h.httpClient.Get(h.admin + "/stats?filter=update_")
	if err != nil {
		return 0, fmt.Errorf("request Envoy update-failure stats: %w", err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return 0, fmt.Errorf("read Envoy update-failure stats: %w", err)
	}
	if err := response.Body.Close(); err != nil {
		return 0, fmt.Errorf("close Envoy update-failure stats: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("Envoy update-failure stats returned HTTP %d", response.StatusCode)
	}
	var total uint64
	for _, line := range strings.Split(string(body), "\n") {
		name, value, found := strings.Cut(line, ":")
		if !found || (!strings.HasSuffix(name, ".update_rejected") && !strings.HasSuffix(name, ".update_failure")) {
			continue
		}
		count, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("parse Envoy update stat %q: %w", name, err)
		}
		total += count
	}
	return total, nil
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

func runtimeLiveAssertRetained(t *testing.T, harness *runtimeLiveHarness, label string, updatedAt time.Time, beforeFailures uint64, check func() (bool, string)) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		failures, err := harness.updateFailures()
		if err != nil {
			t.Fatal(err)
		}
		if failures > beforeFailures {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	failures, err := harness.updateFailures()
	if err != nil {
		t.Fatal(err)
	}
	if failures <= beforeFailures {
		t.Fatalf("%s did not increase Envoy update-failure counters after atomic replacement; before=%d after=%d\nEnvoy logs:\n%s", label, beforeFailures, failures, runtimeLiveLogs(harness.envoyName))
	}
	deadline = time.Now().Add(2 * time.Second)
	var last string
	consecutiveSuccesses := 0
	for time.Now().Before(deadline) {
		observed, detail := check()
		last = detail
		if observed {
			consecutiveSuccesses++
		} else {
			consecutiveSuccesses = 0
		}
		time.Sleep(200 * time.Millisecond)
	}
	if consecutiveSuccesses < 3 {
		t.Fatalf("%s did not retain the last accepted behavior: %s\nEnvoy logs:\n%s", label, last, runtimeLiveLogs(harness.envoyName))
	}
	t.Logf("%s rejected the malformed update and retained the last accepted behavior through %s after atomic replacement", label, time.Since(updatedAt).Round(time.Millisecond))
}

func runtimeLiveLogs(container string) string {
	output, err := runtimeLiveCommand(10*time.Second, "docker", "logs", "--tail", "80", container)
	if err != nil {
		return fmt.Sprintf("read logs: %v\n%s", err, output)
	}
	return string(output)
}
