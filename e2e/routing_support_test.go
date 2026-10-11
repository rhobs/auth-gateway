//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/rhobs/auth-gateway/config"
)

const (
	httpHost       = "auth.auth-gateway.test"
	httpsHost      = "tls.auth-gateway.test"
	queryHTTPHost  = "query.auth-gateway.test"
	queryHTTPSHost = "query-tls.auth-gateway.test"
	unknownHost    = "unknown.auth-gateway.test"
)

var (
	routingNamespace    = e2eNamespace("auth-gateway-routing-e2e")
	tlsNamespace        = e2eNamespace("auth-gateway-tls-e2e")
	httpAddress         string
	httpsAddress        string
	metricsAddress      string
	routingAdminAddress string
	routingRootCAs      *x509.CertPool
)

func setupGateway(ctx SpecContext, namespace string, useTLS bool) {
	httpAddress = ""
	httpsAddress = ""
	metricsAddress = ""
	routingAdminAddress = ""
	routingRootCAs = nil

	Expect(resetE2ENamespace(ctx, namespace)).To(Succeed())
	DeferCleanup(func(ctx SpecContext) {
		Expect(env.DeleteNamespace(ctx, namespace)).To(Succeed())
	}, NodeTimeout(3*time.Minute))

	if useTLS {
		Expect(env.EnsureCertManager(ctx, os.Getenv("AUTH_GATEWAY_E2E_CERT_MANAGER_MANIFEST"))).To(Succeed())
		certificates, err := env.Fixture("certificates.yaml")
		Expect(err).NotTo(HaveOccurred())
		Expect(env.Apply(ctx, namespace, certificates)).To(Succeed())
		for _, resource := range []struct {
			gvr  schema.GroupVersionResource
			name string
		}{
			{gvr: schema.GroupVersionResource{Group: "cert-manager.io", Version: "v1", Resource: "issuers"}, name: "auth-gateway-ca"},
			{gvr: schema.GroupVersionResource{Group: "cert-manager.io", Version: "v1", Resource: "certificates"}, name: "auth-gateway-server"},
			{gvr: schema.GroupVersionResource{Group: "cert-manager.io", Version: "v1", Resource: "certificates"}, name: "auth-gateway-query-server"},
		} {
			Expect(env.WaitForResourceCondition(ctx, namespace, resource.gvr, resource.name, "Ready", 4*time.Minute)).To(Succeed())
		}
	}

	backend, err := env.Fixture("httpbin.yaml")
	Expect(err).NotTo(HaveOccurred())
	Expect(env.Apply(ctx, namespace, backend)).To(Succeed())

	manifest := generatedGatewayManifest(namespace, useTLS)
	Expect(env.Apply(ctx, namespace, manifest)).To(Succeed())
	for _, deployment := range []string{"httpbin", "auth-gateway"} {
		Expect(env.WaitForDeployment(ctx, namespace, deployment, 4*time.Minute)).To(Succeed())
	}

	httpAddress = env.ForwardWithCleanup(ctx, namespace, "service/auth-gateway", 80)
	metricsAddress = env.ForwardWithCleanup(ctx, namespace, "service/auth-gateway", 8889)
	routingAdminAddress = env.ForwardEnvoyAdminWithCleanup(ctx, namespace)
	if useTLS {
		httpsAddress = env.ForwardWithCleanup(ctx, namespace, "service/auth-gateway", 443)
	}
	Expect(waitForSuccessfulRequest(ctx, "HTTP gateway", 30*time.Second, 250*time.Millisecond, func(ctx context.Context) error {
		return checkUpstream(ctx, httpAddress, httpHost)
	})).To(Succeed())

	if useTLS {
		caSecret, err := env.Secret(ctx, namespace, "auth-gateway-e2e-ca")
		Expect(err).NotTo(HaveOccurred())
		caPEM, ok := caSecret.Data["tls.crt"]
		Expect(ok).To(BeTrue(), "test CA Secret should contain tls.crt")
		routingRootCAs = x509.NewCertPool()
		Expect(routingRootCAs.AppendCertsFromPEM(caPEM)).To(BeTrue(), "load the cert-manager test CA")
	}
}

func generatedGatewayManifest(namespace string, useTLS bool) []byte {
	return generatedGatewayManifestWithMetrics(namespace, useTLS, true)
}

func generatedGatewayManifestWithMetrics(namespace string, useTLS, metricsEnabled bool) []byte {
	gatewayFixture, err := env.Fixture("gateway.yaml")
	Expect(err).NotTo(HaveOccurred())
	gatewayConfig, err := config.Load(bytes.NewReader(gatewayFixture))
	Expect(err).NotTo(HaveOccurred())
	gatewayConfig.Kubernetes.Namespace = namespace
	gatewayConfig.Observability.Metrics.Enabled = new(metricsEnabled)
	if !useTLS {
		var servers []config.Server
		for _, server := range gatewayConfig.Servers {
			if server.TLSConfig == nil {
				servers = append(servers, server)
			}
		}
		gatewayConfig.Servers = servers
		gatewayConfig.Kubernetes.HTTPSServicePort = nil
	}
	resources, err := config.GenerateKubernetes(gatewayConfig)
	Expect(err).NotTo(HaveOccurred())
	manifest, err := resources.YAML()
	Expect(err).NotTo(HaveOccurred())
	return manifest
}

func checkUpstream(ctx context.Context, address, host string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+"/upstream-health", nil)
	if err != nil {
		return err
	}
	request.Host = host
	response, err := (&http.Client{Timeout: 2 * time.Second}).Do(request)
	if err != nil {
		return err
	}
	body, err := readAndCloseResponseBody(response, 1<<20)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("upstream readiness returned HTTP %d: %s", response.StatusCode, body)
	}
	return nil
}

type httpsResult struct {
	status      int
	allow       string
	body        []byte
	certificate *x509.Certificate
}

func requestHTTPS(ctx context.Context, address, serverName, requestHost, requestPath string, rootCAs *x509.CertPool) (*httpsResult, error) {
	return requestHTTPSWithMethodAndBody(ctx, address, serverName, requestHost, http.MethodGet, requestPath, nil, nil, rootCAs)
}

func requestHTTPSWithMethod(ctx context.Context, address, serverName, requestHost, method, requestPath string, rootCAs *x509.CertPool) (*httpsResult, error) {
	return requestHTTPSWithMethodAndBody(ctx, address, serverName, requestHost, method, requestPath, nil, nil, rootCAs)
}

func requestHTTPSWithMethodAndBody(ctx context.Context, address, serverName, requestHost, method, requestPath string, body []byte, headers http.Header, rootCAs *x509.CertPool) (*httpsResult, error) {
	client := newTestTLSClient(rootCAs, serverName)
	defer client.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, method, "https://"+address+requestPath, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Host = requestHost
	request.Header = headers.Clone()
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	responseBody, err := readAndCloseResponseBody(response, 1<<20)
	if err != nil {
		return nil, err
	}
	if response.TLS == nil || len(response.TLS.PeerCertificates) == 0 {
		return nil, fmt.Errorf("HTTPS response did not include the peer certificate")
	}
	return &httpsResult{
		status:      response.StatusCode,
		allow:       response.Header.Get("Allow"),
		body:        responseBody,
		certificate: response.TLS.PeerCertificates[0],
	}, nil
}

func checkPrometheusMetrics(ctx context.Context, address string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+"/metrics", nil)
	if err != nil {
		return err
	}
	response, err := (&http.Client{Timeout: 2 * time.Second}).Do(request)
	if err != nil {
		return err
	}
	body, err := readAndCloseResponseBody(response, 1<<20)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("collector metrics returned HTTP %d: %s", response.StatusCode, body)
	}
	if !bytes.Contains(body, []byte("envoy_server_live")) {
		return fmt.Errorf("Envoy server metrics were not exported")
	}
	if err := checkExportedRequestMetric(ctx, address, "envoy_http_downstream_rq_total", nil); err != nil {
		return fmt.Errorf("Envoy HTTP request metrics were not exported: %w", err)
	}
	return nil
}
