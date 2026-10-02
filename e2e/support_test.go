//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/rhobs/auth-gateway/config"
	"github.com/rhobs/auth-gateway/e2e/internal/framework"
)

const (
	routingNamespace = "auth-gateway-routing-e2e"
	tlsNamespace     = "auth-gateway-tls-e2e"
	httpHost         = "auth.auth-gateway.test"
	httpsHost        = "tls.auth-gateway.test"
)

var (
	env             *framework.Environment
	testClient      = &http.Client{Timeout: 10 * time.Second}
	activeNamespace string
	httpAddress     string
	httpsAddress    string
	metricsAddress  string
	rootCAs         *x509.CertPool
)

func setupGateway(ctx SpecContext, namespace string, useTLS bool) {
	activeNamespace = namespace
	httpAddress = ""
	httpsAddress = ""
	metricsAddress = ""
	rootCAs = nil

	Expect(env.DeleteNamespace(ctx, namespace)).To(Succeed())
	Expect(env.CreateNamespace(ctx, namespace)).To(Succeed())
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
	if useTLS {
		httpsAddress = env.ForwardWithCleanup(ctx, namespace, "service/auth-gateway", 443)
	}
	Eventually(func() error {
		return checkUpstream(ctx, httpAddress, httpHost)
	}).WithContext(ctx).WithTimeout(15 * time.Second).WithPolling(250 * time.Millisecond).Should(Succeed())

	if useTLS {
		caSecret, err := env.Secret(ctx, namespace, "auth-gateway-e2e-ca")
		Expect(err).NotTo(HaveOccurred())
		caPEM, ok := caSecret.Data["tls.crt"]
		Expect(ok).To(BeTrue(), "test CA Secret should contain tls.crt")
		rootCAs = x509.NewCertPool()
		Expect(rootCAs.AppendCertsFromPEM(caPEM)).To(BeTrue(), "load the cert-manager test CA")
	}
}

func generatedGatewayManifest(namespace string, useTLS bool) []byte {
	gatewayFixture, err := env.Fixture("gateway.yaml")
	Expect(err).NotTo(HaveOccurred())
	gatewayConfig, err := config.Load(bytes.NewReader(gatewayFixture))
	Expect(err).NotTo(HaveOccurred())
	gatewayConfig.Kubernetes.Namespace = namespace
	if !useTLS {
		gatewayConfig.Listener.HTTPSHosts = nil
		gatewayConfig.ServerTLS = nil
		gatewayConfig.Kubernetes.HTTPSServicePort = 0
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
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
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
	certificate *x509.Certificate
}

func requestHTTPS(ctx context.Context, address, serverName, requestHost, requestPath string, rootCAs *x509.CertPool) (*httpsResult, error) {
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:    rootCAs,
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+address+requestPath, nil)
	if err != nil {
		return nil, err
	}
	request.Host = requestHost
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if _, err := io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20)); err != nil {
		return nil, err
	}
	if response.TLS == nil || len(response.TLS.PeerCertificates) == 0 {
		return nil, fmt.Errorf("HTTPS response did not include the peer certificate")
	}
	return &httpsResult{status: response.StatusCode, certificate: response.TLS.PeerCertificates[0]}, nil
}

func gatewayPodUID(ctx context.Context, namespace string) (string, error) {
	return env.PodUID(ctx, namespace, "app.kubernetes.io/instance=auth-gateway")
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
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK || !bytes.Contains(body, []byte("envoy_server_live")) {
		return fmt.Errorf("HTTP %d did not include Envoy metrics", response.StatusCode)
	}
	return nil
}
