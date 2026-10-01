//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/rhobs/auth-gateway/config"
	"github.com/rhobs/auth-gateway/e2e/internal/framework"
)

const (
	testNamespace = "auth-gateway-e2e"
	httpHost      = "auth.auth-gateway.test"
	httpsHost     = "tls.auth-gateway.test"
)

var (
	env            *framework.Environment
	testClient     = &http.Client{Timeout: 10 * time.Second}
	httpAddress    string
	httpsAddress   string
	metricsAddress string
	rootCAs        *x509.CertPool
)

type httpCase struct {
	method      string
	path        string
	host        string
	wantStatus  int
	inspectEcho bool
}

var _ = BeforeSuite(func(ctx SpecContext) {
	ready := false
	defer func() {
		if !ready {
			logTestState()
		}
	}()

	var err error
	env, err = framework.New()
	Expect(err).NotTo(HaveOccurred())
	suiteConfig, _ := GinkgoConfiguration()
	Expect(suiteConfig.ParallelTotal).To(Equal(1), "the suite shares a namespace and rotates its certificate")
	Expect(env.DeleteNamespace(ctx, testNamespace)).To(Succeed())
	Expect(env.CreateNamespace(ctx, testNamespace)).To(Succeed())
	DeferCleanup(func(ctx SpecContext) {
		Expect(env.DeleteNamespace(ctx, testNamespace)).To(Succeed())
	}, NodeTimeout(3*time.Minute))

	certificates, err := env.Fixture("certificates.yaml")
	Expect(err).NotTo(HaveOccurred())
	Expect(env.Apply(ctx, testNamespace, certificates)).To(Succeed())
	for _, resource := range []struct {
		gvr  schema.GroupVersionResource
		name string
	}{
		{gvr: schema.GroupVersionResource{Group: "cert-manager.io", Version: "v1", Resource: "issuers"}, name: "auth-gateway-ca"},
		{gvr: schema.GroupVersionResource{Group: "cert-manager.io", Version: "v1", Resource: "certificates"}, name: "auth-gateway-server"},
	} {
		Expect(env.WaitForResourceCondition(ctx, testNamespace, resource.gvr, resource.name, "Ready", 4*time.Minute)).To(Succeed())
	}
	backend, err := env.Fixture("httpbin.yaml")
	Expect(err).NotTo(HaveOccurred())
	Expect(env.Apply(ctx, testNamespace, backend)).To(Succeed())

	gatewayFixture, err := env.Fixture("gateway.yaml")
	Expect(err).NotTo(HaveOccurred())
	gatewayConfig, err := config.Load(bytes.NewReader(gatewayFixture))
	Expect(err).NotTo(HaveOccurred())
	resources, err := config.GenerateKubernetes(gatewayConfig)
	Expect(err).NotTo(HaveOccurred())
	manifest, err := resources.YAML()
	Expect(err).NotTo(HaveOccurred())
	Expect(env.Apply(ctx, testNamespace, manifest)).To(Succeed())
	for _, deployment := range []string{"httpbin", "auth-gateway"} {
		Expect(env.WaitForDeployment(ctx, testNamespace, deployment, 4*time.Minute)).To(Succeed())
	}

	httpAddress = env.ForwardWithCleanup(ctx, testNamespace, "service/auth-gateway", 80)
	httpsAddress = env.ForwardWithCleanup(ctx, testNamespace, "service/auth-gateway", 443)
	metricsAddress = env.ForwardWithCleanup(ctx, testNamespace, "service/auth-gateway", 8889)
	Eventually(func() error {
		return checkUpstream(ctx, httpAddress, httpHost)
	}).WithContext(ctx).WithTimeout(15 * time.Second).WithPolling(250 * time.Millisecond).Should(Succeed())

	caSecret, err := env.Secret(ctx, testNamespace, "auth-gateway-e2e-ca")
	Expect(err).NotTo(HaveOccurred())
	caPEM, ok := caSecret.Data["tls.crt"]
	Expect(ok).To(BeTrue(), "test CA Secret should contain tls.crt")
	rootCAs = x509.NewCertPool()
	Expect(rootCAs.AppendCertsFromPEM(caPEM)).To(BeTrue(), "load the cert-manager test CA")
	ready = true
}, NodeTimeout(12*time.Minute))

var _ = ReportAfterEach(func(report SpecReport) {
	if report.Failed() {
		logTestState()
	}
})

var _ = Describe("Auth Gateway", Label("gateway"), Serial, func() {
	DescribeTable("HTTP request handling", func(ctx SpecContext, test httpCase) {
		body := []byte("remote-write test payload")
		request, err := http.NewRequestWithContext(ctx, test.method, "http://"+httpAddress+test.path, bytes.NewReader(body))
		Expect(err).NotTo(HaveOccurred())
		request.Host = test.host
		request.Header.Set("Content-Type", "application/octet-stream")
		response, err := testClient.Do(request)
		Expect(err).NotTo(HaveOccurred())
		defer response.Body.Close()
		responseBody, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		Expect(err).NotTo(HaveOccurred())
		Expect(response.StatusCode).To(Equal(test.wantStatus), string(responseBody))
		if test.wantStatus == http.StatusMethodNotAllowed {
			Expect(response.Header.Get("Allow")).To(Equal("POST"))
		}
		if !test.inspectEcho {
			return
		}

		var echoed struct {
			Method string `json:"method"`
			URL    string `json:"url"`
			Data   string `json:"data"`
		}
		Expect(json.Unmarshal(responseBody, &echoed)).To(Succeed())
		Expect(echoed.Method).To(Equal(http.MethodPost))
		Expect(echoed.URL).To(HaveSuffix("/anything/api/v1/receive"))
		wantData := "data:application/octet-stream;base64," + base64.StdEncoding.EncodeToString(body)
		Expect(echoed.Data).To(Equal(wantData))
	},
		Entry("forwards metrics", httpCase{method: http.MethodPost, path: "/metrics/api/v1/receive", host: httpHost, wantStatus: http.StatusOK, inspectEcho: true}),
		Entry("rejects other methods", httpCase{method: http.MethodGet, path: "/metrics/api/v1/receive", host: httpHost, wantStatus: http.StatusMethodNotAllowed}),
		Entry("rejects unknown paths", httpCase{method: http.MethodPost, path: "/unknown", host: httpHost, wantStatus: http.StatusNotFound}),
		Entry("does not serve the HTTPS host over HTTP", httpCase{method: http.MethodGet, path: "/upstream-health", host: httpsHost, wantStatus: http.StatusNotFound}),
	)

	It("serves HTTPS only for the configured TLS host", func(ctx SpecContext) {
		By("serving a certificate trusted by the test CA")
		response, err := requestHTTPS(ctx, httpsAddress, httpsHost, httpsHost, "/upstream-health", rootCAs)
		Expect(err).NotTo(HaveOccurred())
		Expect(response.status).To(Equal(http.StatusOK))
		Expect(response.certificate.DNSNames).To(ContainElement(httpsHost))

		By("rejecting the HTTP host on the HTTPS listener")
		wrongHost, err := requestHTTPS(ctx, httpsAddress, httpsHost, httpHost, "/upstream-health", rootCAs)
		Expect(err).NotTo(HaveOccurred())
		Expect(wrongHost.status).To(Equal(http.StatusNotFound))
	}, SpecTimeout(30*time.Second))

	It("rotates the server certificate without restarting Envoy", func(ctx SpecContext) {
		initialTLS, err := requestHTTPS(ctx, httpsAddress, httpsHost, httpsHost, "/upstream-health", rootCAs)
		Expect(err).NotTo(HaveOccurred())
		Expect(initialTLS.status).To(Equal(http.StatusOK))
		initialPodUID, err := gatewayPodUID(ctx, testNamespace)
		Expect(err).NotTo(HaveOccurred())

		By("asking cert-manager to renew the server certificate")
		Expect(renewCertificate(ctx, os.Getenv("AUTH_GATEWAY_E2E_CMCTL"), env.KubeContext(), testNamespace, "auth-gateway-server")).To(Succeed())

		var rotatedTLS *httpsResult
		initialSerial := initialTLS.certificate.SerialNumber.String()
		Eventually(func() error {
			result, err := requestHTTPS(ctx, httpsAddress, httpsHost, httpsHost, "/upstream-health", rootCAs)
			if err != nil {
				return err
			}
			if result.certificate.SerialNumber.String() == initialSerial {
				return fmt.Errorf("certificate serial %s has not rotated", initialSerial)
			}
			rotatedTLS = result
			return nil
		}).WithContext(ctx).WithTimeout(8 * time.Minute).WithPolling(500 * time.Millisecond).Should(Succeed())

		Expect(rotatedTLS.status).To(Equal(http.StatusOK))
		Expect(rotatedTLS.certificate.DNSNames).To(ContainElement(httpsHost))
		Expect(rotatedTLS.certificate.NotAfter).To(BeTemporally(">", initialTLS.certificate.NotAfter))
		Expect(rotatedTLS.certificate.RawSubjectPublicKeyInfo).NotTo(Equal(initialTLS.certificate.RawSubjectPublicKeyInfo), "cert-manager should rotate the private key")

		rotatedPodUID, err := gatewayPodUID(ctx, testNamespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(rotatedPodUID).To(Equal(initialPodUID), "the gateway Pod should not restart during certificate rotation")
	}, SpecTimeout(9*time.Minute))

	It("exposes scraped Envoy metrics", func(ctx SpecContext) {
		Eventually(func() error {
			return checkPrometheusMetrics(ctx, metricsAddress)
		}).WithContext(ctx).WithTimeout(70 * time.Second).WithPolling(500 * time.Millisecond).Should(Succeed())
	}, SpecTimeout(90*time.Second))
})

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
	body        []byte
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
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if response.TLS == nil || len(response.TLS.PeerCertificates) == 0 {
		return nil, fmt.Errorf("HTTPS response did not include the peer certificate")
	}
	return &httpsResult{
		status:      response.StatusCode,
		certificate: response.TLS.PeerCertificates[0],
		body:        body,
	}, nil
}

func renewCertificate(ctx context.Context, cmctlPath, clusterContext, namespace, name string) error {
	if cmctlPath == "" {
		cmctlPath = "cmctl"
	}
	args := []string{"renew", "--context", clusterContext, "--namespace", namespace, name}
	output, err := exec.CommandContext(ctx, cmctlPath, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("cmctl %s: %w\n%s", strings.Join(args, " "), err, output)
	}
	return nil
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

func logTestState() {
	if env == nil {
		return
	}
	env.Diagnostics(testNamespace)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	address, stop, err := env.Forward(ctx, testNamespace, "deployment/auth-gateway", 9901)
	if err != nil {
		_, _ = fmt.Fprintf(GinkgoWriter, "Envoy cluster state: start port-forward: %v\n", err)
		return
	}
	defer stop()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+"/clusters?format=json", nil)
	if err != nil {
		_, _ = fmt.Fprintf(GinkgoWriter, "Envoy cluster state: create request: %v\n", err)
		return
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		_, _ = fmt.Fprintf(GinkgoWriter, "Envoy cluster state: request admin API: %v\n", err)
		return
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		_, _ = fmt.Fprintf(GinkgoWriter, "Envoy cluster state: read admin response: %v\n", err)
		return
	}
	_, _ = fmt.Fprintf(GinkgoWriter, "Envoy cluster state (HTTP %d):\n%s\n", response.StatusCode, data)
}
