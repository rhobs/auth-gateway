//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/rhobs/auth-gateway/config"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

const (
	apiKeyNamespace       = "auth-gateway-api-key-e2e"
	apiKeyIsolatedNS      = "auth-gateway-api-key-isolated-e2e"
	apiKeyPublicHost      = "public.api-key.auth-gateway.test"
	apiKeyOnlyHost        = "key.api-key.auth-gateway.test"
	apiKeyAnyHost         = "any.api-key.auth-gateway.test"
	apiKeyAllHost         = "all.api-key.auth-gateway.test"
	apiKeyRequestBody     = "api-key-payload"
	apiKeySharedSecretKey = "key-a"
)

type apiKeyE2E struct {
	config    config.Config
	keys      map[string]*rsa.PrivateKey
	rootCAs   *x509.CertPool
	httpAddr  string
	adminAddr string
	resources *config.KubernetesResources
}

var _ = Describe("API-key authentication", Label("gateway", "api-key", "authentication", "authorization"), Ordered, func() {
	var gateway *apiKeyE2E

	BeforeAll(func(ctx SpecContext) {
		DeferCleanup(func(ctx SpecContext) { Expect(env.DeleteNamespace(ctx, apiKeyNamespace)).To(Succeed()) }, NodeTimeout(3*time.Minute))
		var err error
		gateway, err = setupAPIKeyGateway(ctx, apiKeyNamespace, false, []config.APIKeyCredential{
			{Key: apiKeySharedSecretKey, Attributes: map[string]string{"tenant_id": "client-a", "writer_id": "writer-a"}},
			{Key: "key-denied", Attributes: map[string]string{"tenant_id": "denied", "writer_id": "writer-a"}},
		}, apiKeySharedSecretKey)
		Expect(err).NotTo(HaveOccurred())
	}, NodeTimeout(12*time.Minute))

	It("uses one Secret across protected servers and forwards verified attributes", func(ctx SpecContext) {
		for _, host := range []string{apiKeyOnlyHost, apiKeyAnyHost} {
			status, body, err := gateway.request(ctx, host, false, http.MethodPost, "/ingest", apiKeyRequestBody, "", apiKeySharedSecretKey, nil)
			Expect(err).NotTo(HaveOccurred(), host)
			Expect(status).To(Equal(http.StatusOK), host+": "+string(body))
			expectAPIKeyEcho(body, "team-a", "writer-a")
		}
		status, body, err := gateway.request(ctx, apiKeyPublicHost, false, http.MethodGet, "/health", "", "", apiKeySharedSecretKey, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(status).To(Equal(http.StatusOK), string(body))
		var echo struct {
			Method  string              `json:"method"`
			URL     string              `json:"url"`
			Headers map[string][]string `json:"headers"`
		}
		Expect(json.Unmarshal(body, &echo)).To(Succeed())
		Expect(echo.Method).To(Equal(http.MethodGet))
		Expect(echo.URL).To(HaveSuffix("/anything"))
		Expect(headerValue(echo.Headers, "X-Partner-Key")).To(BeEmpty())
	}, NodeTimeout(60*time.Second))

	It("denies absent or unauthorized keys before the backend", func(ctx SpecContext) {
		for _, test := range []struct {
			name    string
			key     string
			headers http.Header
			status  int
		}{
			{name: "missing key", status: http.StatusUnauthorized},
			{name: "unknown key", key: "unknown-key", status: http.StatusUnauthorized},
			{name: "denied raw attribute", key: "key-denied", status: http.StatusForbidden},
			{name: "spoofed internal identity", headers: http.Header{
				"X-Auth-Gateway-API-Key-Client":          []string{"spoofed"},
				"X-Auth-Gateway-JWT-Verified-Issuer-One": []string{"https://issuer-one.jwt.test"},
			}, status: http.StatusUnauthorized},
		} {
			expectAPIKeyDenied(ctx, gateway, test.name, apiKeyOnlyHost, false, "", test.key, test.headers, test.status)
		}
	}, NodeTimeout(60*time.Second))

	It("uses a verified JWT first on a mixed any_of server", func(ctx SpecContext) {
		jwt := gateway.token("client-b", "writer-b")
		for _, test := range []struct {
			name   string
			token  string
			key    string
			tenant string
			writer string
		}{
			{name: "both credentials", token: jwt, key: apiKeySharedSecretKey, tenant: "team-b", writer: "writer-b"},
			{name: "valid JWT and invalid key", token: jwt, key: "wrong-key", tenant: "team-b", writer: "writer-b"},
			{name: "invalid JWT and valid key", token: "broken.jwt", key: apiKeySharedSecretKey, tenant: "team-a", writer: "writer-a"},
		} {
			status, body, err := gateway.request(ctx, apiKeyAnyHost, false, http.MethodPost, "/ingest", apiKeyRequestBody, test.token, test.key, nil)
			Expect(err).NotTo(HaveOccurred(), test.name)
			Expect(status).To(Equal(http.StatusOK), test.name+": "+string(body))
			expectAPIKeyEcho(body, test.tenant, test.writer)
		}
		expectAPIKeyDenied(ctx, gateway, "valid but unprivileged JWT wins", apiKeyAnyHost, false,
			gateway.token("denied", "writer-a"), apiKeySharedSecretKey, nil, http.StatusForbidden)
		expectAPIKeyDenied(ctx, gateway, "no credentials", apiKeyAnyHost, false, "", "", nil, http.StatusUnauthorized)
		expectAPIKeyDenied(ctx, gateway, "spoofed JWT marker", apiKeyAnyHost, false, "", "", http.Header{
			"X-Auth-Gateway-JWT-Verified-Issuer-One": []string{"https://issuer-one.jwt.test"},
		}, http.StatusUnauthorized)
	}, NodeTimeout(90*time.Second))

	It("requires both credentials and equal nonempty scalar attributes for all_of", func(ctx SpecContext) {
		jwt := gateway.token("client-a", "writer-a")
		status, body, err := gateway.request(ctx, apiKeyAllHost, true, http.MethodPost, "/ingest", apiKeyRequestBody, jwt, apiKeySharedSecretKey, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(status).To(Equal(http.StatusOK), string(body))
		expectAPIKeyEcho(body, "team-a", "writer-a")

		for _, test := range []struct {
			name   string
			token  string
			key    string
			status int
		}{
			{name: "JWT missing", key: apiKeySharedSecretKey, status: http.StatusUnauthorized},
			{name: "key missing", token: jwt, status: http.StatusUnauthorized},
			{name: "tenant mismatch", token: gateway.token("client-b", "writer-a"), key: apiKeySharedSecretKey, status: http.StatusForbidden},
			{name: "writer mismatch", token: gateway.token("client-a", "writer-b"), key: apiKeySharedSecretKey, status: http.StatusForbidden},
			{name: "empty shared claim", token: gateway.token("", "writer-a"), key: apiKeySharedSecretKey, status: http.StatusForbidden},
		} {
			expectAPIKeyDenied(ctx, gateway, test.name, apiKeyAllHost, true, test.token, test.key, nil, test.status)
		}
		claims := map[string]any{
			"organization": map[string]any{"id": []string{"client-a"}},
			"sub":          "writer-a", "aud": "gateway-test", "exp": time.Now().Add(5 * time.Minute).Unix(),
		}
		listToken := (&jwtE2E{keys: gateway.keys}).token("issuer-one", claims, nil)
		expectAPIKeyDenied(ctx, gateway, "list shared claim", apiKeyAllHost, true, listToken, apiKeySharedSecretKey, nil, http.StatusForbidden)
	}, NodeTimeout(90*time.Second))

	It("counts mapped key attributes in response metrics", func(ctx SpecContext) {
		labels := requestMetricLabels("ingest", http.StatusOK, "team-a", "writer-a")
		before, err := requestMetricCount(ctx, gateway.adminAddr, labels)
		Expect(err).NotTo(HaveOccurred())
		status, body, err := gateway.request(ctx, apiKeyOnlyHost, false, http.MethodPost, "/ingest", apiKeyRequestBody, "", apiKeySharedSecretKey, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(status).To(Equal(http.StatusOK), string(body))
		expectAPIKeyEcho(body, "team-a", "writer-a")
		after, err := requestMetricCount(ctx, gateway.adminAddr, labels)
		Expect(err).NotTo(HaveOccurred())
		Expect(after).To(Equal(before + 1))
	}, NodeTimeout(60*time.Second))

	It("reloads mapped key attributes without replacing the Pod", func(ctx SpecContext) {
		oldUID, err := gatewayPodUID(ctx, apiKeyNamespace)
		Expect(err).NotTo(HaveOccurred())
		updatedConfig, err := apiKeyConfig(apiKeyNamespace, false)
		Expect(err).NotTo(HaveOccurred())
		updatedConfig.Processing[0].Attributes["tenant_id"].Mappings["client-a"] = "team-c"
		updated, err := config.GenerateKubernetes(updatedConfig)
		Expect(err).NotTo(HaveOccurred())
		Expect(updated.ConfigMap.Data).To(Equal(gateway.resources.ConfigMap.Data))
		Expect(updated.Deployment.Spec.Template).To(Equal(gateway.resources.Deployment.Spec.Template))
		Expect(updated.ProcessingConfigMap.Data).NotTo(Equal(gateway.resources.ProcessingConfigMap.Data))
		manifest, err := yamlDocuments(updated.ProcessingConfigMap)
		Expect(err).NotTo(HaveOccurred())
		Expect(env.Apply(ctx, apiKeyNamespace, manifest)).To(Succeed())

		labels := requestMetricLabels("ingest", http.StatusOK, "team-c", "writer-a")
		before, err := requestMetricCount(ctx, gateway.adminAddr, labels)
		Expect(err).NotTo(HaveOccurred())
		var status int
		var body []byte
		Eventually(func() bool {
			status, body, err = gateway.request(ctx, apiKeyOnlyHost, false, http.MethodPost, "/ingest", apiKeyRequestBody, "", apiKeySharedSecretKey, nil)
			return err == nil && status == http.StatusOK && headerValue(jwtEchoHeaders(body), "X-Scope-OrgID") == "team-c"
		}).WithContext(ctx).WithTimeout(3*time.Minute).WithPolling(time.Second).Should(BeTrue(), func() string {
			return fmt.Sprintf("mapped key attribute did not reload: HTTP %d: %s (error: %v)", status, body, err)
		})
		expectAPIKeyEcho(body, "team-c", "writer-a")
		after, err := requestMetricCount(ctx, gateway.adminAddr, labels)
		Expect(err).NotTo(HaveOccurred())
		Expect(after).To(BeNumerically(">", before))
		newUID, err := gatewayPodUID(ctx, apiKeyNamespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(newUID).To(Equal(oldUID))
	}, SpecTimeout(5*time.Minute))

	It("rotates the shared Secret across HTTP and HTTPS servers without replacing the Pod", func(ctx SpecContext) {
		oldUID, err := gatewayPodUID(ctx, apiKeyNamespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(gateway.applySecret(ctx, []config.APIKeyCredential{
			{Key: "key-b", Attributes: map[string]string{"tenant_id": "client-b", "writer_id": "writer-b"}},
		})).To(Succeed())

		var status int
		var body []byte
		Eventually(func() bool {
			status, body, err = gateway.request(ctx, apiKeyOnlyHost, false, http.MethodPost, "/ingest", apiKeyRequestBody, "", "key-b", nil)
			if err != nil || status != http.StatusOK || headerValue(jwtEchoHeaders(body), "X-Scope-OrgID") != "team-b" {
				return false
			}
			status, body, err = gateway.request(ctx, apiKeyOnlyHost, false, http.MethodPost, "/ingest", apiKeyRequestBody, "", apiKeySharedSecretKey, nil)
			return err == nil && status == http.StatusUnauthorized
		}).WithContext(ctx).WithTimeout(4*time.Minute).WithPolling(time.Second).Should(BeTrue(), func() string {
			return fmt.Sprintf("Secret rotation did not replace the accepted key: HTTP %d: %s (error: %v)", status, body, err)
		})
		status, body, err = gateway.request(ctx, apiKeyAnyHost, false, http.MethodPost, "/ingest", apiKeyRequestBody, "", "key-b", nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(status).To(Equal(http.StatusOK), string(body))
		expectAPIKeyEcho(body, "team-b", "writer-b")
		status, body, err = gateway.request(ctx, apiKeyAllHost, true, http.MethodPost, "/ingest", apiKeyRequestBody,
			gateway.token("client-b", "writer-b"), "key-b", nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(status).To(Equal(http.StatusOK), string(body))
		expectAPIKeyEcho(body, "team-b", "writer-b")
		newUID, err := gatewayPodUID(ctx, apiKeyNamespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(newUID).To(Equal(oldUID))
	}, SpecTimeout(6*time.Minute))

	It("retains the last accepted keys when a Secret update is invalid", func(ctx SpecContext) {
		before, err := envoyUpdateFailures(ctx, gateway.adminAddr)
		Expect(err).NotTo(HaveOccurred())
		secret, err := config.APIKeySecret(apiKeyNamespace, gateway.config.Authenticators[1], nil)
		Expect(err).NotTo(HaveOccurred())
		secret.Data["api-keys.yaml"] = []byte("resources: [\n")
		manifest, err := yaml.Marshal(secret)
		Expect(err).NotTo(HaveOccurred())
		Expect(env.Apply(ctx, apiKeyNamespace, manifest)).To(Succeed())
		Eventually(func() (uint64, error) {
			return envoyUpdateFailures(ctx, gateway.adminAddr)
		}).WithContext(ctx).WithTimeout(4 * time.Minute).WithPolling(time.Second).Should(BeNumerically(">", before))
		status, body, err := gateway.request(ctx, apiKeyOnlyHost, false, http.MethodPost, "/ingest", apiKeyRequestBody, "", "key-b", nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(status).To(Equal(http.StatusOK), string(body))
		expectAPIKeyEcho(body, "team-b", "writer-b")
		Expect(gateway.applySecret(ctx, []config.APIKeyCredential{
			{Key: "key-b", Attributes: map[string]string{"tenant_id": "client-b", "writer_id": "writer-b"}},
		})).To(Succeed())
	}, SpecTimeout(6*time.Minute))

	It("revokes every key with an explicit empty Secret resource", func(ctx SpecContext) {
		oldUID, err := gatewayPodUID(ctx, apiKeyNamespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(gateway.applySecret(ctx, nil)).To(Succeed())
		var status int
		var body []byte
		Eventually(func() bool {
			status, body, err = gateway.request(ctx, apiKeyOnlyHost, false, http.MethodPost, "/ingest", apiKeyRequestBody, "", "key-b", nil)
			return err == nil && status == http.StatusUnauthorized
		}).WithContext(ctx).WithTimeout(4*time.Minute).WithPolling(time.Second).Should(BeTrue(), func() string {
			return fmt.Sprintf("empty Secret resource did not revoke key-b: HTTP %d: %s (error: %v)", status, body, err)
		})
		expectAPIKeyDenied(ctx, gateway, "revoked key on all_of", apiKeyAllHost, true,
			gateway.token("client-b", "writer-b"), "key-b", nil, http.StatusUnauthorized)
		status, body, err = gateway.request(ctx, apiKeyAnyHost, false, http.MethodPost, "/ingest", apiKeyRequestBody,
			gateway.token("client-b", "writer-b"), "", nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(status).To(Equal(http.StatusOK), string(body))
		expectAPIKeyEcho(body, "team-b", "writer-b")
		newUID, err := gatewayPodUID(ctx, apiKeyNamespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(newUID).To(Equal(oldUID))
	}, SpecTimeout(6*time.Minute))
})

var _ = Describe("API-key namespace isolation", Label("gateway", "api-key", "authentication"), Ordered, func() {
	var gateway *apiKeyE2E

	BeforeAll(func(ctx SpecContext) {
		DeferCleanup(func(ctx SpecContext) { Expect(env.DeleteNamespace(ctx, apiKeyIsolatedNS)).To(Succeed()) }, NodeTimeout(3*time.Minute))
		var err error
		gateway, err = setupAPIKeyGateway(ctx, apiKeyIsolatedNS, true, []config.APIKeyCredential{
			{Key: "isolated-key", Attributes: map[string]string{"tenant_id": "client-b", "writer_id": "writer-b"}},
		}, "isolated-key")
		Expect(err).NotTo(HaveOccurred())
	}, NodeTimeout(8*time.Minute))

	It("uses the same Secret name with independent namespace contents", func(ctx SpecContext) {
		status, body, err := gateway.request(ctx, apiKeyOnlyHost, false, http.MethodPost, "/ingest", apiKeyRequestBody, "", "isolated-key", nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(status).To(Equal(http.StatusOK), string(body))
		expectAPIKeyEcho(body, "team-b", "writer-b")
		status, body, err = gateway.request(ctx, apiKeyOnlyHost, false, http.MethodPost, "/ingest", apiKeyRequestBody, "", apiKeySharedSecretKey, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(status).To(Equal(http.StatusUnauthorized), string(body))
	}, NodeTimeout(60*time.Second))
})

func setupAPIKeyGateway(ctx SpecContext, namespace string, keyOnly bool, credentials []config.APIKeyCredential, warmupKey string) (*apiKeyE2E, error) {
	return setupAPIKeyGatewayWithShape(ctx, namespace, keyOnly, credentials, warmupKey, nil)
}

func setupAPIKeyGatewayWithShape(ctx SpecContext, namespace string, keyOnly bool, credentials []config.APIKeyCredential, warmupKey string, shape func(*config.Config)) (*apiKeyE2E, error) {
	activeNamespace = namespace
	if err := env.DeleteNamespace(ctx, namespace); err != nil {
		return nil, err
	}
	if err := env.CreateNamespace(ctx, namespace); err != nil {
		return nil, err
	}
	c, err := apiKeyConfig(namespace, keyOnly)
	if err != nil {
		return nil, err
	}
	if shape != nil {
		shape(&c)
	}
	gateway := &apiKeyE2E{config: c}
	if !keyOnly {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		gateway.keys = map[string]*rsa.PrivateKey{"issuer-one": key}
		certificates, err := makeJWTTestCertificates([]string{"jwks." + namespace + ".svc.cluster.local", apiKeyAllHost})
		if err != nil {
			return nil, err
		}
		gateway.rootCAs = x509.NewCertPool()
		gateway.rootCAs.AddCert(certificates.root)
		issuerManifest, err := jwtIssuerManifest(namespace, certificates, gateway.keys)
		if err != nil {
			return nil, err
		}
		if err := env.Apply(ctx, namespace, issuerManifest); err != nil {
			return nil, err
		}
		if err := env.WaitForDeployment(ctx, namespace, "jwt-jwks", 4*time.Minute); err != nil {
			return nil, err
		}
		tlsSecret := &corev1.Secret{
			TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
			ObjectMeta: metav1.ObjectMeta{Name: "api-key-gateway-tls", Namespace: namespace},
			Type:       corev1.SecretTypeTLS,
			Data:       map[string][]byte{corev1.TLSCertKey: certificates.chainPEM, corev1.TLSPrivateKeyKey: certificates.keyPEM},
		}
		caConfigMap := &corev1.ConfigMap{
			TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"},
			ObjectMeta: metav1.ObjectMeta{Name: "jwt-jwks-ca", Namespace: namespace},
			Data:       map[string]string{"ca.pem": string(certificates.caPEM)},
		}
		manifest, err := yamlDocuments(tlsSecret, caConfigMap)
		if err != nil {
			return nil, err
		}
		if err := env.Apply(ctx, namespace, manifest); err != nil {
			return nil, err
		}
	}
	backend, err := env.Fixture("httpbin.yaml")
	if err != nil {
		return nil, err
	}
	if err := env.Apply(ctx, namespace, backend); err != nil {
		return nil, err
	}
	if err := gateway.applySecret(ctx, credentials); err != nil {
		return nil, err
	}
	resources, err := config.GenerateKubernetes(c)
	if err != nil {
		return nil, err
	}
	gateway.resources = resources
	manifest, err := resources.YAML()
	if err != nil {
		return nil, err
	}
	if err := env.Apply(ctx, namespace, manifest); err != nil {
		return nil, err
	}
	for _, deployment := range []string{"httpbin", "auth-gateway"} {
		if err := env.WaitForDeployment(ctx, namespace, deployment, 4*time.Minute); err != nil {
			return nil, err
		}
	}
	gateway.httpAddr = env.ForwardWithCleanup(ctx, namespace, "service/auth-gateway", 80)
	gateway.adminAddr = env.ForwardWithCleanup(ctx, namespace, "deployment/auth-gateway", 9901)
	var warmupErr error
	Eventually(func() bool {
		status, body, err := gateway.request(ctx, apiKeyOnlyHost, false, http.MethodPost, "/ingest", apiKeyRequestBody, "", warmupKey, nil)
		if err != nil {
			warmupErr = err
			return false
		}
		if status != http.StatusOK {
			warmupErr = fmt.Errorf("HTTP %d: %s", status, body)
			return false
		}
		return true
	}).WithContext(ctx).WithTimeout(3*time.Minute).WithPolling(time.Second).Should(BeTrue(), func() string {
		return fmt.Sprintf("API-key ECDS warmup failed: %v", warmupErr)
	})
	return gateway, nil
}

func apiKeyConfig(namespace string, keyOnly bool) (config.Config, error) {
	fixture, err := env.Fixture("api-key-gateway.yaml")
	if err != nil {
		return config.Config{}, err
	}
	c, err := config.Load(bytes.NewReader(fixture))
	if err != nil {
		return config.Config{}, err
	}
	c.Kubernetes.Namespace = namespace
	if keyOnly {
		c.Authenticators = c.Authenticators[1:]
		c.AuthorizationPolicies = c.AuthorizationPolicies[1:]
		c.Servers = c.Servers[1:2]
		c.Kubernetes.HTTPSServicePort = nil
	} else {
		c.Authenticators[0].JWT.JWKS.URI = "https://jwks." + namespace + ".svc.cluster.local/issuer-one"
		c.Authenticators[0].JWT.JWKS.TrustedCA = jwtTrustedCA()
	}
	return c, nil
}

func (g *apiKeyE2E) applySecret(ctx context.Context, credentials []config.APIKeyCredential) error {
	key := g.config.Authenticators[len(g.config.Authenticators)-1]
	secret, err := config.APIKeySecret(g.config.Kubernetes.Namespace, key, credentials)
	if err != nil {
		return err
	}
	manifest, err := yaml.Marshal(secret)
	if err != nil {
		return err
	}
	return env.Apply(ctx, g.config.Kubernetes.Namespace, manifest)
}

func (g *apiKeyE2E) token(tenant, writer string) string {
	claims := map[string]any{
		"organization": map[string]any{"id": tenant},
		"sub":          writer,
		"aud":          "gateway-test",
		"exp":          time.Now().Add(5 * time.Minute).Unix(),
	}
	return (&jwtE2E{keys: g.keys}).token("issuer-one", claims, nil)
}

func (g *apiKeyE2E) request(ctx context.Context, host string, useTLS bool, method, requestPath, body, token, key string, headers http.Header) (int, []byte, error) {
	scheme, address, client := "http", g.httpAddr, testClient
	var err error
	if useTLS {
		scheme = "https"
		var stop func()
		address, stop, err = env.Forward(ctx, g.config.Kubernetes.Namespace, "service/auth-gateway", 443)
		if err != nil {
			return 0, nil, err
		}
		defer stop()
		transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: g.rootCAs, ServerName: host, MinVersion: tls.VersionTLS12}}
		defer transport.CloseIdleConnections()
		client = &http.Client{Transport: transport, Timeout: 10 * time.Second}
	}
	request, err := http.NewRequestWithContext(ctx, method, scheme+"://"+address+requestPath, strings.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	request.Host = host
	request.Header = headers.Clone()
	if request.Header == nil {
		request.Header = make(http.Header)
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if key != "" {
		request.Header.Set("X-Partner-Key", key)
	}
	if body != "" {
		request.Header.Set("Content-Type", "application/octet-stream")
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, nil, err
	}
	responseBody, err := readAndCloseResponseBody(response, 1<<20)
	return response.StatusCode, responseBody, err
}

func expectAPIKeyDenied(ctx SpecContext, gateway *apiKeyE2E, name, host string, useTLS bool, token, key string, headers http.Header, wantStatus int) {
	before, err := jwtUpstreamRequests(ctx, gateway.adminAddr, "api-ingest")
	Expect(err).NotTo(HaveOccurred(), name)
	status, body, err := gateway.request(ctx, host, useTLS, http.MethodPost, "/ingest", apiKeyRequestBody, token, key, headers)
	Expect(err).NotTo(HaveOccurred(), name)
	Expect(status).To(Equal(wantStatus), name+": "+string(body))
	after, err := jwtUpstreamRequests(ctx, gateway.adminAddr, "api-ingest")
	Expect(err).NotTo(HaveOccurred(), name)
	Expect(after).To(Equal(before), name+" reached the backend")
}

func envoyUpdateFailures(ctx context.Context, adminAddress string) (uint64, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+adminAddress+"/stats?filter=update_", nil)
	if err != nil {
		return 0, err
	}
	response, err := testClient.Do(request)
	if err != nil {
		return 0, err
	}
	body, err := readAndCloseResponseBody(response, 1<<20)
	if err != nil {
		return 0, err
	}
	if response.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("Envoy stats returned HTTP %d: %s", response.StatusCode, body)
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

func expectAPIKeyEcho(body []byte, tenant, writer string) {
	var echo struct {
		Method  string              `json:"method"`
		URL     string              `json:"url"`
		Data    string              `json:"data"`
		Headers map[string][]string `json:"headers"`
	}
	Expect(json.Unmarshal(body, &echo)).To(Succeed())
	Expect(echo.Method).To(Equal(http.MethodPost))
	Expect(echo.URL).To(HaveSuffix("/anything"))
	Expect(echo.Data).To(Equal("data:application/octet-stream;base64," + base64.StdEncoding.EncodeToString([]byte(apiKeyRequestBody))))
	Expect(headerValue(echo.Headers, "X-Scope-OrgID")).To(Equal(tenant))
	Expect(headerValue(echo.Headers, "X-Writer-ID")).To(Equal(writer))
	for _, name := range []string{"Authorization", "X-Partner-Key", "X-Auth-Gateway-API-Key-Client", "X-Auth-Gateway-JWT-Verified-Issuer-One"} {
		Expect(headerValue(echo.Headers, name)).To(BeEmpty(), name+" leaked to the upstream")
	}
}
