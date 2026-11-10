//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"syscall"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	gatewayconfig "github.com/rhobs/auth-gateway/pkg/gateway"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

const (
	apiKeyPublicHost      = "public.api-key.auth-gateway.test"
	apiKeyOnlyHost        = "key.api-key.auth-gateway.test"
	apiKeySharedHost      = "shared.api-key.auth-gateway.test"
	apiKeyTLSHost         = "key-tls.api-key.auth-gateway.test"
	apiKeyRequestBody     = "api-key-payload"
	apiKeySharedSecretKey = "key-a"
)

var (
	apiKeyBehaviorNS   = e2eNamespace("auth-gateway-api-key-e2e")
	apiKeyProjectionNS = e2eNamespace("auth-gateway-api-key-projection-e2e")
	apiKeyIsolatedNS   = e2eNamespace("auth-gateway-api-key-isolated-e2e")
)

type apiKeyE2E struct {
	config    gatewayapi.Config
	keys      map[string]*rsa.PrivateKey
	rootCAs   *x509.CertPool
	httpAddr  string
	httpsAddr string
	httpsStop func()
	adminAddr string
	keyHeader string
	resources *gatewayconfig.KubernetesResources
}

func setupAPIKeyGateway(ctx SpecContext, namespace string, keyOnly bool, credentials []gatewayapi.APIKeyCredential, warmupKey string) (*apiKeyE2E, error) {
	return setupAPIKeyGatewayWithShape(ctx, namespace, keyOnly, credentials, warmupKey, nil)
}

func setupAPIKeyGatewayWithShape(ctx SpecContext, namespace string, keyOnly bool, credentials []gatewayapi.APIKeyCredential, warmupKey string, shape func(*gatewayapi.Config)) (*apiKeyE2E, error) {
	if err := resetE2ENamespace(ctx, namespace); err != nil {
		return nil, err
	}
	c, err := apiKeyConfig(namespace, keyOnly)
	if err != nil {
		return nil, err
	}
	if shape != nil {
		shape(&c)
	}
	keyAuthenticator, found := findAPIKeyAuthenticator(c.Authenticators)
	if !found {
		return nil, fmt.Errorf("API-key gateway configuration has no API-key authenticator")
	}
	keyHeader := keyAuthenticator.APIKey.Header
	if keyHeader == "" {
		keyHeader = "X-API-Key"
	}
	gateway := &apiKeyE2E{config: c, keyHeader: keyHeader}
	if !keyOnly {
		gateway.keys = make(map[string]*rsa.PrivateKey)
		for _, authenticator := range c.Authenticators {
			if authenticator.JWT == nil {
				continue
			}
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				return nil, err
			}
			gateway.keys[authenticator.Name] = key
		}
		certificates, err := makeJWTTestCertificates([]string{"jwks." + namespace + ".svc.cluster.local", apiKeyTLSHost})
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
	resources, err := gatewayconfig.GenerateKubernetes(c)
	if err != nil {
		return nil, err
	}
	manifest, err := resources.YAML()
	if err != nil {
		return nil, err
	}
	if err := env.Apply(ctx, namespace, manifest); err != nil {
		return nil, err
	}
	gateway.resources = resources
	for _, deployment := range []string{"httpbin", "auth-gateway"} {
		if err := env.WaitForDeployment(ctx, namespace, deployment, 4*time.Minute); err != nil {
			return nil, err
		}
	}
	gateway.httpAddr = env.ForwardWithCleanup(ctx, namespace, "service/auth-gateway", 80)
	for _, server := range c.Servers {
		if server.TLSConfig != nil {
			address, stop, err := env.Forward(ctx, namespace, "service/auth-gateway", 443)
			if err != nil {
				return nil, err
			}
			gateway.httpsAddr = address
			gateway.httpsStop = stop
			DeferCleanup(stop)
			break
		}
	}
	gateway.adminAddr = env.ForwardEnvoyAdminWithCleanup(ctx, namespace)
	if err := waitForSuccessfulRequest(ctx, "API-key ECDS warmup", 3*time.Minute, time.Second, func(ctx context.Context) error {
		status, body, err := gateway.request(ctx, apiKeyOnlyHost, false, http.MethodPost, "/ingest", apiKeyRequestBody, "", warmupKey, nil)
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return fmt.Errorf("HTTP %d: %s", status, body)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return gateway, nil
}

func baselineAPIKeyCredentials() []gatewayapi.APIKeyCredential {
	return []gatewayapi.APIKeyCredential{
		{Key: apiKeySharedSecretKey, Attributes: map[string]string{"tenant_id": "client-a", "writer_id": "writer-a"}},
		{Key: "key-denied", Attributes: map[string]string{"tenant_id": "denied", "writer_id": "writer-a"}},
	}
}

func apiKeyConfig(namespace string, keyOnly bool) (gatewayapi.Config, error) {
	fixture, err := env.Fixture("api-key-gateway.yaml")
	if err != nil {
		return gatewayapi.Config{}, err
	}
	c, err := gatewayconfig.Load(bytes.NewReader(fixture))
	if err != nil {
		return gatewayapi.Config{}, err
	}
	c.Kubernetes.Namespace = namespace
	if keyOnly {
		keyAuthenticators := make([]gatewayapi.Authenticator, 0, 1)
		for _, authenticator := range c.Authenticators {
			if authenticator.APIKey != nil {
				keyAuthenticators = append(keyAuthenticators, authenticator)
			}
		}
		c.Authenticators = keyAuthenticators
		c.Servers = c.Servers[1:2]
		c.Kubernetes.HTTPSServicePort = nil
	} else {
		for index := range c.Authenticators {
			authenticator := &c.Authenticators[index]
			if authenticator.JWT == nil {
				continue
			}
			authenticator.JWT.JWKS.URI = "https://jwks." + namespace + ".svc.cluster.local/" + authenticator.Name
			authenticator.JWT.JWKS.TrustedCA = jwtTrustedCA()
		}
	}
	return c, nil
}

func (g *apiKeyE2E) applySecret(ctx context.Context, credentials []gatewayapi.APIKeyCredential) error {
	key, found := findAPIKeyAuthenticator(g.config.Authenticators)
	if !found {
		return fmt.Errorf("API-key gateway configuration has no API-key authenticator")
	}
	secret, err := gatewayconfig.APIKeySecret(g.config.Kubernetes.Namespace, key, credentials)
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
	return g.tokenForIssuer("issuer-one", tenant, writer)
}

func (g *apiKeyE2E) tokenForIssuer(issuer, tenant, writer string) string {
	claims := map[string]any{
		"organization": map[string]any{"id": tenant},
		"sub":          writer,
		"aud":          "gateway-test",
		"exp":          time.Now().Add(5 * time.Minute).Unix(),
	}
	return (&jwtE2E{keys: g.keys}).token(issuer, claims, nil)
}

func findAPIKeyAuthenticator(authenticators []gatewayapi.Authenticator) (gatewayapi.Authenticator, bool) {
	for _, authenticator := range authenticators {
		if authenticator.APIKey != nil {
			return authenticator, true
		}
	}
	return gatewayapi.Authenticator{}, false
}

func (g *apiKeyE2E) request(ctx context.Context, host string, useTLS bool, method, requestPath, body, token, key string, headers http.Header) (int, []byte, error) {
	scheme, address, client := "http", g.httpAddr, testClient
	var tlsClient *http.Client
	if useTLS {
		scheme = "https"
		if g.httpsAddr == "" {
			return 0, nil, fmt.Errorf("HTTPS port-forward was not opened during gateway setup")
		}
		address = g.httpsAddr
		tlsClient = newTestTLSClient(g.rootCAs, host)
		defer tlsClient.CloseIdleConnections()
		client = tlsClient
	}
	newRequest := func(address string) (*http.Request, error) {
		request, err := http.NewRequestWithContext(ctx, method, scheme+"://"+address+requestPath, strings.NewReader(body))
		if err != nil {
			return nil, err
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
			request.Header.Set(g.keyHeader, key)
		}
		if body != "" {
			request.Header.Set("Content-Type", "application/octet-stream")
		}
		return request, nil
	}
	request, err := newRequest(address)
	if err != nil {
		return 0, nil, err
	}
	response, err := client.Do(request)
	if useTLS && errors.Is(err, syscall.ECONNREFUSED) {
		if err := g.refreshHTTPSForward(ctx); err != nil {
			return 0, nil, fmt.Errorf("reopen HTTPS port-forward after connection refusal: %w", err)
		}
		request, err = newRequest(g.httpsAddr)
		if err != nil {
			return 0, nil, err
		}
		response, err = client.Do(request)
	}
	if err != nil {
		return 0, nil, err
	}
	responseBody, err := readAndCloseResponseBody(response, 1<<20)
	return response.StatusCode, responseBody, err
}

func (g *apiKeyE2E) refreshHTTPSForward(ctx context.Context) error {
	if g.httpsStop != nil {
		g.httpsStop()
	}
	address, stop, err := env.Forward(ctx, g.config.Kubernetes.Namespace, "service/auth-gateway", 443)
	if err != nil {
		return err
	}
	g.httpsAddr = address
	g.httpsStop = stop
	DeferCleanup(stop)
	return nil
}

func expectAPIKeyDenied(ctx SpecContext, gateway *apiKeyE2E, name, host string, useTLS bool, token, key string, headers http.Header, wantStatus int) {
	expectDeniedBeforeUpstream(ctx, gateway.adminAddr, "api-ingest", name, wantStatus, func() (int, []byte, error) {
		return gateway.request(ctx, host, useTLS, http.MethodPost, "/ingest", apiKeyRequestBody, token, key, headers)
	})
}

func expectAPIKeyEcho(body []byte, tenant, writer string) {
	echo, err := decodeHTTPBinEcho(body)
	Expect(err).NotTo(HaveOccurred())
	Expect(echo.Method).To(Equal(http.MethodPost))
	Expect(echo.URL).To(HaveSuffix("/anything"))
	Expect(echo.Data).To(Equal("data:application/octet-stream;base64," + base64.StdEncoding.EncodeToString([]byte(apiKeyRequestBody))))
	Expect(headerValue(echo.Headers, "X-Scope-OrgID")).To(Equal(tenant))
	Expect(headerValue(echo.Headers, "X-Writer-ID")).To(Equal(writer))
	for _, name := range []string{"Authorization", "X-API-Key", "X-Partner-Key", "X-Auth-Gateway-API-Key-Client", "X-Auth-Gateway-JWT-Verified-Issuer-One", "X-Auth-Gateway-JWT-Verified-Issuer-Two"} {
		Expect(headerValue(echo.Headers, name)).To(BeEmpty(), name+" leaked to the upstream")
	}
}
