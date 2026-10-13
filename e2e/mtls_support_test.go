//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
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
	mtlsOnlyHost       = "cert.mtls.auth-gateway.test"
	mtlsMixedHost      = "mixed.mtls.auth-gateway.test"
	mtlsJWTCertHost    = "jwt-cert.mtls.auth-gateway.test"
	mtlsAllHost        = "all.mtls.auth-gateway.test"
	mtlsTrustHost      = "trust.mtls.auth-gateway.test"
	mtlsAllowedURI     = "spiffe://clients.example.test/client-a"
	mtlsSecondURI      = "spiffe://clients.example.test/client-b"
	mtlsDeniedURI      = "spiffe://clients.example.test/denied"
	mtlsPayload        = "mtls-e2e-payload"
	mtlsAllowedKey     = "mtls-key-a"
	mtlsDeniedKey      = "mtls-key-denied"
	mtlsClientCAName   = "gateway-client-ca"
	mtlsClientCAKey    = "ca.crt"
	mtlsGatewayTLSName = "mtls-gateway-tls"
)

type mtlsE2E struct {
	namespace string
	address   string
	adminAddr string
	roots     *x509.CertPool
	keys      map[string]*rsa.PrivateKey
	caA       *mtlsTestCA
	caB       *mtlsTestCA
	allowed   tls.Certificate
	denied    tls.Certificate
	noSAN     tls.Certificate
	multiURI  tls.Certificate
	multiDNS  tls.Certificate
	commaURI  tls.Certificate
	untrusted tls.Certificate
	rotated   tls.Certificate
}

type mtlsTestCA struct {
	certificate *x509.Certificate
	privateKey  *ecdsa.PrivateKey
	pem         []byte
}

func newMTLSTestCA() (*mtlsTestCA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: "auth-gateway mTLS e2e CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &mtlsTestCA{certificate: certificate, privateKey: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}, nil
}

func (ca *mtlsTestCA) clientCertificate(uriValues, dnsNames []string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	var uris []*url.URL
	for _, value := range uriValues {
		uri, err := url.Parse(value)
		if err != nil {
			return tls.Certificate{}, err
		}
		uris = append(uris, uri)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: "auth-gateway mTLS e2e client"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(12 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, DNSNames: dnsNames, URIs: uris,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, &key.PublicKey, ca.privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}),
	)
}

func setupMTLSGateway(ctx SpecContext, namespace string) (*mtlsE2E, error) {
	if err := resetE2ENamespace(ctx, namespace); err != nil {
		return nil, err
	}
	fixture, err := env.Fixture("mtls-gateway.yaml")
	if err != nil {
		return nil, err
	}
	c, err := config.Load(bytes.NewReader(fixture))
	if err != nil {
		return nil, err
	}
	c.Kubernetes.Namespace = namespace
	caA, err := newMTLSTestCA()
	if err != nil {
		return nil, err
	}
	caB, err := newMTLSTestCA()
	if err != nil {
		return nil, err
	}
	untrustedCA, err := newMTLSTestCA()
	if err != nil {
		return nil, err
	}
	gateway := &mtlsE2E{namespace: namespace, caA: caA, caB: caB}
	for _, entry := range []struct {
		ca   *mtlsTestCA
		uris []string
		dns  []string
		to   *tls.Certificate
	}{
		{caA, []string{mtlsAllowedURI}, []string{"client-a.example.test"}, &gateway.allowed},
		{caA, []string{mtlsDeniedURI}, []string{"denied.example.test"}, &gateway.denied},
		{caA, nil, nil, &gateway.noSAN},
		{caA, []string{mtlsAllowedURI, mtlsSecondURI}, []string{"client-a.example.test"}, &gateway.multiURI},
		{caA, []string{mtlsAllowedURI}, []string{"client-a.example.test", "client-b.example.test"}, &gateway.multiDNS},
		{caA, []string{"spiffe://clients.example.test/client,a"}, []string{"client-a.example.test"}, &gateway.commaURI},
		{untrustedCA, []string{mtlsAllowedURI}, []string{"client-a.example.test"}, &gateway.untrusted},
		{caB, []string{mtlsAllowedURI}, []string{"client-a.example.test"}, &gateway.rotated},
	} {
		*entry.to, err = entry.ca.clientCertificate(entry.uris, entry.dns)
		if err != nil {
			return nil, err
		}
	}

	gateway.keys = make(map[string]*rsa.PrivateKey)
	for _, name := range []string{"issuer-one", "issuer-two"} {
		gateway.keys[name], err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
	}
	serverNames := []string{"jwks." + namespace + ".svc.cluster.local", mtlsOnlyHost, mtlsMixedHost, mtlsJWTCertHost, mtlsAllHost, mtlsTrustHost}
	serverCertificates, err := makeJWTTestCertificates(serverNames)
	if err != nil {
		return nil, err
	}
	gateway.roots = x509.NewCertPool()
	gateway.roots.AddCert(serverCertificates.root)
	for index := range c.Authenticators {
		if c.Authenticators[index].JWT != nil {
			c.Authenticators[index].JWT.JWKS.URI = "https://jwks." + namespace + ".svc.cluster.local/" + c.Authenticators[index].Name
			c.Authenticators[index].JWT.JWKS.TrustedCA = jwtTrustedCA()
		}
	}
	issuer, err := jwtIssuerManifest(namespace, serverCertificates, gateway.keys)
	if err != nil {
		return nil, err
	}
	if err := env.Apply(ctx, namespace, issuer); err != nil {
		return nil, err
	}
	backend, err := env.Fixture("httpbin.yaml")
	if err != nil {
		return nil, err
	}
	if err := env.Apply(ctx, namespace, backend); err != nil {
		return nil, err
	}
	serverSecret := &corev1.Secret{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
		ObjectMeta: metav1.ObjectMeta{Name: mtlsGatewayTLSName, Namespace: namespace},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{corev1.TLSCertKey: serverCertificates.chainPEM, corev1.TLSPrivateKeyKey: serverCertificates.keyPEM},
	}
	issuerCA := &corev1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"},
		ObjectMeta: metav1.ObjectMeta{Name: "jwt-jwks-ca", Namespace: namespace},
		Data:       map[string]string{"ca.pem": string(serverCertificates.caPEM)},
	}
	clientCA := gateway.clientCAConfigMap(caA)
	prerequisites, err := yamlDocuments(serverSecret, issuerCA, clientCA)
	if err != nil {
		return nil, err
	}
	if err := env.Apply(ctx, namespace, prerequisites); err != nil {
		return nil, err
	}
	keyAuthenticator, found := findAPIKeyAuthenticator(c.Authenticators)
	if !found {
		return nil, fmt.Errorf("mTLS fixture has no API-key authenticator")
	}
	keySecret, err := config.APIKeySecret(namespace, keyAuthenticator, []config.APIKeyCredential{
		{Key: mtlsAllowedKey, Attributes: map[string]string{"tenant_id": mtlsAllowedURI}},
		{Key: mtlsDeniedKey, Attributes: map[string]string{"tenant_id": mtlsDeniedURI}},
	})
	if err != nil {
		return nil, err
	}
	keyManifest, err := yaml.Marshal(keySecret)
	if err != nil {
		return nil, err
	}
	if err := env.Apply(ctx, namespace, keyManifest); err != nil {
		return nil, err
	}
	resources, err := config.GenerateKubernetes(c)
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
	for _, deployment := range []string{"httpbin", "jwt-jwks", "auth-gateway"} {
		if err := env.WaitForDeployment(ctx, namespace, deployment, 4*time.Minute); err != nil {
			return nil, err
		}
	}
	address, stopForward, err := env.Forward(ctx, namespace, "service/auth-gateway", 443)
	if err != nil {
		return nil, err
	}
	defer stopForward()
	gateway.address = address
	gateway.adminAddr = env.ForwardEnvoyAdminWithCleanup(ctx, namespace)
	if err := waitForSuccessfulRequest(ctx, "mTLS gateway", 3*time.Minute, time.Second, func(ctx context.Context) error {
		status, body, err := gateway.request(ctx, mtlsOnlyHost, &gateway.allowed, "", "", http.MethodPost, "/ingest", mtlsPayload, mtlsRequestHeaders())
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

func (g *mtlsE2E) clientCAConfigMap(ca *mtlsTestCA) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"},
		ObjectMeta: metav1.ObjectMeta{Name: mtlsClientCAName, Namespace: g.namespace},
		Data:       map[string]string{mtlsClientCAKey: string(ca.pem)},
	}
}

func (g *mtlsE2E) applyClientCA(ctx context.Context, ca *mtlsTestCA) error {
	manifest, err := yaml.Marshal(g.clientCAConfigMap(ca))
	if err != nil {
		return err
	}
	return env.Apply(ctx, g.namespace, manifest)
}

func (g *mtlsE2E) token(tenant string) string {
	claims := map[string]any{
		"organization": map[string]any{"id": tenant},
		"aud":          "gateway-test",
		"exp":          time.Now().Add(5 * time.Minute).Unix(),
	}
	return (&jwtE2E{keys: g.keys}).token("issuer-one", claims, nil)
}

func mtlsRequestHeaders() http.Header {
	return http.Header{"X-Tenant": []string{"client-a"}, "X-Scope-OrgID": []string{"caller-controlled"}}
}

func (g *mtlsE2E) request(ctx context.Context, host string, certificate *tls.Certificate, token, key, method, requestPath, body string, headers http.Header) (int, []byte, error) {
	tlsConfig := &tls.Config{RootCAs: g.roots, ServerName: host, MinVersion: tls.VersionTLS12}
	if certificate != nil {
		tlsConfig.Certificates = []tls.Certificate{*certificate}
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: tlsConfig}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	request, err := http.NewRequestWithContext(ctx, method, "https://"+g.address+requestPath, strings.NewReader(body))
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

func expectMTLSEcho(body []byte, tenant string) {
	echo, err := decodeHTTPBinEcho(body)
	Expect(err).NotTo(HaveOccurred())
	Expect(echo.Method).To(Equal(http.MethodPost))
	Expect(echo.URL).To(HaveSuffix("/anything"))
	Expect(echo.Data).To(Equal("data:application/octet-stream;base64," + base64.StdEncoding.EncodeToString([]byte(mtlsPayload))))
	Expect(headerValue(echo.Headers, "Content-Type")).To(Equal("application/octet-stream"))
	Expect(headerValue(echo.Headers, "X-Scope-OrgID")).To(Equal(tenant))
	for _, name := range []string{
		"Authorization", "X-Partner-Key", "X-Auth-Gateway-API-Key-Client", "X-Auth-Gateway-JWT-Verified-Issuer-One",
		"X-Auth-Gateway-MTLS-Fingerprint", "X-Auth-Gateway-MTLS-URI-SAN", "X-Auth-Gateway-MTLS-DNS-SAN", "X-Auth-Gateway-MTLS-Authentication-Pending",
	} {
		Expect(headerValue(echo.Headers, name)).To(BeEmpty(), name+" leaked to the upstream")
	}
}
