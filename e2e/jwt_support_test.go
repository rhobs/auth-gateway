//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"sort"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	"github.com/rhobs/auth-gateway/config"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/yaml"
)

const (
	jwtPlainHost          = "plain.jwt.auth-gateway.test"
	jwtPlainNoPolicyHost  = "no-policy.jwt.auth-gateway.test"
	jwtPlainAnyPolicyHost = "any-policy.jwt.auth-gateway.test"
	jwtPlainAllPolicyHost = "all-policy.jwt.auth-gateway.test"
	jwtHeadersHost        = "headers.jwt.auth-gateway.test"
	jwtManagedHeaderHost  = "managed.jwt.auth-gateway.test"
	jwtHTTPHost           = "writer.jwt.auth-gateway.test"
	jwtHTTPSHost          = "writer-tls.jwt.auth-gateway.test"
	jwtIssuerOneHost      = "issuer-one-only.jwt.auth-gateway.test"
)

var (
	jwtPlainNamespace   = e2eNamespace("auth-gateway-jwt-plain-e2e")
	jwtHeadersNamespace = e2eNamespace("auth-gateway-jwt-headers-e2e")
	jwtNamespace        = e2eNamespace("auth-gateway-jwt-e2e")
)

type jwtE2E struct {
	keys        map[string]*rsa.PrivateKey
	wrongKey    *rsa.PrivateKey
	rootCAs     *x509.CertPool
	httpAddr    string
	httpsAddr   string
	adminAddr   string
	metricsAddr string
	certs       *jwtTestCertificates
	resources   *config.KubernetesResources
}

var (
	jwtPlainGateway   *jwtE2E
	jwtHeadersGateway *jwtE2E
	jwtGateway        *jwtE2E
)

func jwtTrustedCA() *config.TrustedCA {
	return &config.TrustedCA{ConfigMap: &config.CAConfigMap{Name: "jwt-jwks-ca", Key: "ca.pem"}}
}

func setupJWTGateway(ctx SpecContext, namespace, fixtureName string) (*jwtE2E, error) {
	if err := resetE2ENamespace(ctx, namespace); err != nil {
		return nil, err
	}

	keys := map[string]*rsa.PrivateKey{}
	for _, name := range []string{"issuer-one", "issuer-two"} {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		keys[name] = key
	}
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	certificates, err := makeJWTTestCertificates([]string{"jwks." + namespace + ".svc.cluster.local", jwtHTTPSHost})
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificates.root)

	issuerManifest, err := jwtIssuerManifest(namespace, certificates, keys)
	if err != nil {
		return nil, err
	}
	if err := env.Apply(ctx, namespace, issuerManifest); err != nil {
		return nil, err
	}
	if err := env.WaitForDeployment(ctx, namespace, "jwt-jwks", 4*time.Minute); err != nil {
		return nil, err
	}

	backend, err := env.Fixture("httpbin.yaml")
	if err != nil {
		return nil, err
	}
	if err := env.Apply(ctx, namespace, backend); err != nil {
		return nil, err
	}

	fixture, err := env.Fixture(fixtureName)
	if err != nil {
		return nil, err
	}
	gatewayConfig, err := config.Load(bytes.NewReader(fixture))
	if err != nil {
		return nil, err
	}
	gatewayConfig.Kubernetes.Namespace = namespace
	for i := range gatewayConfig.Authenticators {
		gatewayConfig.Authenticators[i].JWT.JWKS.URI = "https://jwks." + namespace + ".svc.cluster.local/" + gatewayConfig.Authenticators[i].Name
		gatewayConfig.Authenticators[i].JWT.JWKS.TrustedCA = jwtTrustedCA()
	}
	resources, err := config.GenerateKubernetes(gatewayConfig)
	if err != nil {
		return nil, err
	}
	hasHTTPS := false
	for _, server := range gatewayConfig.Servers {
		if server.TLSConfig != nil {
			hasHTTPS = true
			break
		}
	}
	if hasHTTPS {
		serverTLS := &corev1.Secret{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: metav1.ObjectMeta{Name: "jwt-gateway-tls", Namespace: namespace}, Type: corev1.SecretTypeTLS, Data: map[string][]byte{corev1.TLSCertKey: certificates.chainPEM, corev1.TLSPrivateKeyKey: certificates.keyPEM}}
		serverTLSManifest, err := yaml.Marshal(serverTLS)
		if err != nil {
			return nil, err
		}
		if err := env.Apply(ctx, namespace, serverTLSManifest); err != nil {
			return nil, err
		}
	}
	caConfigMap := &corev1.ConfigMap{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}, ObjectMeta: metav1.ObjectMeta{Name: "jwt-jwks-ca", Namespace: namespace}, Data: map[string]string{"ca.pem": string(certificates.caPEM)}}
	manifest, err := resources.YAML()
	if err != nil {
		return nil, err
	}
	caYAML, err := yaml.Marshal(caConfigMap)
	if err != nil {
		return nil, err
	}
	if err := env.Apply(ctx, namespace, caYAML); err != nil {
		return nil, err
	}
	if err := env.Apply(ctx, namespace, manifest); err != nil {
		return nil, err
	}
	if err := env.WaitForDeployment(ctx, namespace, "httpbin", 4*time.Minute); err != nil {
		return nil, err
	}
	if err := env.WaitForDeployment(ctx, namespace, "auth-gateway", 4*time.Minute); err != nil {
		return nil, err
	}
	httpAddress := env.ForwardWithCleanup(ctx, namespace, "service/auth-gateway", 80)
	var httpsAddress string
	if hasHTTPS {
		httpsAddress = env.ForwardWithCleanup(ctx, namespace, "service/auth-gateway", 443)
	}
	warmupClaims := jwtTestClaims("customer-a")
	if fixtureName == "jwt-auth.yaml" {
		warmupClaims["x"] = map[string]any{"my_list": []string{"y", "z"}}
	}
	warmupClaims["sub"] = "warmup"
	warmupToken := (&jwtE2E{keys: keys}).token("issuer-one", warmupClaims, nil)
	warmupHost := gatewayConfig.Servers[0].Hostname
	if err := waitForSuccessfulRequest(ctx, "JWT gateway", 30*time.Second, 250*time.Millisecond, func(ctx context.Context) error {
		status, body, err := (&jwtE2E{keys: keys, rootCAs: roots, httpAddr: httpAddress}).request(ctx, httpAddress, warmupHost, false, warmupToken, false)
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return fmt.Errorf("warmup returned HTTP %d: %s", status, body)
		}
		return nil
	}); err != nil {
		env.Diagnostics(namespace)
		return nil, fmt.Errorf("warm up JWT gateway: %w", err)
	}
	return &jwtE2E{
		keys: keys, wrongKey: wrongKey, rootCAs: roots, httpAddr: httpAddress, httpsAddr: httpsAddress,
		certs: certificates, resources: resources,
	}, nil
}

type jwtTestCertificates struct {
	root                    *x509.Certificate
	caPEM, chainPEM, keyPEM []byte
}

func makeJWTTestCertificates(dnsNames []string) (*jwtTestCertificates, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: "auth-gateway JWT e2e CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	root, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serverTemplate := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano() + 1), Subject: pkix.Name{CommonName: dnsNames[0]}, DNSNames: dnsNames, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(12 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, root, &serverKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		return nil, err
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	chainPEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}), caPEM...)
	return &jwtTestCertificates{root: root, caPEM: caPEM, chainPEM: chainPEM, keyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})}, nil
}

func jwtIssuerManifest(namespace string, certificates *jwtTestCertificates, keys map[string]*rsa.PrivateKey) ([]byte, error) {
	issuerOneJWKS, err := jwtSetBytes(keys, "issuer-one")
	if err != nil {
		return nil, err
	}
	issuerTwoJWKS, err := jwtSetBytes(keys, "issuer-two")
	if err != nil {
		return nil, err
	}
	envoyConfig := `node: {id: jwt-jwks, cluster: jwt-jwks}
static_resources:
  listeners:
    - name: jwks
      address:
        socket_address: {address: 0.0.0.0, port_value: 8443}
      filter_chains:
        - transport_socket:
            name: envoy.transport_sockets.tls
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
              common_tls_context:
                tls_certificates:
                  - certificate_chain: {filename: /etc/jwks-tls/tls.crt}
                    private_key: {filename: /etc/jwks-tls/tls.key}
          filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: jwks
                route_config:
                  name: jwks
                  virtual_hosts:
                    - name: jwks
                      domains: ["*"]
                      routes:
                        - match: {prefix: /issuer-one}
                          direct_response:
                            status: 200
                            body: {filename: /etc/jwks/issuer-one.json}
                        - match: {prefix: /issuer-two}
                          direct_response:
                            status: 200
                            body: {filename: /etc/jwks/issuer-two.json}
                        - match: {prefix: /}
                          direct_response: {status: 404}
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
`
	labels := map[string]string{"app": "jwt-jwks"}
	configMap := &corev1.ConfigMap{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}, ObjectMeta: metav1.ObjectMeta{Name: "jwt-jwks-config", Namespace: namespace}, Data: map[string]string{"envoy.yaml": envoyConfig, "issuer-one.json": string(issuerOneJWKS), "issuer-two.json": string(issuerTwoJWKS)}}
	secret := &corev1.Secret{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: metav1.ObjectMeta{Name: "jwt-jwks-tls", Namespace: namespace}, Type: corev1.SecretTypeTLS, Data: map[string][]byte{corev1.TLSCertKey: certificates.chainPEM, corev1.TLSPrivateKeyKey: certificates.keyPEM}}
	container := corev1.Container{
		Name: "envoy", Image: config.DefaultEnvoyImage,
		Args:  []string{"-c", "/etc/jwks/envoy.yaml", "--log-level", "error"},
		Ports: []corev1.ContainerPort{{Name: "https", ContainerPort: 8443}},
		VolumeMounts: []corev1.VolumeMount{
			{Name: "config", MountPath: "/etc/jwks", ReadOnly: true},
			{Name: "tls", MountPath: "/etc/jwks-tls", ReadOnly: true},
		},
	}
	volumes := []corev1.Volume{
		{Name: "config", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: configMap.Name}}}},
		{Name: "tls", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: secret.Name, Items: []corev1.KeyToPath{{Key: corev1.TLSCertKey, Path: "tls.crt"}, {Key: corev1.TLSPrivateKeyKey, Path: "tls.key"}}}}},
	}
	deployment := &appsv1.Deployment{
		TypeMeta:   metav1.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"},
		ObjectMeta: metav1.ObjectMeta{Name: "jwt-jwks", Namespace: namespace},
		Spec: appsv1.DeploymentSpec{
			Replicas: new(int32(1)), Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels}, Spec: corev1.PodSpec{Containers: []corev1.Container{container}, Volumes: volumes}},
		},
	}
	service := &corev1.Service{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Service"}, ObjectMeta: metav1.ObjectMeta{Name: "jwks", Namespace: namespace}, Spec: corev1.ServiceSpec{Selector: labels, Ports: []corev1.ServicePort{{Name: "https", Port: 443, TargetPort: intstr.FromInt(8443)}}}}
	return yamlDocuments(configMap, secret, deployment, service)
}

func jwtSetBytes(keys map[string]*rsa.PrivateKey, issuer string) ([]byte, error) {
	keyIDs := make([]string, 0, len(keys))
	for keyID := range keys {
		if strings.HasPrefix(keyID, issuer) {
			keyIDs = append(keyIDs, keyID)
		}
	}
	sort.Strings(keyIDs)
	publicKeys := make([]map[string]string, 0, len(keyIDs))
	for _, keyID := range keyIDs {
		key := keys[keyID]
		eBytes := big.NewInt(int64(key.PublicKey.E)).Bytes()
		publicKeys = append(publicKeys, map[string]string{"kty": "RSA", "kid": keyID, "use": "sig", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(eBytes)})
	}
	return json.Marshal(map[string]any{"keys": publicKeys})
}

func jwtTestClaims(tenant string) map[string]any {
	return map[string]any{
		"organization":  map[string]any{"id": tenant},
		"sub":           "writer-17",
		"literal.claim": `source "quoted" \ value`,
		"aud":           "gateway-test",
		"exp":           time.Now().Add(5 * time.Minute).Unix(),
	}
}

func (e *jwtE2E) token(issuer string, claims map[string]any, signingKey *rsa.PrivateKey) string {
	return e.tokenWithKeyID(issuer, issuer, claims, signingKey)
}

func (e *jwtE2E) tokenWithKeyID(issuer, keyID string, claims map[string]any, signingKey *rsa.PrivateKey) string {
	if signingKey == nil {
		signingKey = e.keys[issuer]
	}
	issuerURLs := map[string]string{"issuer-one": "https://issuer-one.jwt.test", "issuer-two": "https://issuer-two.jwt.test"}
	if _, exists := claims["iss"]; !exists {
		claims["iss"] = issuerURLs[issuer]
	}
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": keyID})
	payload, _ := json.Marshal(claims)
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(unsigned))
	signature, _ := rsa.SignPKCS1v15(rand.Reader, signingKey, crypto.SHA256, digest[:])
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func (e *jwtE2E) request(ctx context.Context, address, host string, useTLS bool, token string, spoof bool) (int, []byte, error) {
	return e.requestPath(ctx, address, host, useTLS, "/protected", token, spoof)
}

func (e *jwtE2E) requestPath(ctx context.Context, address, host string, useTLS bool, path, token string, spoof bool) (int, []byte, error) {
	return e.requestMethodPath(ctx, address, host, useTLS, http.MethodGet, path, token, spoof)
}

func (e *jwtE2E) requestMethodPath(ctx context.Context, address, host string, useTLS bool, method, path, token string, spoof bool) (int, []byte, error) {
	headers := make(http.Header)
	if spoof {
		headers.Add("X-Scope-OrgID", "spoofed")
		headers.Add("X-Scope-OrgID", "duplicate")
		headers.Set("X-Writer-ID", "spoofed")
	}
	return e.requestMethodPathHeaders(ctx, address, host, useTLS, method, path, token, headers)
}

func (e *jwtE2E) requestMethodPathHeaders(ctx context.Context, address, host string, useTLS bool, method, path, token string, headers http.Header) (int, []byte, error) {
	scheme, client := "http", testClient
	if useTLS {
		scheme = "https"
		client = newTestTLSClient(e.rootCAs, host)
		defer client.CloseIdleConnections()
	}
	request, err := http.NewRequestWithContext(ctx, method, scheme+"://"+address+path, nil)
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
	response, err := client.Do(request)
	if err != nil {
		return 0, nil, err
	}
	body, err := readAndCloseResponseBody(response, 1<<20)
	return response.StatusCode, body, err
}
