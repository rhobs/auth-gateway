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
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/rhobs/auth-gateway/config"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	utilwait "k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/yaml"
)

const (
	jwtPlainNamespace     = "auth-gateway-jwt-plain-e2e"
	jwtHeadersNamespace   = "auth-gateway-jwt-headers-e2e"
	jwtNamespace          = "auth-gateway-jwt-e2e"
	jwtLifecycleNamespace = "auth-gateway-jwt-lifecycle-e2e"
	jwtPlainHost          = "plain.jwt.auth-gateway.test"
	jwtHeadersHost        = "headers.jwt.auth-gateway.test"
	jwtHTTPHost           = "writer.jwt.auth-gateway.test"
	jwtHTTPSHost          = "writer-tls.jwt.auth-gateway.test"
	jwtIssuerOneHost      = "issuer-one-only.jwt.auth-gateway.test"
	jwtLifecycleHost      = "lifecycle.jwt.auth-gateway.test"
)

type jwtE2E struct {
	keys      map[string]*rsa.PrivateKey
	wrongKey  *rsa.PrivateKey
	rootCAs   *x509.CertPool
	httpAddr  string
	httpsAddr string
	certs     *jwtTestCertificates
	resources *config.KubernetesResources
}

var (
	jwtPlainGateway     *jwtE2E
	jwtHeadersGateway   *jwtE2E
	jwtGateway          *jwtE2E
	jwtLifecycleGateway *jwtE2E
)

var _ = Describe("Plain JWT authorization", Label("gateway", "jwt", "authentication", "authorization"), Ordered, func() {
	BeforeAll(func(ctx SpecContext) {
		DeferCleanup(func(ctx SpecContext) { Expect(env.DeleteNamespace(ctx, jwtPlainNamespace)).To(Succeed()) }, NodeTimeout(3*time.Minute))
		var err error
		jwtPlainGateway, err = setupJWTGateway(ctx, jwtPlainNamespace, "jwt-auth.yaml")
		Expect(err).NotTo(HaveOccurred())
	}, NodeTimeout(12*time.Minute))

	It("authorizes when any list member matches the grant", func(ctx SpecContext) {
		for _, test := range []struct {
			name   string
			values []string
		}{
			{name: "y member", values: []string{"y"}},
			{name: "z member", values: []string{"z"}},
			{name: "both members", values: []string{"y", "z"}},
		} {
			claims := map[string]any{
				"x":   map[string]any{"my_list": test.values},
				"aud": "gateway-test",
				"exp": time.Now().Add(5 * time.Minute).Unix(),
			}
			token := jwtPlainGateway.token("issuer-one", claims, nil)
			status, body, err := jwtPlainGateway.request(ctx, jwtPlainGateway.httpAddr, jwtPlainHost, false, token, false)
			Expect(err).NotTo(HaveOccurred(), test.name)
			Expect(status).To(Equal(http.StatusOK), test.name+": "+string(body))
			headers := jwtEchoHeaders(body)
			Expect(headers).NotTo(BeNil(), test.name)
			Expect(headerValue(headers, "Authorization")).To(BeEmpty(), test.name)
			Expect(headerValue(headers, "X-Scope-OrgID")).To(BeEmpty(), test.name)
		}
	}, SpecTimeout(12*time.Minute))

	It("rejects invalid credentials and denied claims before the upstream", func(ctx SpecContext) {
		adminAddress, stop, err := env.Forward(ctx, jwtPlainNamespace, "deployment/auth-gateway", 9901)
		Expect(err).NotTo(HaveOccurred())
		defer stop()

		allowed := map[string]any{"x": map[string]any{"my_list": []string{"y", "z"}}, "aud": "gateway-test", "exp": time.Now().Add(5 * time.Minute).Unix()}
		denied := map[string]any{"x": map[string]any{"my_list": []string{"unlisted"}}, "aud": "gateway-test", "exp": time.Now().Add(5 * time.Minute).Unix()}
		cases := []struct {
			name   string
			token  string
			status int
		}{
			{name: "missing token", status: http.StatusUnauthorized},
			{name: "invalid signature", token: jwtPlainGateway.token("issuer-one", allowed, jwtPlainGateway.wrongKey), status: http.StatusUnauthorized},
			{name: "denied claim", token: jwtPlainGateway.token("issuer-one", denied, nil), status: http.StatusForbidden},
		}
		for _, test := range cases {
			before, err := jwtUpstreamRequests(ctx, adminAddress, "api-metrics")
			Expect(err).NotTo(HaveOccurred(), test.name)
			status, body, err := jwtPlainGateway.request(ctx, jwtPlainGateway.httpAddr, jwtPlainHost, false, test.token, false)
			Expect(err).NotTo(HaveOccurred(), test.name)
			Expect(status).To(Equal(test.status), test.name+": "+string(body))
			after, err := jwtUpstreamRequests(ctx, adminAddress, "api-metrics")
			Expect(err).NotTo(HaveOccurred(), test.name)
			Expect(after).To(Equal(before), test.name+" reached the upstream")
		}
	}, NodeTimeout(60*time.Second))
})

var _ = Describe("Direct JWT headers", Label("gateway", "jwt", "authentication", "authorization"), Ordered, func() {
	BeforeAll(func(ctx SpecContext) {
		DeferCleanup(func(ctx SpecContext) { Expect(env.DeleteNamespace(ctx, jwtHeadersNamespace)).To(Succeed()) }, NodeTimeout(3*time.Minute))
		var err error
		jwtHeadersGateway, err = setupJWTGateway(ctx, jwtHeadersNamespace, "jwt-auth-with-headers.yaml")
		Expect(err).NotTo(HaveOccurred())
	}, NodeTimeout(12*time.Minute))

	It("replaces caller-supplied managed headers with verified values", func(ctx SpecContext) {
		claims := map[string]any{
			"organization": map[string]any{"id": "customer-a"},
			"sub":          "writer-17",
			"aud":          "gateway-test",
			"exp":          time.Now().Add(5 * time.Minute).Unix(),
		}
		token := jwtHeadersGateway.token("issuer-one", claims, nil)
		status, body, err := jwtHeadersGateway.request(ctx, jwtHeadersGateway.httpAddr, jwtHeadersHost, false, token, true)
		Expect(err).NotTo(HaveOccurred())
		Expect(status).To(Equal(http.StatusOK), string(body))
		headers := jwtEchoHeaders(body)
		Expect(headerValue(headers, "X-Scope-OrgID")).To(Equal("customer-a"))
		Expect(headerValue(headers, "X-Writer-ID")).To(Equal("writer-17"))
		Expect(headerValue(headers, "Authorization")).To(BeEmpty())
	}, SpecTimeout(12*time.Minute))

	It("rejects a missing required header attribute even when the caller supplies that header", func(ctx SpecContext) {
		adminAddress, stop, err := env.Forward(ctx, jwtHeadersNamespace, "deployment/auth-gateway", 9901)
		Expect(err).NotTo(HaveOccurred())
		defer stop()
		before, err := jwtUpstreamRequests(ctx, adminAddress, "api-metrics")
		Expect(err).NotTo(HaveOccurred())

		claims := map[string]any{
			"organization": map[string]any{"id": "customer-a"},
			"aud":          "gateway-test",
			"exp":          time.Now().Add(5 * time.Minute).Unix(),
		}
		token := jwtHeadersGateway.token("issuer-one", claims, nil)
		status, body, err := jwtHeadersGateway.request(ctx, jwtHeadersGateway.httpAddr, jwtHeadersHost, false, token, true)
		Expect(err).NotTo(HaveOccurred())
		Expect(status).To(Equal(http.StatusForbidden), string(body))
		after, err := jwtUpstreamRequests(ctx, adminAddress, "api-metrics")
		Expect(err).NotTo(HaveOccurred())
		Expect(after).To(Equal(before), "the missing verified header attribute reached the upstream")
	}, NodeTimeout(60*time.Second))
})

var _ = Describe("JWT access and identity processing", Label("gateway", "jwt", "authentication", "authorization"), Ordered, func() {
	BeforeAll(func(ctx SpecContext) {
		DeferCleanup(func(ctx SpecContext) { Expect(env.DeleteNamespace(ctx, jwtNamespace)).To(Succeed()) }, NodeTimeout(3*time.Minute))
		var err error
		jwtGateway, err = setupJWTGateway(ctx, jwtNamespace, "jwt-gateway.yaml")
		Expect(err).NotTo(HaveOccurred())
	}, NodeTimeout(12*time.Minute))

	It("authorizes original claims and sends processed attributes over HTTP and HTTPS", func(ctx SpecContext) {
		for _, target := range []struct {
			address string
			host    string
			tls     bool
		}{{jwtGateway.httpAddr, jwtHTTPHost, false}, {jwtGateway.httpsAddr, jwtHTTPSHost, true}} {
			for _, test := range []struct {
				issuer string
				tenant string
				team   string
			}{{"issuer-one", "customer-a", "team-a"}, {"issuer-two", "customer-b", "team-b"}} {
				claims := jwtTestClaims(test.tenant)
				claims["sub"] = "writer-17"
				token := jwtGateway.token(test.issuer, claims, nil)
				status, responseBody, err := jwtGateway.request(ctx, target.address, target.host, target.tls, token, true)
				Expect(err).NotTo(HaveOccurred())
				if status != http.StatusOK {
					writeTestOutput("valid %s request status=%d body=%s\n", test.issuer, status, responseBody)
					env.Diagnostics(jwtNamespace)
				}
				Expect(status).To(Equal(http.StatusOK), string(responseBody))
				var echo struct {
					Headers map[string][]string `json:"headers"`
				}
				Expect(json.Unmarshal(responseBody, &echo)).To(Succeed())
				Expect(headerValue(echo.Headers, "X-Scope-OrgID")).To(Equal(test.team))
				Expect(headerValue(echo.Headers, "X-Writer-ID")).To(Equal("writer-17"))
				Expect(headerValue(echo.Headers, "X-Chain")).To(Equal("second"), "one processor must perform one lookup")
				Expect(headerValue(echo.Headers, "X-Order")).To(Equal("final"), "later processors must consume earlier output")
				Expect(headerValue(echo.Headers, "X-Literal")).To(Equal(`mapped "quoted" \ value`))
				Expect(headerValue(echo.Headers, "Authorization")).To(BeEmpty())
			}
		}
		claims := jwtTestClaims("customer-a")
		delete(claims, "sub")
		delete(claims, "chain")
		delete(claims, "order")
		delete(claims, "literal.claim")
		token := jwtGateway.token("issuer-one", claims, nil)
		status, responseBody, err := jwtGateway.requestPath(ctx, jwtGateway.httpAddr, jwtHTTPHost, false, "/headerless", token, true)
		Expect(err).NotTo(HaveOccurred())
		Expect(status).To(Equal(http.StatusOK), string(responseBody))
		var echo struct {
			Headers map[string][]string `json:"headers"`
		}
		Expect(json.Unmarshal(responseBody, &echo)).To(Succeed())
		Expect(headerValue(echo.Headers, "X-Scope-OrgID")).To(BeEmpty())
		Expect(headerValue(echo.Headers, "X-Writer-ID")).To(BeEmpty())
		Expect(headerValue(echo.Headers, "Authorization")).To(BeEmpty())
	}, SpecTimeout(12*time.Minute))

	It("passes through authorized values without a mapping", func(ctx SpecContext) {
		claims := jwtTestClaims("customer-pass")
		token := jwtGateway.token("issuer-one", claims, nil)
		status, body, err := jwtGateway.request(ctx, jwtGateway.httpAddr, jwtHTTPHost, false, token, false)
		Expect(err).NotTo(HaveOccurred())
		Expect(status).To(Equal(http.StatusOK), string(body))
		Expect(headerValue(jwtEchoHeaders(body), "X-Scope-OrgID")).To(Equal("customer-pass"))
	}, NodeTimeout(60*time.Second))

	It("rejects invalid credentials, missing required attributes, and denied original claims", func(ctx SpecContext) {
		adminAddress, stop, err := env.Forward(ctx, jwtNamespace, "deployment/auth-gateway", 9901)
		Expect(err).NotTo(HaveOccurred())
		defer stop()

		issuerOne := func(claims map[string]any, key *rsa.PrivateKey) string {
			return jwtGateway.token("issuer-one", claims, key)
		}
		validClaims := func() map[string]any { return jwtTestClaims("customer-a") }
		missingExpiration := validClaims()
		delete(missingExpiration, "exp")
		expired := validClaims()
		expired["exp"] = time.Now().Add(-2 * time.Minute).Unix()
		wrongAudience := validClaims()
		wrongAudience["aud"] = "other-service"
		wrongIssuer := validClaims()
		wrongIssuer["iss"] = "https://unknown.jwt.test"
		unknownTenant := validClaims()
		unknownTenant["organization"].(map[string]any)["id"] = "unmapped-customer"
		deniedTenant := validClaims()
		deniedTenant["organization"].(map[string]any)["id"] = "customer-b"
		missingAuthorization := validClaims()
		delete(missingAuthorization["organization"].(map[string]any), "id")
		missingRequired := validClaims()
		delete(missingRequired, "sub")
		unsafeHeader := validClaims()
		unsafeHeader["sub"] = "writer-17\r\nInjected: yes"
		cases := []struct {
			name, token string
			status      int
		}{
			{name: "missing bearer", status: http.StatusUnauthorized},
			{name: "malformed bearer", token: "not-a-jwt", status: http.StatusUnauthorized},
			{name: "wrong signature", token: issuerOne(validClaims(), jwtGateway.wrongKey), status: http.StatusUnauthorized},
			{name: "wrong issuer", token: issuerOne(wrongIssuer, nil), status: http.StatusUnauthorized},
			// Envoy 1.39.1 rejects a validly signed token with an untrusted audience as 403.
			{name: "wrong audience", token: issuerOne(wrongAudience, nil), status: http.StatusForbidden},
			{name: "expired", token: issuerOne(expired, nil), status: http.StatusUnauthorized},
			{name: "missing expiration", token: issuerOne(missingExpiration, nil), status: http.StatusUnauthorized},
			{name: "tenant claim has no grant", token: issuerOne(unknownTenant, nil), status: http.StatusForbidden},
			{name: "another issuer's grant cannot be borrowed", token: issuerOne(deniedTenant, nil), status: http.StatusForbidden},
			{name: "missing authorization claim", token: issuerOne(missingAuthorization, nil), status: http.StatusForbidden},
			{name: "required header attribute is missing", token: issuerOne(missingRequired, nil), status: http.StatusForbidden},
			{name: "required header attribute is unsafe", token: issuerOne(unsafeHeader, nil), status: http.StatusForbidden},
		}
		for _, test := range cases {
			before, err := jwtUpstreamRequests(ctx, adminAddress, "api-metrics")
			Expect(err).NotTo(HaveOccurred(), test.name)
			status, body, err := jwtGateway.request(ctx, jwtGateway.httpAddr, jwtHTTPHost, false, test.token, false)
			Expect(err).NotTo(HaveOccurred(), test.name)
			if status != test.status {
				writeTestOutput("%s response status=%d body=%s\n", test.name, status, body)
				env.Diagnostics(jwtNamespace)
			}
			Expect(status).To(Equal(test.status), test.name+": "+string(body))
			after, err := jwtUpstreamRequests(ctx, adminAddress, "api-metrics")
			Expect(err).NotTo(HaveOccurred(), test.name)
			Expect(after).To(Equal(before), test.name+" reached the upstream")
		}
	}, NodeTimeout(60*time.Second))

	It("isolates JWT issuers by server", func(ctx SpecContext) {
		for _, test := range []struct {
			issuer, tenant, host string
			status               int
		}{{"issuer-two", "customer-a", jwtHTTPHost, http.StatusForbidden}, {"issuer-two", "customer-b", jwtIssuerOneHost, http.StatusUnauthorized}} {
			claims := jwtTestClaims(test.tenant)
			token := jwtGateway.token(test.issuer, claims, nil)
			status, body, err := jwtGateway.request(ctx, jwtGateway.httpAddr, test.host, false, token, false)
			Expect(err).NotTo(HaveOccurred())
			Expect(status).To(Equal(test.status), test.issuer+" at "+test.host+": "+string(body))
		}
	}, NodeTimeout(60*time.Second))

	It("reloads mapping changes through ECDS without changing authorization or the Pod", func(ctx SpecContext) {
		claims := jwtTestClaims("customer-a")
		claims["sub"] = "writer-17"
		token := jwtGateway.token("issuer-one", claims, nil)
		status, body, err := jwtGateway.request(ctx, jwtGateway.httpAddr, jwtHTTPHost, false, token, false)
		Expect(err).NotTo(HaveOccurred())
		Expect(status).To(Equal(http.StatusOK), "original identity mapping should be authorized: "+string(body))

		selector := "app.kubernetes.io/name=auth-gateway"
		oldUID, err := env.PodUID(ctx, jwtNamespace, selector)
		Expect(err).NotTo(HaveOccurred())

		fixture, err := env.Fixture("jwt-gateway.yaml")
		Expect(err).NotTo(HaveOccurred())
		updatedConfig, err := config.Load(bytes.NewReader(fixture))
		Expect(err).NotTo(HaveOccurred())
		updatedConfig.Kubernetes.Namespace = jwtNamespace
		for i := range updatedConfig.Authenticators {
			updatedConfig.Authenticators[i].JWT.JWKS.URI = "https://jwks." + jwtNamespace + ".svc.cluster.local/" + updatedConfig.Authenticators[i].Name
			updatedConfig.Authenticators[i].JWT.JWKS.TrustedCA = jwtTrustedCA()
		}
		updatedConfig.Processing[0].Attributes["tenant_id"].Mappings["customer-a"] = "team-b"
		updatedResources, err := config.GenerateKubernetes(updatedConfig)
		Expect(err).NotTo(HaveOccurred())
		Expect(updatedResources.ConfigMap.Data).To(Equal(jwtGateway.resources.ConfigMap.Data), "mapping changes must not alter the Envoy bootstrap ConfigMap")
		Expect(updatedResources.ProcessingConfigMap).NotTo(BeNil())
		Expect(updatedResources.ProcessingConfigMap.Data["processing.yaml"]).NotTo(Equal(jwtGateway.resources.ProcessingConfigMap.Data["processing.yaml"]))
		manifest, err := yamlDocuments(updatedResources.ProcessingConfigMap)
		Expect(err).NotTo(HaveOccurred())
		Expect(env.Apply(ctx, jwtNamespace, manifest)).To(Succeed())

		Eventually(func() bool {
			status, body, err = jwtGateway.request(ctx, jwtGateway.httpAddr, jwtHTTPHost, false, token, false)
			return err == nil && status == http.StatusOK && headerValue(jwtEchoHeaders(body), "X-Scope-OrgID") == "team-b"
		}).WithContext(ctx).WithTimeout(3*time.Minute).WithPolling(time.Second).Should(BeTrue(), func() string {
			return fmt.Sprintf("ECDS mapping update did not change the output while preserving authorization: status=%d body=%s error=%v", status, body, err)
		})
		newUID, err := env.PodUID(ctx, jwtNamespace, selector)
		Expect(err).NotTo(HaveOccurred())
		Expect(newUID).To(Equal(oldUID), "an ECDS processing update must not replace the gateway Pod")
	}, SpecTimeout(6*time.Minute))
})

var _ = Describe("JWT JWKS lifecycle", Label("gateway", "jwt", "jwks"), Ordered, func() {
	BeforeAll(func(ctx SpecContext) {
		DeferCleanup(func(ctx SpecContext) { Expect(env.DeleteNamespace(ctx, jwtLifecycleNamespace)).To(Succeed()) }, NodeTimeout(3*time.Minute))
		var err error
		jwtLifecycleGateway, err = setupJWTGateway(ctx, jwtLifecycleNamespace, "jwt-jwks-lifecycle.yaml")
		Expect(err).NotTo(HaveOccurred())
	}, NodeTimeout(12*time.Minute))

	It("rotates keys without restarting the gateway and isolates a failing issuer", func(ctx SpecContext) {
		claims := func(tenant string) map[string]any {
			return jwtTestClaims(tenant)
		}
		issuerOneToken := jwtLifecycleGateway.token("issuer-one", claims("customer-a"), nil)
		issuerTwoToken := jwtLifecycleGateway.token("issuer-two", claims("customer-b"), nil)
		for _, test := range []struct{ issuer, token string }{{"issuer-one", issuerOneToken}, {"issuer-two", issuerTwoToken}} {
			status, body, err := jwtLifecycleGateway.request(ctx, jwtLifecycleGateway.httpAddr, jwtLifecycleHost, false, test.token, false)
			Expect(err).NotTo(HaveOccurred(), test.issuer)
			Expect(status).To(Equal(http.StatusOK), test.issuer+": "+string(body))
		}

		selector := "app.kubernetes.io/name=auth-gateway"
		gatewayUID, err := env.PodUID(ctx, jwtLifecycleNamespace, selector)
		Expect(err).NotTo(HaveOccurred())
		nextKey, err := rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).NotTo(HaveOccurred())
		rotatedKeys := make(map[string]*rsa.PrivateKey, len(jwtLifecycleGateway.keys)+1)
		for name, key := range jwtLifecycleGateway.keys {
			rotatedKeys[name] = key
		}
		rotatedKeys["issuer-one-next"] = nextKey
		Expect(updateJWTJWKSServer(ctx, jwtLifecycleNamespace, jwtLifecycleGateway.certs, rotatedKeys, map[string]int{"issuer-two": http.StatusServiceUnavailable}, "rotation-1")).To(Succeed())

		currentUID, err := env.PodUID(ctx, jwtLifecycleNamespace, selector)
		Expect(err).NotTo(HaveOccurred())
		Expect(currentUID).To(Equal(gatewayUID), "JWKS rotation must not restart the gateway")

		// The warm issuer-two cache remains usable while that JWKS path is unavailable.
		status, body, err := jwtLifecycleGateway.request(ctx, jwtLifecycleGateway.httpAddr, jwtLifecycleHost, false, issuerTwoToken, false)
		Expect(err).NotTo(HaveOccurred())
		Expect(status).To(Equal(http.StatusOK), string(body))

		rotatedToken := jwtLifecycleGateway.tokenWithKeyID("issuer-one", "issuer-one-next", claims("customer-a"), nextKey)
		var rotatedStatus int
		var rotatedBody []byte
		Eventually(func() bool {
			rotatedStatus, rotatedBody, err = jwtLifecycleGateway.request(ctx, jwtLifecycleGateway.httpAddr, jwtLifecycleHost, false, rotatedToken, false)
			return err == nil && rotatedStatus == http.StatusOK
		}).WithContext(ctx).WithTimeout(30*time.Second).WithPolling(250*time.Millisecond).Should(BeTrue(), func() string {
			return fmt.Sprintf("rotated token returned HTTP %d: %s (error: %v)", rotatedStatus, rotatedBody, err)
		})

		// A new gateway pod has a cold JWKS cache. The unhealthy issuer fails,
		// while the healthy issuer fetches the rotated key and remains available.
		Expect(env.RestartDeployment(ctx, jwtLifecycleNamespace, "auth-gateway", 4*time.Minute)).To(Succeed())
		var coldGatewayUID string
		Eventually(func() bool {
			coldGatewayUID, err = env.PodUID(ctx, jwtLifecycleNamespace, selector)
			return err == nil && coldGatewayUID != ""
		}).WithContext(ctx).WithTimeout(time.Minute).WithPolling(250*time.Millisecond).Should(BeTrue(), func() string {
			return fmt.Sprintf("wait for replacement gateway pod: %v", err)
		})
		Expect(coldGatewayUID).NotTo(Equal(gatewayUID))
		jwtLifecycleGateway.httpAddr = env.ForwardWithCleanup(ctx, jwtLifecycleNamespace, "service/auth-gateway", 80)
		status, body, err = jwtLifecycleGateway.request(ctx, jwtLifecycleGateway.httpAddr, jwtLifecycleHost, false, rotatedToken, false)
		Expect(err).NotTo(HaveOccurred())
		Expect(status).To(Equal(http.StatusOK), "healthy issuer: "+string(body))
		status, body, err = jwtLifecycleGateway.request(ctx, jwtLifecycleGateway.httpAddr, jwtLifecycleHost, false, issuerTwoToken, false)
		Expect(err).NotTo(HaveOccurred())
		Expect(status).To(BeNumerically(">=", http.StatusBadRequest), "unavailable issuer returned: "+string(body))

		Expect(updateJWTJWKSServer(ctx, jwtLifecycleNamespace, jwtLifecycleGateway.certs, rotatedKeys, nil, "rotation-2")).To(Succeed())
		var recoveredStatus int
		var recoveredBody []byte
		Eventually(func() bool {
			recoveredStatus, recoveredBody, err = jwtLifecycleGateway.request(ctx, jwtLifecycleGateway.httpAddr, jwtLifecycleHost, false, issuerTwoToken, false)
			return err == nil && recoveredStatus == http.StatusOK
		}).WithContext(ctx).WithTimeout(30*time.Second).WithPolling(250*time.Millisecond).Should(BeTrue(), func() string {
			return fmt.Sprintf("recovered issuer returned HTTP %d: %s (error: %v)", recoveredStatus, recoveredBody, err)
		})
		finalUID, err := env.PodUID(ctx, jwtLifecycleNamespace, selector)
		Expect(err).NotTo(HaveOccurred())
		Expect(finalUID).To(Equal(coldGatewayUID), "restoring JWKS should not restart the gateway")
	}, SpecTimeout(12*time.Minute))
})

func jwtTrustedCA() *config.TrustedCA {
	return &config.TrustedCA{ConfigMap: &config.CAConfigMap{Name: "jwt-jwks-ca", Key: "ca.pem"}}
}

func setupJWTGateway(ctx SpecContext, namespace, fixtureName string) (*jwtE2E, error) {
	activeNamespace = namespace
	if err := env.DeleteNamespace(ctx, namespace); err != nil {
		return nil, err
	}
	if err := env.CreateNamespace(ctx, namespace); err != nil {
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
	var warmupErr error
	if err := utilwait.PollUntilContextTimeout(ctx, 250*time.Millisecond, 30*time.Second, true, func(ctx context.Context) (bool, error) {
		status, body, requestErr := (&jwtE2E{keys: keys, rootCAs: roots, httpAddr: httpAddress}).request(ctx, httpAddress, warmupHost, false, warmupToken, false)
		if requestErr != nil {
			warmupErr = requestErr
			return false, nil
		}
		if status != http.StatusOK {
			warmupErr = fmt.Errorf("warmup returned HTTP %d: %s", status, body)
			return false, nil
		}
		return true, nil
	}); err != nil {
		env.Diagnostics(namespace)
		return nil, fmt.Errorf("warm up JWT gateway: %w (last attempt: %v)", err, warmupErr)
	}
	rootCAs = roots
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
	return jwtIssuerManifestWithState(namespace, certificates, keys, nil, "")
}

func jwtIssuerManifestWithState(namespace string, certificates *jwtTestCertificates, keys map[string]*rsa.PrivateKey, statuses map[string]int, revision string) ([]byte, error) {
	issuerOneJWKS, err := jwtSetBytes(keys, "issuer-one")
	if err != nil {
		return nil, err
	}
	issuerTwoJWKS, err := jwtSetBytes(keys, "issuer-two")
	if err != nil {
		return nil, err
	}
	statusFor := func(issuer string) int {
		if status, exists := statuses[issuer]; exists {
			return status
		}
		return http.StatusOK
	}
	envoyConfig := fmt.Sprintf(`node: {id: jwt-jwks, cluster: jwt-jwks}
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
                            status: %d
                            body: {filename: /etc/jwks/issuer-one.json}
                        - match: {prefix: /issuer-two}
                          direct_response:
                            status: %d
                            body: {filename: /etc/jwks/issuer-two.json}
                        - match: {prefix: /}
                          direct_response: {status: 404}
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router

`, statusFor("issuer-one"), statusFor("issuer-two"))
	labels := map[string]string{"app": "jwt-jwks"}
	configMap := &corev1.ConfigMap{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}, ObjectMeta: metav1.ObjectMeta{Name: "jwt-jwks-config", Namespace: namespace}, Data: map[string]string{"envoy.yaml": envoyConfig, "issuer-one.json": string(issuerOneJWKS), "issuer-two.json": string(issuerTwoJWKS)}}
	secret := &corev1.Secret{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: metav1.ObjectMeta{Name: "jwt-jwks-tls", Namespace: namespace}, Type: corev1.SecretTypeTLS, Data: map[string][]byte{corev1.TLSCertKey: certificates.chainPEM, corev1.TLSPrivateKeyKey: certificates.keyPEM}}
	container := corev1.Container{
		Name: "envoy", Image: "envoyproxy/envoy:v1.39.1",
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
			Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels, Annotations: map[string]string{}}, Spec: corev1.PodSpec{Containers: []corev1.Container{container}, Volumes: volumes}},
		},
	}
	if revision != "" {
		deployment.Spec.Template.Annotations["auth-gateway.test/jwks-revision"] = revision
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

func updateJWTJWKSServer(ctx context.Context, namespace string, certificates *jwtTestCertificates, keys map[string]*rsa.PrivateKey, statuses map[string]int, revision string) error {
	manifest, err := jwtIssuerManifestWithState(namespace, certificates, keys, statuses, revision)
	if err != nil {
		return err
	}
	if err := env.Apply(ctx, namespace, manifest); err != nil {
		return err
	}
	return env.WaitForDeployment(ctx, namespace, "jwt-jwks", 4*time.Minute)
}

func yamlDocuments(objects ...any) ([]byte, error) {
	var output strings.Builder
	for i, object := range objects {
		data, err := yaml.Marshal(object)
		if err != nil {
			return nil, err
		}
		if i > 0 {
			output.WriteString("---\n")
		}
		output.Write(data)
	}
	return []byte(output.String()), nil
}

func jwtTestClaims(tenant string) map[string]any {
	return map[string]any{
		"organization":  map[string]any{"id": tenant},
		"sub":           "writer-17",
		"chain":         "first",
		"order":         "first",
		"literal.claim": `source "quoted" \ value`,
		"aud":           "gateway-test",
		"exp":           time.Now().Add(5 * time.Minute).Unix(),
	}
}

func jwtEchoHeaders(body []byte) map[string][]string {
	var echo struct {
		Headers map[string][]string `json:"headers"`
	}
	if err := json.Unmarshal(body, &echo); err != nil {
		return nil
	}
	return echo.Headers
}

func jwtUpstreamRequests(ctx context.Context, adminAddress, clusterName string) (uint64, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://"+adminAddress+"/stats?filter=cluster."+clusterName+".upstream_rq_total", nil)
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
	wanted := "cluster." + clusterName + ".upstream_rq_total"
	for _, line := range strings.Split(string(body), "\n") {
		name, value, found := strings.Cut(line, ":")
		if !found || strings.TrimSpace(name) != wanted {
			continue
		}
		count, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("parse Envoy stat %q: %w", wanted, err)
		}
		return count, nil
	}
	return 0, fmt.Errorf("Envoy stats do not include %q: %s", wanted, body)
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
	scheme, client := "http", testClient
	if useTLS {
		scheme = "https"
		transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: e.rootCAs, ServerName: host, MinVersion: tls.VersionTLS12}}
		defer transport.CloseIdleConnections()
		client = &http.Client{Transport: transport, Timeout: 10 * time.Second}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+address+path, nil)
	if err != nil {
		return 0, nil, err
	}
	request.Host = host
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if spoof {
		request.Header.Add("X-Scope-OrgID", "spoofed")
		request.Header.Add("X-Scope-OrgID", "duplicate")
		request.Header.Set("X-Writer-ID", "spoofed")
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, nil, err
	}
	body, err := readAndCloseResponseBody(response, 1<<20)
	return response.StatusCode, body, err
}

func headerValue(headers map[string][]string, name string) string {
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return strings.Join(value, ",")
		}
	}
	return ""
}
