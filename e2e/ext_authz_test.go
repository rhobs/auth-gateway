//go:build e2e

package e2e

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/rhobs/auth-gateway/e2e/internal/framework"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	gatewayconfig "github.com/rhobs/auth-gateway/pkg/gateway"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	extAuthzHost    = "ext.auth-gateway.test"
	extAuthzImage   = "auth-gateway-ext-authz-test:local"
	extAuthzCluster = "api-ext-authz-api"
)

var extAuthzNamespace = e2eNamespace("auth-gateway-ext-authz-e2e")

var _ = Describe("External authorization", Label("gateway", "ext-authz", "authentication", "authorization", "namespace-"+extAuthzNamespace), Ordered, func() {
	var gateway *apiKeyE2E
	BeforeAll(func(ctx SpecContext) {
		DeferCleanup(func() { deleteNamespaceInBackground(extAuthzNamespace) })
		Expect(env.BuildAndLoadGoImage(ctx, "./e2e/cmd/ext-authz-test-server", extAuthzImage)).To(Succeed())
		certificates, err := makeJWTTestCertificates([]string{"policy." + extAuthzNamespace + ".svc.cluster.local"})
		Expect(err).NotTo(HaveOccurred())
		gateway, err = setupAPIKeyGatewayWithShape(ctx, extAuthzNamespace, false, baselineAPIKeyCredentials(), apiKeySharedSecretKey, func(c *gatewayapi.Config) {
			manifest, err := extAuthzServiceManifest(extAuthzNamespace, certificates)
			Expect(err).NotTo(HaveOccurred())
			Expect(env.Apply(ctx, extAuthzNamespace, manifest)).To(Succeed())
			Expect(env.WaitForDeployment(ctx, extAuthzNamespace, "policy", 4*time.Minute)).To(Succeed())
			fixture, err := env.Fixture("ext-authz.yaml")
			Expect(err).NotTo(HaveOccurred())
			shape, err := gatewayconfig.Load(bytes.NewReader(fixture))
			Expect(err).NotTo(HaveOccurred())
			addExtAuthzScenario(c, shape, extAuthzNamespace)
		})
		Expect(err).NotTo(HaveOccurred())
	}, NodeTimeout(12*time.Minute))

	It("sends declared attributes and parsed JWT claims to the policy service", func(ctx SpecContext) {
		token := gateway.tokenForIssuer("issuer-one", "internal", "writer")
		status, body := expectUpstreamRequestDelta(ctx, gateway.adminAddr, extAuthzCluster, "verified JWT", 1, func() (int, []byte, error) {
			return gateway.request(ctx, extAuthzHost, false, http.MethodGet, "/protected", "", token, "", http.Header{"X-Tenant": {"internal"}, "X-Scope-OrgID": {"spoofed"}})
		})
		Expect(status).To(Equal(http.StatusOK), string(body))
		echo, err := decodeHTTPBinEcho(body)
		Expect(err).NotTo(HaveOccurred())
		Expect(echo.Method).To(Equal(http.MethodGet))
		Expect(echo.URL).To(HaveSuffix("/anything"))
		Expect(echo.Data).To(BeEmpty())
		Expect(headerValue(echo.Headers, "Authorization")).To(BeEmpty())
		Expect(headerValue(echo.Headers, "X-Scope-OrgID")).To(Equal("internal"))
		Expect(headerValue(echo.Headers, "X-Role")).To(Equal("metrics:read"))
	})

	It("rejects invalid local JWTs and claims denied by the policy", func(ctx SpecContext) {
		for _, test := range []struct {
			name, token string
			status      int
		}{
			{"invalid signature", gateway.tokenForIssuer("issuer-one", "internal", "writer") + "invalid", http.StatusUnauthorized},
			{"wrong tenant", gateway.tokenForIssuer("issuer-one", "partner", "writer"), http.StatusForbidden},
		} {
			expectDeniedBeforeUpstream(ctx, gateway.adminAddr, extAuthzCluster, test.name, test.status, func() (int, []byte, error) {
				return gateway.request(ctx, extAuthzHost, false, http.MethodGet, "/protected", "", test.token, "", http.Header{"X-Tenant": {"internal"}})
			})
		}
	})

	It("authenticates and authorizes through the external service", func(ctx SpecContext) {
		status, body := expectUpstreamRequestDelta(ctx, gateway.adminAddr, extAuthzCluster, "external credential", 1, func() (int, []byte, error) {
			return gateway.request(ctx, extAuthzHost, false, http.MethodGet, "/protected", "", "e2e-partner", "", http.Header{"X-Tenant": {"partner"}, "X-Scope-OrgID": {"spoofed"}})
		})
		Expect(status).To(Equal(http.StatusOK), string(body))
		echo, err := decodeHTTPBinEcho(body)
		Expect(err).NotTo(HaveOccurred())
		Expect(echo.Method).To(Equal(http.MethodGet))
		Expect(echo.URL).To(HaveSuffix("/anything"))
		Expect(echo.Data).To(BeEmpty())
		Expect(headerValue(echo.Headers, "Authorization")).To(BeEmpty())
		Expect(headerValue(echo.Headers, "X-Scope-OrgID")).To(Equal("partner"))
	})

	It("sends API-key attributes without JWT claims", func(ctx SpecContext) {
		status, body := expectUpstreamRequestDelta(ctx, gateway.adminAddr, extAuthzCluster, "verified API key", 1, func() (int, []byte, error) {
			return gateway.request(ctx, extAuthzHost, false, http.MethodGet, "/protected", "", "", apiKeySharedSecretKey, http.Header{"X-Tenant": {"client-a"}})
		})
		Expect(status).To(Equal(http.StatusOK), string(body))
		echo, err := decodeHTTPBinEcho(body)
		Expect(err).NotTo(HaveOccurred())
		Expect(headerValue(echo.Headers, "X-Partner-Key")).To(BeEmpty())
		Expect(headerValue(echo.Headers, "X-Scope-OrgID")).To(Equal("client-a"))
	})

	It("rejects missing credentials, tenant spoofing, and repeated credentials", func(ctx SpecContext) {
		for _, test := range []struct {
			name, tenant, token string
			headers             http.Header
			status              int
		}{
			{"missing credential", "partner", "", nil, http.StatusUnauthorized},
			{"wrong tenant", "partner-other", "e2e-partner", nil, http.StatusForbidden},
			{"repeated credential", "partner", "", http.Header{"Authorization": {"Bearer e2e-partner", "Bearer other"}}, http.StatusBadRequest},
		} {
			headers := test.headers.Clone()
			if headers == nil {
				headers = make(http.Header)
			}
			headers.Set("X-Tenant", test.tenant)
			expectDeniedBeforeUpstream(ctx, gateway.adminAddr, extAuthzCluster, test.name, test.status, func() (int, []byte, error) {
				return gateway.request(ctx, extAuthzHost, false, http.MethodGet, "/protected", "", test.token, "", headers)
			})
		}
	})

	It("fails closed on service errors and forbidden mutations", func(ctx SpecContext) {
		for _, test := range []struct {
			mode   string
			status int
		}{
			{"error", http.StatusServiceUnavailable},
			{"timeout", http.StatusServiceUnavailable},
			{"mutation", http.StatusInternalServerError},
		} {
			expectDeniedBeforeUpstream(ctx, gateway.adminAddr, extAuthzCluster, test.mode, test.status, func() (int, []byte, error) {
				return gateway.request(ctx, extAuthzHost, false, http.MethodGet, "/protected", "", "e2e-partner", "", http.Header{"X-Tenant": {"partner"}, "X-Policy-Mode": {test.mode}})
			})
		}
	}, NodeTimeout(90*time.Second))
})

func TestExtAuthzScenarioConfig(t *testing.T) {
	root, err := framework.Root()
	if err != nil {
		t.Fatal(err)
	}
	baseFixture, err := os.ReadFile(filepath.Join(root, "e2e", "fixtures", "api-key-gateway.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	config, err := gatewayconfig.Load(bytes.NewReader(baseFixture))
	if err != nil {
		t.Fatal(err)
	}
	scenarioFixture, err := os.ReadFile(filepath.Join(root, "e2e", "fixtures", "ext-authz.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	shape, err := gatewayconfig.Load(bytes.NewReader(scenarioFixture))
	if err != nil {
		t.Fatal(err)
	}
	addExtAuthzScenario(&config, shape, "ext-authz-test")
	if _, err := gatewayconfig.GenerateKubernetes(config); err != nil {
		t.Fatal(err)
	}
}

func addExtAuthzScenario(config *gatewayapi.Config, shape gatewayapi.Config, namespace string) {
	for index := range config.Authenticators {
		for _, authenticator := range shape.Authenticators {
			if config.Authenticators[index].Name != authenticator.Name {
				continue
			}
			for _, attribute := range authenticator.Attributes {
				if attribute.FromSource == "fixed" {
					config.Authenticators[index].Attributes = append(config.Authenticators[index].Attributes, attribute)
				}
			}
		}
	}
	service := shape.ExtAuthzServices[0]
	service.Upstream.Address = "policy." + namespace + ".svc.cluster.local"
	service.Upstream.TLSConfig.ServerName = service.Upstream.Address
	service.Upstream.TLSConfig.TrustedCA = &gatewayapi.TrustedCA{ConfigMap: &gatewayapi.CAConfigMap{Name: "policy-ca", Key: "ca.pem"}}
	config.ExtAuthzServices = append(config.ExtAuthzServices, service)
	config.APIs = append(config.APIs, shape.APIs...)
	config.Servers = append(config.Servers, shape.Servers...)
}

func extAuthzServiceManifest(namespace string, certificates *jwtTestCertificates) ([]byte, error) {
	labels := map[string]string{"app": "policy"}
	secret := &corev1.Secret{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: metav1.ObjectMeta{Name: "policy-tls", Namespace: namespace}, Type: corev1.SecretTypeTLS, Data: map[string][]byte{corev1.TLSCertKey: certificates.chainPEM, corev1.TLSPrivateKeyKey: certificates.keyPEM}}
	ca := &corev1.ConfigMap{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}, ObjectMeta: metav1.ObjectMeta{Name: "policy-ca", Namespace: namespace}, Data: map[string]string{"ca.pem": string(certificates.caPEM)}}
	deployment := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"}, ObjectMeta: metav1.ObjectMeta{Name: "policy", Namespace: namespace},
		Spec: appsv1.DeploymentSpec{Replicas: new(int32(1)), Selector: &metav1.LabelSelector{MatchLabels: labels}, Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels}, Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "policy", Image: extAuthzImage, ImagePullPolicy: corev1.PullPolicy("Never"), Ports: []corev1.ContainerPort{{Name: "grpc", ContainerPort: 9000}}, VolumeMounts: []corev1.VolumeMount{{Name: "tls", MountPath: "/tls", ReadOnly: true}}}},
			Volumes:    []corev1.Volume{{Name: "tls", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "policy-tls"}}}},
		}}},
	}
	service := &corev1.Service{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Service"}, ObjectMeta: metav1.ObjectMeta{Name: "policy", Namespace: namespace}, Spec: corev1.ServiceSpec{Selector: labels, Ports: []corev1.ServicePort{{Name: "grpc", Port: 9000, TargetPort: intstr.FromInt(9000)}}}}
	return yamlDocuments(secret, ca, deployment, service)
}
