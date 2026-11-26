//go:build e2e

package e2e

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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
	extProcHost       = "proc.auth-gateway.test"
	extProcImage      = "auth-gateway-ext-proc-test:local"
	extProcAPICluster = "api-ext-proc-api"
)

var extProcNamespace = e2eNamespace("auth-gateway-ext-proc-e2e")

type processorInput struct {
	Metadata   map[string]map[string]any `json:"metadata"`
	Attributes map[string]map[string]any `json:"attributes"`
	Headers    map[string]string         `json:"headers"`
}

var _ = Describe("External request processing", Label("gateway", "ext-proc", "processing", "namespace-"+extProcNamespace), Ordered, func() {
	var gateway *apiKeyE2E
	BeforeAll(func(ctx SpecContext) {
		DeferCleanup(func() { deleteNamespaceInBackground(extProcNamespace) })
		Expect(env.BuildAndLoadGoImage(ctx, "./e2e/cmd/ext-proc-test-server", extProcImage)).To(Succeed())
		var err error
		gateway, err = setupAPIKeyGatewayWithShape(ctx, extProcNamespace, false, baselineAPIKeyCredentials(), apiKeySharedSecretKey, func(c *gatewayapi.Config) {
			manifest, err := extProcServiceManifest(extProcNamespace)
			Expect(err).NotTo(HaveOccurred())
			Expect(env.Apply(ctx, extProcNamespace, manifest)).To(Succeed())
			Expect(env.WaitForDeployment(ctx, extProcNamespace, "processor", 4*time.Minute)).To(Succeed())
			fixture, err := env.Fixture("ext-proc.yaml")
			Expect(err).NotTo(HaveOccurred())
			shape, err := gatewayconfig.Load(bytes.NewReader(fixture))
			Expect(err).NotTo(HaveOccurred())
			addExtProcScenario(c, shape, extProcNamespace)
		})
		Expect(err).NotTo(HaveOccurred())
	}, NodeTimeout(12*time.Minute))

	It("receives verified JWT inputs after credential cleanup and managed header mappings", func(ctx SpecContext) {
		token := gateway.tokenForIssuer("issuer-one", "customer-a", "writer")
		code, body := expectUpstreamRequestDelta(ctx, gateway.adminAddr, extProcAPICluster, "headers processing", 1, func() (int, []byte, error) {
			return gateway.request(ctx, extProcHost, false, "GET", "/headers", "", token, "", http.Header{"X-Auth": {"jwt"}, "X-Writer-Id": {"spoofed"}})
		})
		Expect(code).To(Equal(http.StatusOK), string(body))
		echo, err := decodeHTTPBinEcho(body)
		Expect(err).NotTo(HaveOccurred())
		Expect(echo.Method).To(Equal("GET"))
		Expect(echo.URL).To(HaveSuffix("/anything"))
		Expect(echo.Data).To(BeEmpty())
		Expect(headerValue(echo.Headers, "X-Processed")).To(Equal("yes"))
		Expect(headerValue(echo.Headers, "X-Writer-ID")).To(Equal("writer"))
		Expect(headerValue(echo.Headers, "Authorization")).To(BeEmpty())
		var input processorInput
		Expect(json.Unmarshal([]byte(headerValue(echo.Headers, "X-Processor-Input")), &input)).To(Succeed())
		Expect(input.Headers).NotTo(HaveKey("authorization"))
		Expect(input.Headers).NotTo(HaveKey("x-partner-key"))
		Expect(input.Headers["x-writer-id"]).To(Equal("writer"))
		Expect(input.Metadata["auth_gateway.ext_proc.attributes"]).To(Equal(map[string]any{"operation": "transform (100%)", "tenant_id": "customer-a", "writer_id": "writer"}))
		claims := input.Metadata["envoy.filters.http.jwt_authn"]["issuer-one"].(map[string]any)
		Expect(claims["sub"]).To(Equal("writer"))
		Expect(input.Attributes["envoy.filters.http.ext_proc"]).To(HaveKeyWithValue("request.method", "GET"))
		Expect(input.Attributes["envoy.filters.http.ext_proc"]).To(HaveKeyWithValue("request.path", "/headers"))
	})

	It("transforms buffered, partial, streamed, and full duplex request bodies", func(ctx SpecContext) {
		for _, path := range []string{"/buffered", "/partial", "/streamed", "/duplex"} {
			payload := "hello processor"
			if path == "/streamed" {
				payload = strings.Repeat("stream ", 12000)
			}
			action := ""
			if path == "/duplex" {
				action = "duplex"
			}
			code, body := expectUpstreamRequestDelta(ctx, gateway.adminAddr, extProcAPICluster, path, 1, func() (int, []byte, error) {
				return gateway.request(ctx, extProcHost, false, "POST", path, payload, "", apiKeySharedSecretKey, http.Header{"X-Auth": {"key"}, "X-Processor-Action": {action}})
			})
			Expect(code).To(Equal(http.StatusOK), string(body))
			echo, err := decodeHTTPBinEcho(body)
			Expect(err).NotTo(HaveOccurred())
			Expect(echo.Method).To(Equal("POST"))
			Expect(echo.URL).To(HaveSuffix("/anything"))
			Expect(echo.Data).To(Equal("data:application/octet-stream;base64," + base64.StdEncoding.EncodeToString([]byte(strings.ToUpper(payload)))))
			Expect(headerValue(echo.Headers, "X-Partner-Key")).To(BeEmpty())
			var input processorInput
			Expect(json.Unmarshal([]byte(headerValue(echo.Headers, "X-Processor-Input")), &input)).To(Succeed())
			Expect(input.Metadata).NotTo(HaveKey("envoy.filters.http.jwt_authn"))
			Expect(input.Metadata["auth_gateway.ext_proc.attributes"]).To(HaveKeyWithValue("operation", "transform (100%)"))
		}
	})

	It("processes public routes and isolates requests without an attachment", func(ctx SpecContext) {
		for _, path := range []string{"/public", "/unprocessed"} {
			code, body, err := gateway.request(ctx, extProcHost, false, "GET", path, "", "", "", nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(code).To(Equal(http.StatusOK), string(body))
			echo, err := decodeHTTPBinEcho(body)
			Expect(err).NotTo(HaveOccurred())
			Expect(echo.Method).To(Equal("GET"))
			Expect(echo.URL).To(HaveSuffix("/anything"))
			Expect(echo.Data).To(BeEmpty())
			if path == "/unprocessed" {
				Expect(headerValue(echo.Headers, "X-Processed")).To(BeEmpty())
				continue
			}
			var input processorInput
			Expect(json.Unmarshal([]byte(headerValue(echo.Headers, "X-Processor-Input")), &input)).To(Succeed())
			Expect(input.Metadata["auth_gateway.ext_proc.attributes"]).To(Equal(map[string]any{"audience": "public"}))
			Expect(input.Metadata).NotTo(HaveKey("envoy.filters.http.jwt_authn"))
		}
	})

	It("preserves processor rejections and rejects protected header mutations before upstream", func(ctx SpecContext) {
		for _, test := range []struct {
			action, header string
			code           int
		}{
			{"reject", "", http.StatusForbidden}, {"error", "", http.StatusInternalServerError},
			{"mutate", "authorization", http.StatusInternalServerError},
			{"mutate", "x-writer-id", http.StatusInternalServerError},
			{"mutate", "x-envoy-retry-on", http.StatusInternalServerError},
		} {
			expectDeniedBeforeUpstream(ctx, gateway.adminAddr, extProcAPICluster, test.action+test.header, test.code, func() (int, []byte, error) {
				return gateway.request(ctx, extProcHost, false, "GET", "/headers", "", "", apiKeySharedSecretKey, http.Header{"X-Auth": {"key"}, "X-Processor-Action": {test.action}, "X-Processor-Mutate": {test.header}})
			})
		}
	})

	It("applies fail-open to processing failures while preserving explicit rejections", func(ctx SpecContext) {
		for _, test := range []struct {
			action string
			code   int
			delta  uint64
		}{{"error", 200, 1}, {"reject", 403, 0}} {
			code, body := expectUpstreamRequestDelta(ctx, gateway.adminAddr, "api-ext-proc-public", test.action, test.delta, func() (int, []byte, error) {
				return gateway.request(ctx, extProcHost, false, "GET", "/public", "", "", "", http.Header{"X-Processor-Action": {test.action}})
			})
			Expect(code).To(Equal(test.code), string(body))
		}
	})

	It("does not invoke processors for generated denial and local response routes", func(ctx SpecContext) {
		for _, test := range []struct {
			method, path, key string
			code              int
		}{{"GET", "/headers", "invalid", 401}, {"GET", "/missing", "", 404}, {"POST", "/headers", "", 405}} {
			before, err := upstreamRequestCount(ctx, gateway.adminAddr, "ext-proc-transform")
			Expect(err).NotTo(HaveOccurred())
			expectDeniedBeforeUpstream(ctx, gateway.adminAddr, extProcAPICluster, test.path, test.code, func() (int, []byte, error) {
				return gateway.request(ctx, extProcHost, false, test.method, test.path, "", "", test.key, http.Header{"X-Auth": {"key"}})
			})
			after, err := upstreamRequestCount(ctx, gateway.adminAddr, "ext-proc-transform")
			Expect(err).NotTo(HaveOccurred())
			Expect(after).To(Equal(before))
		}
	})
})

func TestExtProcScenarioConfig(t *testing.T) {
	root, err := framework.Root()
	if err != nil {
		t.Fatal(err)
	}
	load := func(name string) gatewayapi.Config {
		fixture, err := os.ReadFile(filepath.Join(root, "e2e", "fixtures", name))
		if err != nil {
			t.Fatal(err)
		}
		c, err := gatewayconfig.Load(bytes.NewReader(fixture))
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	config := load("api-key-gateway.yaml")
	addExtProcScenario(&config, load("ext-proc.yaml"), "ext-proc-test")
	if _, err := gatewayconfig.GenerateKubernetes(config); err != nil {
		t.Fatal(err)
	}
}

func addExtProcScenario(config *gatewayapi.Config, shape gatewayapi.Config, namespace string) {
	for i := range shape.ExtProcServices {
		shape.ExtProcServices[i].Upstream.Address = "processor." + namespace + ".svc.cluster.local"
	}
	config.ExtProcServices = append(config.ExtProcServices, shape.ExtProcServices...)
	config.APIs = append(config.APIs, shape.APIs...)
	config.Servers = append(config.Servers, shape.Servers...)
}

func extProcServiceManifest(namespace string) ([]byte, error) {
	labels := map[string]string{"app": "processor"}
	deployment := &appsv1.Deployment{TypeMeta: metav1.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"}, ObjectMeta: metav1.ObjectMeta{Name: "processor", Namespace: namespace}, Spec: appsv1.DeploymentSpec{
		Replicas: new(int32(1)), Selector: &metav1.LabelSelector{MatchLabels: labels}, Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "processor", Image: extProcImage, ImagePullPolicy: corev1.PullPolicy("Never"), Ports: []corev1.ContainerPort{{Name: "grpc", ContainerPort: 9000}}}}}},
	}}
	service := &corev1.Service{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Service"}, ObjectMeta: metav1.ObjectMeta{Name: "processor", Namespace: namespace}, Spec: corev1.ServiceSpec{Selector: labels, Ports: []corev1.ServicePort{{Name: "grpc", Port: 9000, TargetPort: intstr.FromInt(9000)}}}}
	return yamlDocuments(deployment, service)
}
