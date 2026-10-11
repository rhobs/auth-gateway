//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
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
)

const (
	upstreamTransportHost = "upstream-transport.auth-gateway.test"
)

var (
	upstreamTransportNamespace = e2eNamespace("upstream-transport-e2e")
	upstreamTransportSAN       = "transport-backend." + upstreamTransportNamespace + ".svc.cluster.local"
)

var _ = Describe("Upstream TLS and HTTP/2", Label("gateway", "upstream-transport", "namespace-"+upstreamTransportNamespace), Ordered, func() {
	var gatewayAddress string
	var adminAddress string

	BeforeAll(func(ctx SpecContext) {
		DeferCleanup(func(ctx SpecContext) {
			Expect(env.DeleteNamespace(ctx, upstreamTransportNamespace)).To(Succeed())
		}, NodeTimeout(3*time.Minute))

		Expect(resetE2ENamespace(ctx, upstreamTransportNamespace)).To(Succeed())

		httpbin, err := env.Fixture("httpbin.yaml")
		Expect(err).NotTo(HaveOccurred())
		Expect(env.Apply(ctx, upstreamTransportNamespace, httpbin)).To(Succeed())

		certificates, err := makeJWTTestCertificates([]string{upstreamTransportSAN})
		Expect(err).NotTo(HaveOccurred())
		backend, err := upstreamTransportBackendManifest(upstreamTransportNamespace, certificates)
		Expect(err).NotTo(HaveOccurred())
		Expect(env.Apply(ctx, upstreamTransportNamespace, backend)).To(Succeed())
		Expect(env.WaitForDeployment(ctx, upstreamTransportNamespace, "httpbin", 4*time.Minute)).To(Succeed())
		Expect(env.WaitForDeployment(ctx, upstreamTransportNamespace, "transport-backend", 4*time.Minute)).To(Succeed())

		fixture, err := env.Fixture("upstream-transport.yaml")
		Expect(err).NotTo(HaveOccurred())
		gatewayConfig, err := config.Load(bytes.NewReader(fixture))
		Expect(err).NotTo(HaveOccurred())
		gatewayConfig.Kubernetes.Namespace = upstreamTransportNamespace
		gatewayConfig.APIs[0].Upstream.TLSConfig.ServerName = upstreamTransportSAN
		gatewayConfig.APIs[1].Upstream.TLSConfig.ServerName = "wrong-name." + upstreamTransportNamespace + ".svc.cluster.local"
		resources, err := config.GenerateKubernetes(gatewayConfig)
		Expect(err).NotTo(HaveOccurred())
		manifest, err := resources.YAML()
		Expect(err).NotTo(HaveOccurred())
		Expect(env.Apply(ctx, upstreamTransportNamespace, manifest)).To(Succeed())
		Expect(env.WaitForDeployment(ctx, upstreamTransportNamespace, "auth-gateway", 4*time.Minute)).To(Succeed())

		gatewayAddress = env.ForwardWithCleanup(ctx, upstreamTransportNamespace, "service/auth-gateway", 80)
		adminAddress = env.ForwardEnvoyAdminWithCleanup(ctx, upstreamTransportNamespace)
		for _, path := range []string{"/tls-echo", "/http2-echo"} {
			Expect(waitForSuccessfulRequest(ctx, "upstream transport "+path, 30*time.Second, 250*time.Millisecond, func(ctx context.Context) error {
				status, body, err := requestUpstreamTransport(ctx, gatewayAddress, path, []byte("transport readiness"))
				if err != nil {
					return err
				}
				if status != http.StatusOK {
					return fmt.Errorf("warmup returned HTTP %d: %s", status, body)
				}
				return nil
			})).To(Succeed())
		}
	}, NodeTimeout(12*time.Minute))

	It("verifies upstream TLS and sends HTTP/2 requests", func(ctx SpecContext) {
		payload := []byte("full upstream transport echo")
		for _, test := range []struct {
			name, path, cluster, rewrittenPath string
		}{
			{name: "TLS upstream", path: "/tls-echo?source=e2e", cluster: "api-tls-echo", rewrittenPath: "/anything/tls-echo?source=e2e"},
			{name: "HTTP/2 upstream", path: "/http2-echo?source=e2e", cluster: "api-http2-echo", rewrittenPath: "/anything/http2-echo?source=e2e"},
		} {
			status, body := expectUpstreamRequestDelta(ctx, adminAddress, test.cluster, test.name, 1, func() (int, []byte, error) {
				return requestUpstreamTransport(ctx, gatewayAddress, test.path, payload)
			})
			Expect(status).To(Equal(http.StatusOK), test.name+": "+string(body))

			echo, err := decodeHTTPBinEcho(body)
			Expect(err).NotTo(HaveOccurred(), test.name)
			Expect(echo.Method).To(Equal(http.MethodPost), test.name)
			Expect(echo.URL).To(HaveSuffix(test.rewrittenPath), test.name)
			Expect(echo.Data).To(Equal("data:application/octet-stream;base64,"+base64.StdEncoding.EncodeToString(payload)), test.name)
			Expect(headerValue(echo.Headers, "Content-Type")).To(Equal("application/octet-stream"), test.name)
			Expect(headerValue(echo.Headers, "X-E2E-Upstream-Transport")).To(Equal("forwarded"), test.name)
		}
	}, SpecTimeout(60*time.Second))

	It("rejects a mismatched upstream SAN and records the Envoy verification counter", func(ctx SpecContext) {
		const statName = "cluster.api-tls-mismatch.ssl.fail_verify_san"
		before, err := envoyCounter(ctx, adminAddress, statName)
		Expect(err).NotTo(HaveOccurred())

		status, body, err := requestUpstreamTransport(ctx, gatewayAddress, "/tls-mismatch", []byte("must not reach backend"))
		Expect(err).NotTo(HaveOccurred())
		Expect(status).To(Equal(http.StatusServiceUnavailable), string(body))

		Eventually(func() (uint64, error) {
			return envoyCounter(ctx, adminAddress, statName)
		}).WithContext(ctx).WithTimeout(10 * time.Second).WithPolling(250 * time.Millisecond).Should(Equal(before + 1))
	}, SpecTimeout(30*time.Second))
})

func requestUpstreamTransport(ctx context.Context, gatewayAddress, path string, payload []byte) (int, []byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+gatewayAddress+path, bytes.NewReader(payload))
	if err != nil {
		return 0, nil, err
	}
	request.Host = upstreamTransportHost
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("X-E2E-Upstream-Transport", "forwarded")

	response, err := testClient.Do(request)
	if err != nil {
		return 0, nil, err
	}
	body, err := readAndCloseResponseBody(response, 1<<20)
	return response.StatusCode, body, err
}

func envoyCounter(ctx context.Context, adminAddress, statName string) (uint64, error) {
	body, err := env.EnvoyAdminGet(ctx, adminAddress, "/stats?filter="+statName)
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(body), "\n") {
		name, value, found := strings.Cut(line, ":")
		if !found || strings.TrimSpace(name) != statName {
			continue
		}
		count, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("parse Envoy stat %q: %w", statName, err)
		}
		return count, nil
	}
	return 0, fmt.Errorf("Envoy stats do not include %q: %s", statName, body)
}

func upstreamTransportBackendManifest(namespace string, certificates *jwtTestCertificates) ([]byte, error) {
	envoyConfig := fmt.Sprintf(`node: {id: transport-backend, cluster: transport-backend}
admin:
  access_log_path: /dev/null
  address:
    socket_address: {address: 0.0.0.0, port_value: 9901}
static_resources:
  listeners:
    - name: tls
      address:
        socket_address: {address: 0.0.0.0, port_value: 8443}
      filter_chains:
        - transport_socket:
            name: envoy.transport_sockets.tls
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
              common_tls_context:
                tls_certificates:
                  - certificate_chain: {filename: /etc/transport-tls/tls.crt}
                    private_key: {filename: /etc/transport-tls/tls.key}
          filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: tls
                codec_type: HTTP1
                route_config:
                  name: tls
                  virtual_hosts:
                    - name: httpbin
                      domains: ["*"]
                      routes:
                        - match: {prefix: /}
                          route: {cluster: httpbin}
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
    - name: http2
      address:
        socket_address: {address: 0.0.0.0, port_value: 8081}
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: http2
                codec_type: HTTP2
                route_config:
                  name: http2
                  virtual_hosts:
                    - name: httpbin
                      domains: ["*"]
                      routes:
                        - match: {prefix: /}
                          route: {cluster: httpbin}
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
  clusters:
    - name: httpbin
      type: STRICT_DNS
      connect_timeout: 5s
      lb_policy: ROUND_ROBIN
      load_assignment:
        cluster_name: httpbin
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {address: httpbin.%s.svc.cluster.local, port_value: 8080}
`, namespace)

	labels := map[string]string{"app.kubernetes.io/name": "transport-backend"}
	configMap := &corev1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"},
		ObjectMeta: metav1.ObjectMeta{Name: "transport-backend-config", Namespace: namespace},
		Data:       map[string]string{"envoy.yaml": envoyConfig},
	}
	tlsSecret := &corev1.Secret{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
		ObjectMeta: metav1.ObjectMeta{Name: "transport-backend-tls", Namespace: namespace},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{corev1.TLSCertKey: certificates.chainPEM, corev1.TLSPrivateKeyKey: certificates.keyPEM},
	}
	caConfigMap := &corev1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"},
		ObjectMeta: metav1.ObjectMeta{Name: "transport-backend-ca", Namespace: namespace},
		Data:       map[string]string{"ca.pem": string(certificates.caPEM)},
	}
	container := corev1.Container{
		Name: "envoy", Image: config.DefaultEnvoyImage, ImagePullPolicy: corev1.PullIfNotPresent,
		Args: []string{"-c", "/etc/transport-config/envoy.yaml", "--log-level", "error"},
		Ports: []corev1.ContainerPort{
			{Name: "tls", ContainerPort: 8443},
			{Name: "http2", ContainerPort: 8081},
			{Name: "admin", ContainerPort: 9901},
		},
		ReadinessProbe: &corev1.Probe{
			ProbeHandler:        corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/ready", Port: intstr.FromString("admin")}},
			PeriodSeconds:       1,
			TimeoutSeconds:      1,
			FailureThreshold:    30,
			SuccessThreshold:    1,
			InitialDelaySeconds: 1,
		},
		VolumeMounts: []corev1.VolumeMount{
			{Name: "config", MountPath: "/etc/transport-config", ReadOnly: true},
			{Name: "tls", MountPath: "/etc/transport-tls", ReadOnly: true},
		},
	}
	volumes := []corev1.Volume{
		{Name: "config", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: configMap.Name}}}},
		{Name: "tls", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: tlsSecret.Name, Items: []corev1.KeyToPath{{Key: corev1.TLSCertKey, Path: "tls.crt"}, {Key: corev1.TLSPrivateKeyKey, Path: "tls.key"}}}}},
	}
	deployment := &appsv1.Deployment{
		TypeMeta:   metav1.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"},
		ObjectMeta: metav1.ObjectMeta{Name: "transport-backend", Namespace: namespace},
		Spec: appsv1.DeploymentSpec{
			Replicas: new(int32(1)),
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{container}, Volumes: volumes},
			},
		},
	}
	service := &corev1.Service{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Service"},
		ObjectMeta: metav1.ObjectMeta{Name: "transport-backend", Namespace: namespace},
		Spec: corev1.ServiceSpec{
			Selector: labels,
			Ports: []corev1.ServicePort{
				{Name: "tls", Port: 8443, TargetPort: intstr.FromString("tls")},
				{Name: "http2", Port: 8081, TargetPort: intstr.FromString("http2")},
			},
		},
	}
	return yamlDocuments(configMap, tlsSecret, caConfigMap, deployment, service)
}
