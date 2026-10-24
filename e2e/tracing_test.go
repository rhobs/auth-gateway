//go:build e2e

package e2e

import (
	"bytes"
	"fmt"
	"net/http"
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
	tracingHost   = "tracing.auth-gateway.test"
	tracingAPIKey = "tracing-e2e-key"
)

var (
	tracingNamespace        = e2eNamespace("auth-gateway-tracing-e2e")
	tracingSupportNamespace = e2eNamespace("auth-gateway-tracing-support")
)

type tracingE2E struct {
	httpAddress    string
	metricsAddress string
	sinkPodName    string
	serviceName    string
}

var _ = Describe("Tracing", Label("gateway", "tracing", "metrics", "restricted", "namespace-"+tracingNamespace, "namespace-"+tracingSupportNamespace), Ordered, func() {
	var gateway *tracingE2E

	BeforeAll(func(ctx SpecContext) {
		gateway = setupTracingGateway(ctx)
	}, NodeTimeout(10*time.Minute))

	It("serves requests and exports spans and metrics under restricted Pod admission", func(ctx SpecContext) {
		podName, containers, err := env.PodContainerNames(ctx, tracingNamespace, "app.kubernetes.io/name=auth-gateway")
		Expect(err).NotTo(HaveOccurred())
		Expect(podName).NotTo(BeEmpty())
		Expect(containers).To(ConsistOf("envoy", "metrics"), "the gateway Pod should contain only Envoy and its collector sidecar")

		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+gateway.httpAddress+"/trace", nil)
		Expect(err).NotTo(HaveOccurred())
		request.Host = tracingHost
		request.Header.Set("X-Trace-Key", tracingAPIKey)
		response, err := testClient.Do(request)
		Expect(err).NotTo(HaveOccurred())
		body, err := readAndCloseResponseBody(response, 1<<20)
		Expect(err).NotTo(HaveOccurred())
		Expect(response.StatusCode).To(Equal(http.StatusOK), string(body))

		echo, err := decodeHTTPBinEcho(body)
		Expect(err).NotTo(HaveOccurred())
		Expect(echo.Method).To(Equal(http.MethodGet))
		Expect(echo.URL).To(HaveSuffix("/anything/trace"))
		Expect(echo.Data).To(BeEmpty())
		Expect(headerValue(echo.Headers, "X-Trace-Key")).To(BeEmpty(), "the API key must not reach the upstream")

		Eventually(func() error {
			logs, err := env.ContainerLogs(ctx, tracingSupportNamespace, gateway.sinkPodName, "collector", 200)
			if err != nil {
				return err
			}
			serviceName := "service.name: Str(" + gateway.serviceName + ")"
			if !bytes.Contains(logs, []byte(serviceName)) {
				return fmt.Errorf("trace sink has not logged service name %q: %s", gateway.serviceName, logs)
			}
			return nil
		}).WithContext(ctx).WithTimeout(60 * time.Second).WithPolling(time.Second).Should(Succeed())

		Eventually(func() error {
			if err := checkPrometheusMetrics(ctx, gateway.metricsAddress); err != nil {
				return err
			}
			return checkExportedRequestMetric(ctx, gateway.metricsAddress, "gateway_http_requests_total", map[string]string{
				"api": "tracing", "http_status_code": "200",
			})
		}).WithContext(ctx).WithTimeout(70 * time.Second).WithPolling(500 * time.Millisecond).Should(Succeed())
	}, NodeTimeout(3*time.Minute))
})

func setupTracingGateway(ctx SpecContext) *tracingE2E {
	Expect(resetE2ENamespace(ctx, tracingNamespace)).To(Succeed())
	DeferCleanup(func() { deleteNamespaceInBackground(tracingNamespace) })
	namespaceManifest, err := yamlDocuments(&corev1.Namespace{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Namespace"},
		ObjectMeta: metav1.ObjectMeta{
			Name: tracingNamespace,
			Labels: map[string]string{
				"pod-security.kubernetes.io/enforce":         "restricted",
				"pod-security.kubernetes.io/enforce-version": "latest",
			},
		},
	})
	Expect(err).NotTo(HaveOccurred())
	Expect(env.Apply(ctx, tracingNamespace, namespaceManifest)).To(Succeed())
	Expect(resetE2ENamespace(ctx, tracingSupportNamespace)).To(Succeed())
	DeferCleanup(func() { deleteNamespaceInBackground(tracingSupportNamespace) })

	sinkManifest, err := tracingSinkManifest(tracingSupportNamespace)
	Expect(err).NotTo(HaveOccurred())
	Expect(env.Apply(ctx, tracingSupportNamespace, sinkManifest)).To(Succeed())
	Expect(env.WaitForDeployment(ctx, tracingSupportNamespace, "trace-sink", 4*time.Minute)).To(Succeed())

	backend, err := env.Fixture("httpbin.yaml")
	Expect(err).NotTo(HaveOccurred())
	Expect(env.Apply(ctx, tracingSupportNamespace, backend)).To(Succeed())
	Expect(env.WaitForDeployment(ctx, tracingSupportNamespace, "httpbin", 4*time.Minute)).To(Succeed())

	fixture, err := env.Fixture("tracing.yaml")
	Expect(err).NotTo(HaveOccurred())
	gatewayConfig, err := config.Load(bytes.NewReader(fixture))
	Expect(err).NotTo(HaveOccurred())
	gatewayConfig.Kubernetes.Namespace = tracingNamespace
	gatewayConfig.APIs[0].Upstream.Address = "httpbin." + tracingSupportNamespace + ".svc.cluster.local"
	gatewayConfig.Observability.Tracing.Endpoint = "trace-sink." + tracingSupportNamespace + ".svc.cluster.local:4317"
	secret, err := config.APIKeySecret(tracingNamespace, gatewayConfig.Authenticators[0], []config.APIKeyCredential{{
		Key: tracingAPIKey, Attributes: map[string]string{"tenant_id": "trace-client"},
	}})
	Expect(err).NotTo(HaveOccurred())
	secretManifest, err := yamlDocuments(secret)
	Expect(err).NotTo(HaveOccurred())
	Expect(env.Apply(ctx, tracingNamespace, secretManifest)).To(Succeed())

	resources, err := config.GenerateKubernetes(gatewayConfig)
	Expect(err).NotTo(HaveOccurred())
	manifest, err := resources.YAML()
	Expect(err).NotTo(HaveOccurred())
	Expect(env.Apply(ctx, tracingNamespace, manifest)).To(Succeed())
	Expect(env.WaitForDeployment(ctx, tracingNamespace, "auth-gateway", 4*time.Minute)).To(Succeed())

	sinkPodName, sinkContainers, err := env.PodContainerNames(ctx, tracingSupportNamespace, "app.kubernetes.io/name=tracing-sink")
	Expect(err).NotTo(HaveOccurred())
	Expect(sinkContainers).To(ConsistOf("collector"))

	return &tracingE2E{
		httpAddress:    env.ForwardWithCleanup(ctx, tracingNamespace, "service/auth-gateway", 80),
		metricsAddress: env.ForwardWithCleanup(ctx, tracingNamespace, "service/auth-gateway", 8889),
		sinkPodName:    sinkPodName,
		serviceName:    gatewayConfig.Observability.Tracing.ServiceName,
	}
}

func tracingSinkManifest(namespace string) ([]byte, error) {
	labels := map[string]string{"app.kubernetes.io/name": "tracing-sink"}
	configMap := &corev1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"},
		ObjectMeta: metav1.ObjectMeta{Name: "trace-sink", Namespace: namespace},
		Data: map[string]string{"config.yaml": `receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
exporters:
  debug:
    verbosity: detailed
service:
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [debug]
`},
	}
	deployment := &appsv1.Deployment{
		TypeMeta:   metav1.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"},
		ObjectMeta: metav1.ObjectMeta{Name: "trace-sink", Namespace: namespace},
		Spec: appsv1.DeploymentSpec{
			Replicas: new(int32(1)),
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name:            "collector",
						Image:           config.DefaultOTelCollectorImage,
						ImagePullPolicy: corev1.PullIfNotPresent,
						Args:            []string{"--config=/etc/collector/config.yaml"},
						Ports:           []corev1.ContainerPort{{Name: "otlp-grpc", ContainerPort: 4317, Protocol: corev1.ProtocolTCP}},
						ReadinessProbe: &corev1.Probe{
							ProbeHandler:     corev1.ProbeHandler{TCPSocket: &corev1.TCPSocketAction{Port: intstr.FromString("otlp-grpc")}},
							PeriodSeconds:    2,
							TimeoutSeconds:   1,
							FailureThreshold: 10,
						},
						VolumeMounts: []corev1.VolumeMount{{Name: "config", MountPath: "/etc/collector", ReadOnly: true}},
					}},
					Volumes: []corev1.Volume{{
						Name: "config",
						VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{Name: "trace-sink"},
						}},
					}},
				},
			},
		},
	}
	service := &corev1.Service{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Service"},
		ObjectMeta: metav1.ObjectMeta{Name: "trace-sink", Namespace: namespace},
		Spec: corev1.ServiceSpec{
			Selector: labels,
			Ports: []corev1.ServicePort{{
				Name:       "otlp-grpc",
				Port:       4317,
				TargetPort: intstr.FromString("otlp-grpc"),
				Protocol:   corev1.ProtocolTCP,
			}},
		},
	}
	return yamlDocuments(configMap, deployment, service)
}
