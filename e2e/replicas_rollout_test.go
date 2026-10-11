//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/rhobs/auth-gateway/config"
	"github.com/rhobs/auth-gateway/e2e/internal/framework"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

const (
	rolloutHost              = "writer.jwt.auth-gateway.test"
	rolloutPodSelector       = gatewayPodSelector
	rolloutProbeSelector     = "app.kubernetes.io/name=auth-gateway-rollout-probe"
	defaultRolloutProbeImage = "curlimages/curl:8.12.1"
)

var rolloutNamespace = e2eNamespace("auth-gateway-rollout-e2e")

type rolloutPodEndpoint struct {
	identity     framework.PodIdentity
	namespace    string
	listenerPort int
}

var _ = Describe("Replicas and bootstrap rollouts", Label("gateway", "replicas", "rollout", "namespace-"+rolloutNamespace), Ordered, func() {
	var gateway *jwtE2E
	var gatewayConfig config.Config
	var gatewayResources *config.KubernetesResources
	var endpoints []rolloutPodEndpoint

	BeforeAll(func(ctx SpecContext) {
		DeferCleanup(func(ctx SpecContext) {
			Expect(env.DeleteNamespace(ctx, rolloutNamespace)).To(Succeed())
		}, NodeTimeout(3*time.Minute))

		var err error
		gateway, err = setupJWTGateway(ctx, rolloutNamespace, "jwt-gateway.yaml")
		Expect(err).NotTo(HaveOccurred())

		gatewayConfig, err = loadRolloutJWTConfig(rolloutNamespace)
		Expect(err).NotTo(HaveOccurred())
		gatewayConfig.Kubernetes.Replicas = new(int32(2))
		gatewayResources, err = config.GenerateKubernetes(gatewayConfig)
		Expect(err).NotTo(HaveOccurred())
		Expect(gatewayResources.ConfigMap.Data).To(Equal(gateway.resources.ConfigMap.Data))
		Expect(gatewayResources.ProcessingConfigMap.Data).To(Equal(gateway.resources.ProcessingConfigMap.Data))

		deploymentManifest, err := yamlDocuments(gatewayResources.Deployment)
		Expect(err).NotTo(HaveOccurred())
		Expect(env.Apply(ctx, rolloutNamespace, deploymentManifest)).To(Succeed())
		Expect(env.WaitForDeployment(ctx, rolloutNamespace, "auth-gateway", 4*time.Minute)).To(Succeed())
		gateway.resources = gatewayResources
		endpoints = openRolloutPodEndpoints(ctx, rolloutNamespace, *gatewayConfig.Listener.Port)
	}, NodeTimeout(17*time.Minute))

	It("updates the server certificate on both replicas without replacing Pods", func(ctx SpecContext) {
		token := rolloutJWTToken(gateway)
		headers := http.Header{"Authorization": []string{"Bearer " + token}}
		initialSerials := make(map[string]string, len(endpoints))
		for _, endpoint := range endpoints {
			response, err := requestRolloutHTTPS(ctx, endpoint, jwtHTTPSHost, jwtHTTPSHost,
				http.MethodGet, "/protected", nil, headers, gateway.rootCAs)
			Expect(err).NotTo(HaveOccurred(), endpoint.identity.Name)
			Expect(response.status).To(Equal(http.StatusOK), endpoint.identity.Name+": "+string(response.body))
			expectRolloutEcho(response.status, response.body, "team-a")
			initialSerials[endpoint.identity.UID] = response.certificate.SerialNumber.String()
		}
		initialUIDs := rolloutPodUIDs(ctx, rolloutNamespace)

		rotated, err := makeJWTTestCertificates([]string{jwtHTTPSHost})
		Expect(err).NotTo(HaveOccurred())
		gateway.rootCAs.AddCert(rotated.root)
		secret := &corev1.Secret{
			TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
			ObjectMeta: metav1.ObjectMeta{Name: "jwt-gateway-tls", Namespace: rolloutNamespace},
			Type:       corev1.SecretTypeTLS,
			Data:       map[string][]byte{corev1.TLSCertKey: rotated.chainPEM, corev1.TLSPrivateKeyKey: rotated.keyPEM},
		}
		manifest, err := yamlDocuments(secret)
		Expect(err).NotTo(HaveOccurred())
		Expect(env.Apply(ctx, rolloutNamespace, manifest)).To(Succeed())

		responses := make(map[string]*httpsResult, len(endpoints))
		var lastError error
		Eventually(func() bool {
			responses = make(map[string]*httpsResult, len(endpoints))
			for _, endpoint := range endpoints {
				response, err := requestRolloutHTTPS(ctx, endpoint, jwtHTTPSHost, jwtHTTPSHost,
					http.MethodGet, "/protected", nil, headers, gateway.rootCAs)
				if err != nil {
					lastError = fmt.Errorf("request replica %s: %w", endpoint.identity.Name, err)
					return false
				}
				if response.status != http.StatusOK {
					lastError = fmt.Errorf("replica %s returned HTTP %d: %s", endpoint.identity.Name, response.status, response.body)
					return false
				}
				serial := response.certificate.SerialNumber.String()
				if serial == initialSerials[endpoint.identity.UID] {
					lastError = fmt.Errorf("replica %s still serves its original certificate %s", endpoint.identity.Name, serial)
					return false
				}
				responses[endpoint.identity.UID] = response
			}
			lastError = nil
			return true
		}).WithContext(ctx).WithTimeout(3*time.Minute).WithPolling(time.Second).Should(BeTrue(), func() string {
			return fmt.Sprintf("not every replica loaded the renewed server certificate: %v", lastError)
		})

		for _, endpoint := range endpoints {
			expectRolloutEcho(responses[endpoint.identity.UID].status, responses[endpoint.identity.UID].body, "team-a")
		}
		Expect(rolloutPodUIDs(ctx, rolloutNamespace)).To(Equal(initialUIDs), "SDS certificate updates must not replace either replica")
	}, SpecTimeout(4*time.Minute))

	It("reloads processing configuration on both replicas without replacing either Pod", func(ctx SpecContext) {
		initialUIDs := rolloutPodUIDs(ctx, rolloutNamespace)
		Expect(initialUIDs).To(HaveLen(2))
		token := rolloutJWTToken(gateway)
		for _, endpoint := range endpoints {
			status, body, err := requestRolloutHTTP(ctx, gateway, endpoint, rolloutHost, token)
			Expect(err).NotTo(HaveOccurred(), endpoint.identity.Name)
			expectRolloutEcho(status, body, "team-a")
		}

		gatewayConfig.Processing[0].Attributes["tenant_id"].Mappings["customer-a"] = "team-c"
		updated, err := config.GenerateKubernetes(gatewayConfig)
		Expect(err).NotTo(HaveOccurred())
		Expect(updated.ConfigMap.Data).To(Equal(gatewayResources.ConfigMap.Data), "an ECDS update must not change the bootstrap ConfigMap")
		Expect(updated.ProcessingConfigMap.Data).NotTo(Equal(gatewayResources.ProcessingConfigMap.Data))
		Expect(updated.Deployment.Spec.Template).To(Equal(gatewayResources.Deployment.Spec.Template))
		processingManifest, err := yamlDocuments(*updated.ProcessingConfigMap)
		Expect(err).NotTo(HaveOccurred())
		Expect(env.Apply(ctx, rolloutNamespace, processingManifest)).To(Succeed())
		gatewayResources = updated
		gateway.resources = updated

		for _, endpoint := range endpoints {
			var status int
			var body []byte
			var requestErr error
			Eventually(func() bool {
				status, body, requestErr = requestRolloutHTTP(ctx, gateway, endpoint, rolloutHost, token)
				return requestErr == nil && status == http.StatusOK && headerValue(jwtEchoHeaders(body), "X-Scope-OrgID") == "team-c"
			}).WithContext(ctx).WithTimeout(3*time.Minute).WithPolling(time.Second).Should(BeTrue(), func() string {
				return fmt.Sprintf("replica %s did not reload ECDS: HTTP %d: %s (error: %v)", endpoint.identity.Name, status, body, requestErr)
			})
		}

		for request := range 20 {
			endpoint := endpoints[request%len(endpoints)]
			status, body, err := requestRolloutHTTP(ctx, gateway, endpoint, rolloutHost, token)
			Expect(err).NotTo(HaveOccurred(), endpoint.identity.Name)
			expectRolloutEcho(status, body, "team-c")
		}

		finalUIDs := rolloutPodUIDs(ctx, rolloutNamespace)
		Expect(finalUIDs).To(Equal(initialUIDs), "an ECDS processing update must preserve every replica UID")
		Expect(rolloutPodIdentities(ctx, rolloutNamespace)).To(Equal(rolloutPodIdentitiesFromEndpoints(endpoints)))
	}, SpecTimeout(6*time.Minute))

	It("keeps bootstrap-only changes inactive until an explicit rolling restart", func(ctx SpecContext) {
		stableUIDs := rolloutPodUIDs(ctx, rolloutNamespace)
		Expect(stableUIDs).To(HaveLen(2))
		token := rolloutJWTToken(gateway)
		oldMetricLabels := requestMetricLabels("metrics", http.StatusOK, "team-c", "writer-17")
		newMetricLabels := requestMetricLabels("metrics", http.StatusOK, "writer-17", "writer-17")
		oldCounts := make(map[string]uint64, len(endpoints))
		for _, endpoint := range endpoints {
			status, body, err := requestRolloutHTTP(ctx, gateway, endpoint, rolloutHost, token)
			Expect(err).NotTo(HaveOccurred(), endpoint.identity.Name)
			expectRolloutEcho(status, body, "team-c")
			oldCounts[endpoint.identity.UID], err = rolloutMetricCount(ctx, endpoint, oldMetricLabels)
			Expect(err).NotTo(HaveOccurred(), endpoint.identity.Name)
			Expect(oldCounts[endpoint.identity.UID]).To(BeNumerically(">", 0), endpoint.identity.Name)
			newCount, err := rolloutMetricCount(ctx, endpoint, newMetricLabels)
			Expect(err).NotTo(HaveOccurred(), endpoint.identity.Name)
			Expect(newCount).To(BeZero(), endpoint.identity.Name)
		}

		gatewayConfig.APIs[0].Metrics.Labels["tenant"] = "writer_id"
		updated, err := config.GenerateKubernetes(gatewayConfig)
		Expect(err).NotTo(HaveOccurred())
		Expect(updated.ConfigMap.Data).NotTo(Equal(gatewayResources.ConfigMap.Data), "the metric label binding must change the bootstrap ConfigMap")
		Expect(updated.ProcessingConfigMap.Data).To(Equal(gatewayResources.ProcessingConfigMap.Data), "a bootstrap-only change must not change ECDS")
		Expect(updated.Deployment.Spec.Template).To(Equal(gatewayResources.Deployment.Spec.Template), "a bootstrap-only change must not change the Pod template")
		bootstrapManifest, err := yamlDocuments(updated.ConfigMap)
		Expect(err).NotTo(HaveOccurred())
		Expect(env.Apply(ctx, rolloutNamespace, bootstrapManifest)).To(Succeed())

		for range 60 {
			for _, endpoint := range endpoints {
				status, body, err := requestRolloutHTTP(ctx, gateway, endpoint, rolloutHost, token)
				Expect(err).NotTo(HaveOccurred(), endpoint.identity.Name)
				expectRolloutEcho(status, body, "team-c")
			}
			time.Sleep(time.Second)
		}

		for _, endpoint := range endpoints {
			oldCount, err := rolloutMetricCount(ctx, endpoint, oldMetricLabels)
			Expect(err).NotTo(HaveOccurred(), endpoint.identity.Name)
			Expect(oldCount).To(BeNumerically(">", oldCounts[endpoint.identity.UID]), endpoint.identity.Name)
			newCount, err := rolloutMetricCount(ctx, endpoint, newMetricLabels)
			Expect(err).NotTo(HaveOccurred(), endpoint.identity.Name)
			Expect(newCount).To(BeZero(), endpoint.identity.Name+" applied the bootstrap change without a restart")
		}
		Expect(rolloutPodUIDs(ctx, rolloutNamespace)).To(Equal(stableUIDs), "updating only the bootstrap ConfigMap must not replace Pods")

		probeManifest, err := rolloutAvailabilityProbeManifest(rolloutNamespace, token)
		Expect(err).NotTo(HaveOccurred())
		Expect(env.Apply(ctx, rolloutNamespace, probeManifest)).To(Succeed())
		Expect(env.WaitForDeployment(ctx, rolloutNamespace, "auth-gateway-rollout-probe", 3*time.Minute)).To(Succeed())
		probeNames, err := env.PodNames(ctx, rolloutNamespace, rolloutProbeSelector)
		Expect(err).NotTo(HaveOccurred())
		Expect(probeNames).To(HaveLen(1))
		probePodName := probeNames[0]
		Eventually(func() int {
			logs, logErr := env.ContainerLogs(ctx, rolloutNamespace, probePodName, "curl-probe", 0)
			if logErr != nil {
				return 0
			}
			statuses := rolloutProbeStatuses(logs)
			return len(statuses)
		}).WithContext(ctx).WithTimeout(30 * time.Second).WithPolling(250 * time.Millisecond).Should(BeNumerically(">=", 5))
		expectSuccessfulRolloutProbe(ctx, rolloutNamespace, probePodName)

		restartGatewayWithAvailabilityProbe(ctx, rolloutNamespace, probePodName, stableUIDs)
		newUIDs := rolloutPodUIDs(ctx, rolloutNamespace)
		Expect(newUIDs).To(HaveLen(2))
		Expect(newUIDs).NotTo(Equal(stableUIDs), "a Deployment restart must replace the gateway Pods")
		endpoints = openRolloutPodEndpoints(ctx, rolloutNamespace, *gatewayConfig.Listener.Port)
		for _, endpoint := range endpoints {
			status, body, err := requestRolloutHTTP(ctx, gateway, endpoint, rolloutHost, token)
			Expect(err).NotTo(HaveOccurred(), endpoint.identity.Name)
			expectRolloutEcho(status, body, "team-c")
			newCount, err := rolloutMetricCount(ctx, endpoint, newMetricLabels)
			Expect(err).NotTo(HaveOccurred(), endpoint.identity.Name)
			Expect(newCount).To(BeNumerically(">", 0), endpoint.identity.Name+" did not use the new bootstrap metric label binding")
		}
		expectSuccessfulRolloutProbe(ctx, rolloutNamespace, probePodName)
	}, SpecTimeout(9*time.Minute))
})

func loadRolloutJWTConfig(namespace string) (config.Config, error) {
	fixture, err := env.Fixture("jwt-gateway.yaml")
	if err != nil {
		return config.Config{}, err
	}
	gatewayConfig, err := config.Load(bytes.NewReader(fixture))
	if err != nil {
		return config.Config{}, err
	}
	gatewayConfig.Kubernetes.Namespace = namespace
	for i := range gatewayConfig.Authenticators {
		gatewayConfig.Authenticators[i].JWT.JWKS.URI = "https://jwks." + namespace + ".svc.cluster.local/" + gatewayConfig.Authenticators[i].Name
		gatewayConfig.Authenticators[i].JWT.JWKS.TrustedCA = jwtTrustedCA()
	}
	return gatewayConfig, nil
}

func openRolloutPodEndpoints(ctx SpecContext, namespace string, listenerPort uint32) []rolloutPodEndpoint {
	identities := rolloutPodIdentities(ctx, namespace)
	Expect(identities).To(HaveLen(2))
	endpoints := make([]rolloutPodEndpoint, 0, len(identities))
	for _, identity := range identities {
		endpoints = append(endpoints, rolloutPodEndpoint{
			identity:     identity,
			namespace:    namespace,
			listenerPort: int(listenerPort),
		})
	}
	return endpoints
}

func requestRolloutHTTP(ctx context.Context, gateway *jwtE2E, endpoint rolloutPodEndpoint, host, token string) (int, []byte, error) {
	address, stop, err := env.Forward(ctx, endpoint.namespace, "pod/"+endpoint.identity.Name, endpoint.listenerPort)
	if err != nil {
		return 0, nil, err
	}
	defer stop()
	return gateway.request(ctx, address, host, false, token, false)
}

func requestRolloutHTTPS(ctx context.Context, endpoint rolloutPodEndpoint, serverName, host, method, path string, body []byte, headers http.Header, rootCAs *x509.CertPool) (*httpsResult, error) {
	address, stop, err := env.Forward(ctx, endpoint.namespace, "pod/"+endpoint.identity.Name, endpoint.listenerPort)
	if err != nil {
		return nil, err
	}
	defer stop()
	return requestHTTPSWithMethodAndBody(ctx, address, serverName, host, method, path, body, headers, rootCAs)
}

func rolloutMetricCount(ctx context.Context, endpoint rolloutPodEndpoint, labels map[string]string) (uint64, error) {
	address, stop, err := env.Forward(ctx, endpoint.namespace, "pod/"+endpoint.identity.Name, 9901)
	if err != nil {
		return 0, err
	}
	defer stop()
	return requestMetricCount(ctx, address, labels)
}

func rolloutPodIdentities(ctx context.Context, namespace string) []framework.PodIdentity {
	identities, err := env.PodIdentities(ctx, namespace, rolloutPodSelector)
	Expect(err).NotTo(HaveOccurred())
	return identities
}

func rolloutPodIdentitiesFromEndpoints(endpoints []rolloutPodEndpoint) []framework.PodIdentity {
	identities := make([]framework.PodIdentity, 0, len(endpoints))
	for _, endpoint := range endpoints {
		identities = append(identities, endpoint.identity)
	}
	return identities
}

func rolloutPodUIDs(ctx context.Context, namespace string) []string {
	uids, err := env.PodUIDs(ctx, namespace, rolloutPodSelector)
	Expect(err).NotTo(HaveOccurred())
	return uids
}

func rolloutJWTToken(gateway *jwtE2E) string {
	claims := jwtTestClaims("customer-a")
	claims["exp"] = time.Now().Add(30 * time.Minute).Unix()
	return gateway.token("issuer-one", claims, nil)
}

func expectRolloutEcho(status int, body []byte, wantTenant string) {
	Expect(status).To(Equal(http.StatusOK), string(body))
	echo, err := decodeHTTPBinEcho(body)
	Expect(err).NotTo(HaveOccurred())
	Expect(echo.Method).To(Equal(http.MethodGet))
	Expect(echo.URL).To(HaveSuffix("/anything"))
	Expect(headerValue(echo.Headers, "X-Scope-OrgID")).To(Equal(wantTenant))
	Expect(headerValue(echo.Headers, "X-Writer-ID")).To(Equal("writer-17"))
	Expect(headerValue(echo.Headers, "Authorization")).To(BeEmpty())
}

func rolloutAvailabilityProbeManifest(namespace, token string) ([]byte, error) {
	labels := map[string]string{"app.kubernetes.io/name": "auth-gateway-rollout-probe"}
	probeScript := `while true; do
  status="$(curl --silent --show-error --connect-timeout 1 --max-time 3 --output /dev/null --write-out '%{http_code}' --header "Host: ${REQUEST_HOST}" --header "Authorization: Bearer ${TOKEN}" "${TARGET_URL}")"
  printf '%s\n' "${status:-000}"
  sleep 0.2
done`
	deployment := &appsv1.Deployment{
		TypeMeta:   metav1.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"},
		ObjectMeta: metav1.ObjectMeta{Name: "auth-gateway-rollout-probe", Namespace: namespace},
		Spec: appsv1.DeploymentSpec{
			Replicas: new(int32(1)),
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{Containers: []corev1.Container{{
					Name:            "curl-probe",
					Image:           rolloutAvailabilityProbeImage(),
					ImagePullPolicy: corev1.PullIfNotPresent,
					Command:         []string{"/bin/sh", "-c", probeScript},
					Env: []corev1.EnvVar{
						{Name: "REQUEST_HOST", Value: rolloutHost},
						{Name: "TARGET_URL", Value: "http://auth-gateway." + namespace + ".svc.cluster.local:80/protected"},
						{Name: "TOKEN", Value: token},
					},
				}}},
			},
		},
	}
	return yamlDocuments(deployment)
}

func rolloutAvailabilityProbeImage() string {
	if image := os.Getenv("AUTH_GATEWAY_E2E_ROLLOUT_PROBE_IMAGE"); image != "" {
		return image
	}
	return defaultRolloutProbeImage
}

func TestRolloutAvailabilityProbeTargetsGatewayService(t *testing.T) {
	const namespace = "gateway-test"
	manifest, err := rolloutAvailabilityProbeManifest(namespace, "signed-test-token")
	if err != nil {
		t.Fatalf("generate availability probe: %v", err)
	}
	var deployment appsv1.Deployment
	if err := yaml.Unmarshal(manifest, &deployment); err != nil {
		t.Fatalf("decode availability probe: %v", err)
	}
	if deployment.Spec.Replicas == nil || *deployment.Spec.Replicas != 1 {
		t.Fatalf("probe replicas = %v, want 1", deployment.Spec.Replicas)
	}
	if len(deployment.Spec.Template.Spec.Containers) != 1 {
		t.Fatalf("probe has %d containers, want 1", len(deployment.Spec.Template.Spec.Containers))
	}
	container := deployment.Spec.Template.Spec.Containers[0]
	environment := make(map[string]string, len(container.Env))
	for _, value := range container.Env {
		environment[value.Name] = value.Value
	}
	if environment["TARGET_URL"] != "http://auth-gateway."+namespace+".svc.cluster.local:80/protected" {
		t.Fatalf("probe TARGET_URL = %q, want gateway Service URL", environment["TARGET_URL"])
	}
	if environment["REQUEST_HOST"] != rolloutHost || environment["TOKEN"] != "signed-test-token" {
		t.Fatalf("probe auth environment = %#v, want gateway host and supplied token", environment)
	}
	command := strings.Join(container.Command, " ")
	for _, expected := range []string{"curl", "--connect-timeout 1", "--max-time 3", "--write-out '%{http_code}'", "sleep 0.2"} {
		if !strings.Contains(command, expected) {
			t.Errorf("probe command %q does not contain %q", command, expected)
		}
	}
}

func rolloutProbeStatuses(logs []byte) []string {
	var statuses []string
	for _, line := range strings.Split(string(logs), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			statuses = append(statuses, line)
		}
	}
	return statuses
}

func expectSuccessfulRolloutProbe(ctx context.Context, namespace, podName string) []string {
	logs, err := env.ContainerLogs(ctx, namespace, podName, "curl-probe", 0)
	Expect(err).NotTo(HaveOccurred())
	statuses := rolloutProbeStatuses(logs)
	Expect(statuses).NotTo(BeEmpty())
	recentStatuses := statuses
	if len(recentStatuses) > 20 {
		recentStatuses = recentStatuses[len(recentStatuses)-20:]
	}
	for _, status := range statuses {
		Expect(status).To(Equal("200"), "the in-cluster Service probe observed a failed or non-200 gateway response; recent output: %s", strings.Join(recentStatuses, ", "))
	}
	return statuses
}

func restartGatewayWithAvailabilityProbe(ctx SpecContext, namespace, probePodName string, previousUIDs []string) {
	initialStatuses := expectSuccessfulRolloutProbe(ctx, namespace, probePodName)
	lastStatusCount := len(initialStatuses)
	restartDone := make(chan error, 1)
	go func() {
		restartDone <- env.RestartDeployment(ctx, namespace, "auth-gateway", 4*time.Minute)
	}()

	deadline := time.NewTimer(4*time.Minute + 15*time.Second)
	defer deadline.Stop()
	poll := time.NewTicker(300 * time.Millisecond)
	defer poll.Stop()
	var restartErr error
	completed := false
	uidSetChanged := false
	requestsDuringRollout := false
	for !completed {
		currentUIDs := rolloutPodUIDs(ctx, namespace)
		if !slices.Equal(currentUIDs, previousUIDs) {
			uidSetChanged = true
		}
		statuses := expectSuccessfulRolloutProbe(ctx, namespace, probePodName)
		if uidSetChanged && len(statuses) > lastStatusCount {
			requestsDuringRollout = true
		}
		if len(statuses) > lastStatusCount {
			lastStatusCount = len(statuses)
		}

		select {
		case restartErr = <-restartDone:
			completed = true
		case <-deadline.C:
			Fail("gateway Deployment restart did not finish within four minutes")
		case <-ctx.Done():
			Fail("test context ended while the gateway Deployment was restarting")
		case <-poll.C:
		}
	}
	Expect(restartErr).NotTo(HaveOccurred())
	Expect(uidSetChanged).To(BeTrue(), "the gateway Pod UID set should change during the restart")
	Expect(requestsDuringRollout).To(BeTrue(), "the Service probe should keep sending successful requests while Pods are being replaced")
	expectSuccessfulRolloutProbe(ctx, namespace, probePodName)
}
