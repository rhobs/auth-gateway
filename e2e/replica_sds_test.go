//go:build e2e

package e2e

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"net/http"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/rhobs/auth-gateway/config"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	replicaTLSHost   = "tls.replica-sds.auth-gateway.test"
	replicaHTTPHost  = "http.replica-sds.auth-gateway.test"
	replicaTLSSecret = "replica-gateway-tls"
)

var replicaSDSNamespace = e2eNamespace("auth-gateway-replica-sds-e2e")

type replicaTLSEndpoint struct {
	name    string
	uid     string
	address string
}

var _ = Describe("Multi-replica server TLS", Label("gateway", "tls", "replicas", "namespace-"+replicaSDSNamespace), Ordered, func() {
	var rootCAs *x509.CertPool
	var endpoints []replicaTLSEndpoint
	var serviceHTTPAddress string
	var serviceHTTPSAddress string
	var initialUIDs []string
	var initialSerials map[string]string

	BeforeAll(func(ctx SpecContext) {
		DeferCleanup(func(ctx SpecContext) {
			Expect(env.DeleteNamespace(ctx, replicaSDSNamespace)).To(Succeed())
		}, NodeTimeout(3*time.Minute))

		Expect(env.DeleteNamespace(ctx, replicaSDSNamespace)).To(Succeed())
		Expect(env.CreateNamespace(ctx, replicaSDSNamespace)).To(Succeed())

		backend, err := env.Fixture("httpbin.yaml")
		Expect(err).NotTo(HaveOccurred())
		Expect(env.Apply(ctx, replicaSDSNamespace, backend)).To(Succeed())
		Expect(env.WaitForDeployment(ctx, replicaSDSNamespace, "httpbin", 4*time.Minute)).To(Succeed())

		certificates, err := makeJWTTestCertificates([]string{replicaTLSHost})
		Expect(err).NotTo(HaveOccurred())
		rootCAs = x509.NewCertPool()
		rootCAs.AddCert(certificates.root)
		secretManifest, err := yamlDocuments(replicaGatewayTLSSecret(certificates))
		Expect(err).NotTo(HaveOccurred())
		Expect(env.Apply(ctx, replicaSDSNamespace, secretManifest)).To(Succeed())

		fixture, err := env.Fixture("gateway.yaml")
		Expect(err).NotTo(HaveOccurred())
		gatewayConfig, err := config.Load(bytes.NewReader(fixture))
		Expect(err).NotTo(HaveOccurred())
		gatewayConfig.Kubernetes.Namespace = replicaSDSNamespace
		gatewayConfig.Kubernetes.Replicas = new(int32(2))
		gatewayConfig.Kubernetes.ServicePort = new(int32(18080))
		gatewayConfig.Kubernetes.HTTPSServicePort = new(int32(18443))
		upstreamHealth, found := findAPI(gatewayConfig.APIs, "upstream-health")
		Expect(found).To(BeTrue(), "upstream-health API is missing from the fixture")
		gatewayConfig.APIs = []config.API{upstreamHealth}
		gatewayConfig.Servers = []config.Server{
			{Hostname: replicaHTTPHost, APIs: []string{"upstream-health"}},
			{Hostname: replicaTLSHost, TLSConfig: &config.ServerTLS{Secret: replicaTLSSecret}, APIs: []string{"upstream-health"}},
		}
		resources, err := config.GenerateKubernetes(gatewayConfig)
		Expect(err).NotTo(HaveOccurred())
		manifest, err := resources.YAML()
		Expect(err).NotTo(HaveOccurred())
		Expect(env.Apply(ctx, replicaSDSNamespace, manifest)).To(Succeed())
		Expect(env.WaitForDeployment(ctx, replicaSDSNamespace, "auth-gateway", 4*time.Minute)).To(Succeed())

		identities, err := env.PodIdentities(ctx, replicaSDSNamespace, gatewayPodSelector)
		Expect(err).NotTo(HaveOccurred())
		Expect(identities).To(HaveLen(2))
		initialUIDs, err = env.PodUIDs(ctx, replicaSDSNamespace, gatewayPodSelector)
		Expect(err).NotTo(HaveOccurred())
		for _, identity := range identities {
			address := env.ForwardWithCleanup(ctx, replicaSDSNamespace, "pod/"+identity.Name, int(*gatewayConfig.Listener.Port))
			endpoints = append(endpoints, replicaTLSEndpoint{name: identity.Name, uid: identity.UID, address: address})
		}
		serviceHTTPAddress = env.ForwardWithCleanup(ctx, replicaSDSNamespace, "service/auth-gateway", 18080)
		serviceHTTPSAddress = env.ForwardWithCleanup(ctx, replicaSDSNamespace, "service/auth-gateway", 18443)
	}, NodeTimeout(12*time.Minute))

	It("serves custom Service ports and reloads a TLS Secret on both replicas", func(ctx SpecContext) {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+serviceHTTPAddress+"/upstream-health", nil)
		Expect(err).NotTo(HaveOccurred())
		request.Host = replicaHTTPHost
		response, err := testClient.Do(request)
		Expect(err).NotTo(HaveOccurred())
		body, err := readAndCloseResponseBody(response, 1<<20)
		Expect(err).NotTo(HaveOccurred())
		Expect(response.StatusCode).To(Equal(http.StatusOK), string(body))

		serviceTLS, err := requestHTTPS(ctx, serviceHTTPSAddress, replicaTLSHost, replicaTLSHost, "/upstream-health", rootCAs)
		Expect(err).NotTo(HaveOccurred())
		Expect(serviceTLS.status).To(Equal(http.StatusOK), string(serviceTLS.body))
		initialSerials = make(map[string]string, len(endpoints))
		for _, endpoint := range endpoints {
			result, err := requestHTTPS(ctx, endpoint.address, replicaTLSHost, replicaTLSHost, "/upstream-health", rootCAs)
			Expect(err).NotTo(HaveOccurred(), endpoint.name)
			Expect(result.status).To(Equal(http.StatusOK), endpoint.name+": "+string(result.body))
			initialSerials[endpoint.uid] = result.certificate.SerialNumber.String()
		}

		rotatedCertificates, err := makeJWTTestCertificates([]string{replicaTLSHost})
		Expect(err).NotTo(HaveOccurred())
		rootCAs.AddCert(rotatedCertificates.root)
		rotatedSecretManifest, err := yamlDocuments(replicaGatewayTLSSecret(rotatedCertificates))
		Expect(err).NotTo(HaveOccurred())
		Expect(env.Apply(ctx, replicaSDSNamespace, rotatedSecretManifest)).To(Succeed())

		Eventually(func() error {
			for _, endpoint := range endpoints {
				result, err := requestHTTPS(ctx, endpoint.address, replicaTLSHost, replicaTLSHost, "/upstream-health", rootCAs)
				if err != nil {
					return fmt.Errorf("request through replica %s: %w", endpoint.name, err)
				}
				if result.status != http.StatusOK {
					return fmt.Errorf("replica %s returned HTTP %d: %s", endpoint.name, result.status, result.body)
				}
				if result.certificate.SerialNumber.String() == initialSerials[endpoint.uid] {
					return fmt.Errorf("replica %s still serves certificate serial %s", endpoint.name, initialSerials[endpoint.uid])
				}
			}
			return nil
		}).WithContext(ctx).WithTimeout(3 * time.Minute).WithPolling(500 * time.Millisecond).Should(Succeed())

		finalUIDs, err := env.PodUIDs(ctx, replicaSDSNamespace, gatewayPodSelector)
		Expect(err).NotTo(HaveOccurred())
		Expect(finalUIDs).To(Equal(initialUIDs), "TLS Secret updates must not replace gateway Pods")
	}, SpecTimeout(5*time.Minute))
})

func findAPI(apis []config.API, name string) (config.API, bool) {
	for _, api := range apis {
		if api.Name == name {
			return api, true
		}
	}
	return config.API{}, false
}

func replicaGatewayTLSSecret(certificates *jwtTestCertificates) *corev1.Secret {
	return &corev1.Secret{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
		ObjectMeta: metav1.ObjectMeta{Name: replicaTLSSecret, Namespace: replicaSDSNamespace},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       certificates.chainPEM,
			corev1.TLSPrivateKeyKey: certificates.keyPEM,
		},
	}
}
