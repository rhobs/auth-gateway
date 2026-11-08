package kubernetes

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	jwt "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/jwt_authn/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	configuration "github.com/rhobs/auth-gateway/pkg/config"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGenerateKubernetesIsolatesGatewaySelectors(t *testing.T) {
	for _, cluster := range []string{"auth-gateway", "shared-cluster"} {
		t.Run(cluster, func(t *testing.T) {
			for _, name := range []string{"gateway-one", "gateway-two"} {
				c := loadConfigCase(t, "public-routing")
				c.Kubernetes.Name = name
				c.Node.Cluster = cluster
				resources, err := Generate(c)
				if err != nil {
					t.Fatal(err)
				}
				want := map[string]string{
					"app.kubernetes.io/name":     "auth-gateway",
					"app.kubernetes.io/instance": name,
				}
				for _, got := range []map[string]string{
					resources.ServiceAccount.Labels,
					resources.Deployment.Labels,
					resources.Deployment.Spec.Selector.MatchLabels,
					resources.Deployment.Spec.Template.Labels,
					resources.Service.Labels,
					resources.Service.Spec.Selector,
				} {
					assertConfigDiff(t, name+" gateway labels", want, got)
				}
			}
		})
	}
}

func TestGenerateKubernetesSelectorsIgnoreNodeCluster(t *testing.T) {
	c := loadConfigCase(t, "public-routing")
	before, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	c.Node.Cluster = "another-envoy-cluster"
	after, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	assertConfigDiff(t, "Deployment selector after node.cluster update", before.Deployment.Spec.Selector, after.Deployment.Spec.Selector)
	assertConfigDiff(t, "Pod labels after node.cluster update", before.Deployment.Spec.Template.Labels, after.Deployment.Spec.Template.Labels)
	assertConfigDiff(t, "Service selector after node.cluster update", before.Service.Spec.Selector, after.Service.Spec.Selector)
}

func TestGenerateKubernetesPreservesYAMLImageOverrides(t *testing.T) {
	const input = `version: 1
servers:
  - hostname: auth.example.com
    apis: [status]
apis:
  - name: status
    upstream:
      address: httpbin
      port: 8080
    routes:
      - methods: [GET]
        path:
          exact: /status
kubernetes:
  name: auth-gateway
  namespace: image-overrides
  image: mirror.example.com/envoy:approved
  otel_collector_image: mirror.example.com/otel-collector:approved
`
	c, err := configuration.Load(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"mirror.example.com/envoy:approved",
		"mirror.example.com/otel-collector:approved",
	}

	resources, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	containers := resources.Deployment.Spec.Template.Spec.Containers
	if len(containers) != 2 {
		t.Fatalf("generated containers = %d, want Envoy and collector", len(containers))
	}
	got := []string{containers[0].Image, containers[1].Image}
	assertConfigDiff(t, "generated Kubernetes image overrides", want, got)
}

func TestKubernetesResourcesObjectsReturnsApplyOrder(t *testing.T) {
	resources := &Resources{
		ConfigMap:              corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "gateway"}},
		OTelCollectorConfigMap: &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "collector"}},
		ServiceAccount:         corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "service-account"}},
		Deployment:             appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "deployment"}},
		Service:                corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "service"}},
	}

	for _, test := range []struct {
		name string
		want []string
		edit func(*Resources)
	}{
		{name: "all resources", want: []string{"gateway", "collector", "service-account", "deployment", "service"}},
		{name: "without optional config maps", want: []string{"gateway", "service-account", "deployment", "service"}, edit: func(r *Resources) {
			r.OTelCollectorConfigMap = nil
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			current := *resources
			if test.edit != nil {
				test.edit(&current)
			}
			objects := current.Objects()
			if len(objects) != len(test.want) {
				t.Fatalf("object count = %d, want %d", len(objects), len(test.want))
			}
			for index, object := range objects {
				metadata, ok := object.(metav1.Object)
				if !ok {
					t.Fatalf("object %d has type %T, want Kubernetes metadata", index, object)
				}
				if got := metadata.GetName(); got != test.want[index] {
					t.Fatalf("object %d name = %q, want %q", index, got, test.want[index])
				}
			}
		})
	}
}

func TestGenerateKubernetesMountsOneExternalAPIKeySecret(t *testing.T) {
	c := loadConfigCase(t, "api-key-auth")
	resources, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, object := range resources.Objects() {
		if _, ok := object.(*corev1.Secret); ok {
			t.Fatal("generated gateway resources included API-key credentials")
		}
	}
	pod := resources.Deployment.Spec.Template.Spec
	var secretVolume, secretMount int
	for _, volume := range pod.Volumes {
		if volume.Name != configuration.ApiKeySecretVolumeName {
			continue
		}
		secretVolume++
		if volume.Secret == nil || volume.Secret.SecretName != "gateway-api-keys" ||
			len(volume.Secret.Items) != 1 || volume.Secret.Items[0].Key != configuration.ApiKeySecretFilename ||
			volume.Secret.Items[0].Path != configuration.ApiKeySecretFilename {
			t.Fatalf("API-key Secret volume = %#v", volume)
		}
	}
	for _, mount := range pod.Containers[0].VolumeMounts {
		if mount.Name != configuration.ApiKeySecretVolumeName {
			continue
		}
		secretMount++
		if mount.MountPath != configuration.ApiKeyDirectory || !mount.ReadOnly || mount.SubPath != "" || mount.SubPathExpr != "" {
			t.Fatalf("API-key Secret mount cannot reload the projected directory: %#v", mount)
		}
	}
	if secretVolume != 1 || secretMount != 1 {
		t.Fatalf("API-key Secret volumes/mounts = %d/%d, want one shared by all servers", secretVolume, secretMount)
	}
	if len(resources.Deployment.Spec.Template.Annotations) != 0 {
		t.Fatalf("Secret updates must not require Pod checksum changes: %#v", resources.Deployment.Spec.Template.Annotations)
	}
}

func TestGenerateKubernetesMountsServerTLSSecretAndSharesListenerPort(t *testing.T) {
	config, err := configuration.Load(strings.NewReader(readFixture(t, "public-routing/config.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := &gatewayapi.ServerTLS{
		Secret:      "auth-gateway-tls",
		Certificate: "/etc/gateway-certs/tls.crt",
		PrivateKey:  "/etc/gateway-certs/tls.key",
	}
	config.Servers = []gatewayapi.Server{
		{Hostname: "auth.example.com", APIs: []string{"metrics"}},
		{Hostname: "mts.auth.example.com", TLSConfig: tlsConfig, APIs: []string{"metrics"}},
	}
	resources, err := Generate(config)
	if err != nil {
		t.Fatal(err)
	}

	ports := make(map[string]struct {
		port       int32
		targetPort string
	}, len(resources.Service.Spec.Ports))
	for _, port := range resources.Service.Spec.Ports {
		ports[port.Name] = struct {
			port       int32
			targetPort string
		}{port: port.Port, targetPort: port.TargetPort.String()}
	}
	if got := ports["http"]; got.port != configuration.DefaultServicePort || got.targetPort != "http" {
		t.Fatalf("HTTP Service port = %#v", got)
	}
	if got := ports["https"]; got.port != configuration.DefaultHTTPSServicePort || got.targetPort != "http" {
		t.Fatalf("HTTPS Service port = %#v, want port 443 targeting the same Envoy listener", got)
	}
	if got := resources.ConfigMap.Data["server-certificate-1.yaml"]; got == "" {
		t.Fatalf("config Map does not contain the server TLS SDS resource")
	}

	var tlsVolumeFound bool
	for _, volume := range resources.Deployment.Spec.Template.Spec.Volumes {
		if volume.Name == "server-tls-1" && volume.Secret != nil {
			tlsVolumeFound = true
			if volume.Secret.SecretName != tlsConfig.Secret {
				t.Errorf("mounted Secret = %q, want %q", volume.Secret.SecretName, tlsConfig.Secret)
			}
			if got := volume.Secret.Items; len(got) != 2 || got[0].Key != "tls.crt" || got[0].Path != "tls.crt" || got[1].Key != "tls.key" || got[1].Path != "tls.key" {
				t.Errorf("mounted TLS Secret items = %#v", got)
			}
		}
	}
	if !tlsVolumeFound {
		t.Fatal("Deployment has no projected server TLS Secret volume")
	}
	var tlsMountFound bool
	for _, mount := range resources.Deployment.Spec.Template.Spec.Containers[0].VolumeMounts {
		if mount.Name == "server-tls-1" && mount.MountPath == "/etc/gateway-certs" && mount.ReadOnly {
			tlsMountFound = true
		}
	}
	if !tlsMountFound {
		t.Fatal("Envoy does not mount the server TLS Secret directory read-only")
	}
}

func TestGenerateKubernetesOmitsHTTPServicePortForHTTPSOnly(t *testing.T) {
	config, err := configuration.Load(strings.NewReader(readFixture(t, "public-routing/config.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	config.Servers = []gatewayapi.Server{{
		Hostname:  "mts.auth.example.com",
		TLSConfig: &gatewayapi.ServerTLS{Secret: "auth-gateway-tls"},
		APIs:      []string{"metrics"},
	}}
	resources, err := Generate(config)
	if err != nil {
		t.Fatal(err)
	}
	if resources.Service.Spec.Ports[0].Name != "https" || resources.Service.Spec.Ports[0].Port != configuration.DefaultHTTPSServicePort {
		t.Fatalf("HTTPS-only Service port = %#v", resources.Service.Spec.Ports[0])
	}
	for _, port := range resources.Service.Spec.Ports {
		if port.Name == "http" {
			t.Fatalf("HTTPS-only Service exposes an HTTP port: %#v", resources.Service.Spec.Ports)
		}
	}
}

func TestGenerateKubernetesRequiresSettings(t *testing.T) {
	config, err := configuration.Load(strings.NewReader(readFixture(t, "public-routing/config.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	config.Kubernetes = nil
	if _, err := Generate(config); err == nil || !strings.Contains(err.Error(), "kubernetes settings are required") {
		t.Fatalf("GenerateKubernetes error = %v, want missing Kubernetes settings", err)
	}
}

func TestGenerateKubernetesSharesTLSSecretMount(t *testing.T) {
	config, err := configuration.Load(strings.NewReader(readFixture(t, "server-tls/config.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	config.Servers[2].TLSConfig = config.Servers[1].TLSConfig
	resources, err := Generate(config)
	if err != nil {
		t.Fatal(err)
	}
	pod := resources.Deployment.Spec.Template.Spec
	secretVolumes := 0
	for _, volume := range pod.Volumes {
		if volume.Secret != nil {
			secretVolumes++
			if volume.Secret.SecretName != "auth-gateway-tls" || volume.Secret.DefaultMode == nil || *volume.Secret.DefaultMode != 0o444 {
				t.Fatalf("unexpected shared Secret volume: %#v", volume.Secret)
			}
		}
	}
	if secretVolumes != 1 {
		t.Fatalf("shared Secret volume count = %d, want 1", secretVolumes)
	}
	tlsMounts := 0
	for _, mount := range pod.Containers[0].VolumeMounts {
		if mount.Name == "server-tls-1" {
			tlsMounts++
			if mount.MountPath != "/etc/auth-gateway-tls" || !mount.ReadOnly || mount.SubPath != "" || mount.SubPathExpr != "" {
				t.Fatalf("shared Secret mount prevents directory projection: %#v", mount)
			}
		}
	}
	if tlsMounts != 1 {
		t.Fatalf("shared TLS mount count = %d, want 1", tlsMounts)
	}
	if len(resources.ConfigMap.Data) != 3 {
		t.Fatal("shared certificate servers did not get separate SDS files")
	}
	for _, volume := range pod.Volumes {
		if volume.ConfigMap == nil || volume.Name != "config" {
			continue
		}
		if len(volume.ConfigMap.Items) != len(resources.ConfigMap.Data) {
			t.Fatal("Deployment does not project every generated config file")
		}
		previous := ""
		for _, item := range volume.ConfigMap.Items {
			if _, exists := resources.ConfigMap.Data[item.Key]; !exists || item.Path != item.Key || item.Key <= previous {
				t.Fatalf("unexpected ConfigMap item: %#v", item)
			}
			previous = item.Key
		}
	}
}

func TestGenerateKubernetesMountsSharedSecretAtDifferentPaths(t *testing.T) {
	config, err := configuration.Load(strings.NewReader(readFixture(t, "server-tls/config.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	config.Servers[2].TLSConfig = &gatewayapi.ServerTLS{
		Secret: "auth-gateway-tls", Certificate: "/etc/query-tls/server.pem", PrivateKey: "/etc/query-tls/key.pem",
	}
	resources, err := Generate(config)
	if err != nil {
		t.Fatal(err)
	}
	secretVolumes := 0
	for _, volume := range resources.Deployment.Spec.Template.Spec.Volumes {
		if volume.Secret != nil {
			secretVolumes++
			if volume.Secret.SecretName != "auth-gateway-tls" {
				t.Fatal("mounted a different Secret")
			}
			if volume.Name == "server-tls-2" {
				items := volume.Secret.Items
				if len(items) != 2 || items[0].Path != "server.pem" || items[1].Path != "key.pem" {
					t.Fatalf("custom certificate filenames = %#v", items)
				}
			}
		}
	}
	if secretVolumes != 2 {
		t.Fatalf("Secret volume count = %d, want 2 for distinct paths", secretVolumes)
	}
}

func TestGenerateKubernetesFitsConfigMapNameLimit(t *testing.T) {
	config, err := configuration.Load(strings.NewReader(readFixture(t, "public-routing/config.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	config.Kubernetes.Name = strings.Repeat("a", 56)
	resources, err := Generate(config)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(resources.ConfigMap.Name); got != 63 {
		t.Fatalf("ConfigMap name length = %d, want 63", got)
	}
}

func TestEnvoyConcurrencyGeneration(t *testing.T) {
	c := loadConfigCase(t, "public-routing")
	c.Kubernetes.EnvoyConcurrency = new(uint32(3))
	r, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	args := r.Deployment.Spec.Template.Spec.Containers[0].Args
	index := slices.Index(args, "--concurrency")
	if index < 0 || index+1 == len(args) || args[index+1] != "3" {
		t.Fatalf("Envoy args = %v", args)
	}
	c.Kubernetes.EnvoyConcurrency = nil
	c.Kubernetes.Resources.Limits["cpu"] = "4"
	r, err = Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(r.Deployment.Spec.Template.Spec.Containers[0].Args, "--concurrency") {
		t.Fatal("worker count inferred from CPU limit")
	}
}

func TestKubernetesDeploymentOverrides(t *testing.T) {
	c := loadConfigCase(t, "server-tls")
	c.Kubernetes.Replicas = new(int32(2))
	c.Kubernetes.ServicePort = new(int32(18080))
	c.Kubernetes.HTTPSServicePort = new(int32(18443))
	c.Kubernetes.EnvoyConcurrency = new(uint32(3))
	c.Kubernetes.Resources = gatewayapi.KubernetesResourceRequirements{
		Requests: map[string]string{"cpu": "250m", "memory": "128Mi"},
		Limits:   map[string]string{"cpu": "1", "memory": "512Mi"},
	}

	resources, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	if resources.Deployment.Spec.Replicas == nil || *resources.Deployment.Spec.Replicas != 2 {
		t.Fatalf("Deployment replicas = %v, want 2", resources.Deployment.Spec.Replicas)
	}
	ports := make(map[string]int32, len(resources.Service.Spec.Ports))
	for _, port := range resources.Service.Spec.Ports {
		ports[port.Name] = port.Port
	}
	wantPorts := map[string]int32{"http": 18080, "https": 18443, "metrics": configuration.DefaultOTelMetricsPort}
	if !reflect.DeepEqual(ports, wantPorts) {
		t.Fatalf("Service ports = %v, want %v", ports, wantPorts)
	}

	envoy := resources.Deployment.Spec.Template.Spec.Containers[0]
	concurrencyIndex := slices.Index(envoy.Args, "--concurrency")
	if concurrencyIndex < 0 || concurrencyIndex+1 >= len(envoy.Args) {
		t.Fatalf("Envoy args = %v, want --concurrency followed by 3", envoy.Args)
	}
	if got, want := envoy.Args[concurrencyIndex+1], "3"; got != want {
		t.Fatalf("Envoy concurrency = %q, want %q", got, want)
	}
	wantResources := corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("250m"),
			corev1.ResourceMemory: resource.MustParse("128Mi"),
		},
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("1"),
			corev1.ResourceMemory: resource.MustParse("512Mi"),
		},
	}
	if !reflect.DeepEqual(envoy.Resources, wantResources) {
		t.Fatalf("Envoy resources = %#v, want %#v", envoy.Resources, wantResources)
	}
}

func TestKubernetesDeploymentDrainsBeforeTerminating(t *testing.T) {
	c := loadConfigCase(t, "server-tls")
	resources, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	podSpec := resources.Deployment.Spec.Template.Spec
	if podSpec.TerminationGracePeriodSeconds == nil || *podSpec.TerminationGracePeriodSeconds != configuration.TerminationGracePeriodSeconds {
		t.Fatalf("termination grace period = %v, want %d seconds", podSpec.TerminationGracePeriodSeconds, configuration.TerminationGracePeriodSeconds)
	}

	envoy := podSpec.Containers[0]
	if envoy.Lifecycle == nil || envoy.Lifecycle.PreStop == nil || envoy.Lifecycle.PreStop.Exec == nil {
		t.Fatalf("Envoy lifecycle = %#v, want a pre-stop drain delay", envoy.Lifecycle)
	}
	wantCommand := []string{"/bin/sh", "-c", fmt.Sprintf("sleep %d", configuration.PreStopDrainDelaySeconds)}
	if !slices.Equal(envoy.Lifecycle.PreStop.Exec.Command, wantCommand) {
		t.Fatalf("Envoy pre-stop command = %v, want %v", envoy.Lifecycle.PreStop.Exec.Command, wantCommand)
	}
}

func TestKubernetesPodRunsHardened(t *testing.T) {
	for _, test := range []struct {
		name       string
		metrics    bool
		tracing    bool
		containers []string
	}{
		{name: "without collector", containers: []string{"envoy"}},
		{name: "metrics", metrics: true, containers: []string{"envoy", "metrics"}},
		{name: "tracing", tracing: true, containers: []string{"envoy", "metrics"}},
		{name: "metrics and tracing", metrics: true, tracing: true, containers: []string{"envoy", "metrics"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := loadConfigCase(t, "public-routing")
			c.Observability.Metrics.Enabled = new(test.metrics)
			c.Observability.Tracing.Enabled = new(test.tracing)
			if test.tracing {
				c.Observability.Tracing.Endpoint = "trace-sink:4317"
			}
			resources, err := Generate(c)
			if err != nil {
				t.Fatal(err)
			}
			pod := resources.Deployment.Spec.Template.Spec
			if pod.SecurityContext == nil || pod.SecurityContext.SeccompProfile == nil {
				t.Error("Pod SeccompProfile = nil, want RuntimeDefault")
			} else if got := pod.SecurityContext.SeccompProfile.Type; got != corev1.SeccompProfileTypeRuntimeDefault {
				t.Errorf("Pod SeccompProfile.Type = %q, want RuntimeDefault", got)
			}
			var containerNames []string
			for _, container := range pod.Containers {
				containerNames = append(containerNames, container.Name)
				t.Run(container.Name, func(t *testing.T) {
					security := container.SecurityContext
					if security == nil {
						t.Fatal("SecurityContext = nil, want a hardened SecurityContext")
					}
					if security.AllowPrivilegeEscalation == nil || *security.AllowPrivilegeEscalation {
						t.Errorf("AllowPrivilegeEscalation = %v, want false", security.AllowPrivilegeEscalation)
					}
					if security.ReadOnlyRootFilesystem == nil || !*security.ReadOnlyRootFilesystem {
						t.Errorf("ReadOnlyRootFilesystem = %v, want true", security.ReadOnlyRootFilesystem)
					}
					if security.RunAsNonRoot == nil || !*security.RunAsNonRoot {
						t.Errorf("RunAsNonRoot = %v, want true", security.RunAsNonRoot)
					}
					if security.Capabilities == nil || !slices.Equal(security.Capabilities.Drop, []corev1.Capability{"ALL"}) {
						t.Errorf("Capabilities = %#v, want Drop: [ALL]", security.Capabilities)
					}
					if container.Name == "envoy" {
						if security.RunAsUser == nil || *security.RunAsUser != 101 {
							t.Errorf("RunAsUser = %v, want 101", security.RunAsUser)
						}
						if security.RunAsGroup == nil || *security.RunAsGroup != 101 {
							t.Errorf("RunAsGroup = %v, want 101", security.RunAsGroup)
						}
					} else if security.RunAsUser != nil || security.RunAsGroup != nil {
						t.Errorf("collector UID/GID = %v/%v, want the image's non-root user", security.RunAsUser, security.RunAsGroup)
					}
				})
			}
			assertConfigDiff(t, "container names", test.containers, containerNames)
		})
	}
}

func TestJWKSTransportAndTrust(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-multiple-issuers")
	ca := &gatewayapi.TrustedCA{ConfigMap: &gatewayapi.CAConfigMap{Name: "issuer-ca", Key: "roots.pem"}}
	for i := range c.Authenticators {
		c.Authenticators[i].JWT.JWKS.TrustedCA = ca
	}
	j := &c.Authenticators[0].JWT.JWKS
	j.URI = "https://192.0.2.1:9443/keys"
	j.CacheDuration = duration(15 * time.Second)
	j.FetchTimeout = duration(2 * time.Second)
	j.ConnectTimeout = duration(500 * time.Millisecond)
	r, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	b := decodeBootstrap(t, []byte(r.ConfigMap.Data["envoy.yaml"]))
	manager := decodeHTTPManager(t, b.StaticResources.Listeners[0].FilterChains[0])
	var providers jwt.JwtAuthentication
	for _, f := range manager.HttpFilters {
		if f.Name == "envoy.filters.http.jwt_authn" {
			if err := f.GetTypedConfig().UnmarshalTo(&providers); err != nil {
				t.Fatal(err)
			}
		}
	}
	remote := providers.Providers[c.Authenticators[0].Name].GetRemoteJwks()
	if remote.CacheDuration.AsDuration() != 15*time.Second || remote.HttpUri.Timeout.AsDuration() != 2*time.Second || remote.AsyncFetch != nil || remote.RetryPolicy != nil {
		t.Fatalf("remote JWKS controls = %v", remote)
	}
	for _, cluster := range b.StaticResources.Clusters {
		if !strings.HasPrefix(cluster.Name, "jwks-") {
			continue
		}
		var transport tls.UpstreamTlsContext
		if err := cluster.TransportSocket.GetTypedConfig().UnmarshalTo(&transport); err != nil {
			t.Fatal(err)
		}
		validation := transport.CommonTlsContext.GetValidationContext()
		if validation.TrustedCa.GetFilename() != configuration.FilenameTrustedCA(*ca) || len(validation.MatchTypedSubjectAltNames) != 1 {
			t.Fatalf("trust = %v", validation)
		}
		san := validation.MatchTypedSubjectAltNames[0]
		if cluster.Name == configuration.JwksClusterName(c.Authenticators[0].Name) {
			if transport.Sni != "" || san.SanType != tls.SubjectAltNameMatcher_IP_ADDRESS || san.Matcher.GetExact() != "192.0.2.1" {
				t.Fatalf("IP identity = %v", &transport)
			}
			if cluster.ConnectTimeout.AsDuration() != 500*time.Millisecond {
				t.Fatalf("JWKS cluster connection timeout = %v", cluster.ConnectTimeout)
			}
		} else if transport.Sni == "" || san.SanType != tls.SubjectAltNameMatcher_DNS || san.Matcher.GetExact() != transport.Sni {
			t.Fatalf("DNS identity = %v", &transport)
		}
	}
	volumes := 0
	for _, volume := range r.Deployment.Spec.Template.Spec.Volumes {
		if volume.ConfigMap != nil && volume.ConfigMap.Name == ca.ConfigMap.Name {
			volumes++
			if len(volume.ConfigMap.Items) != 1 || volume.ConfigMap.Items[0].Key != "roots.pem" || volume.ConfigMap.Items[0].Path != "ca.crt" {
				t.Fatalf("CA projection = %v", volume)
			}
		}
	}
	if volumes != 1 {
		t.Fatalf("CA mount count = %d, want deduplicated mount", volumes)
	}
	for _, mount := range r.Deployment.Spec.Template.Spec.Containers[0].VolumeMounts {
		if strings.HasPrefix(mount.MountPath, configuration.CaDirectory) && (!mount.ReadOnly || mount.SubPath != "") {
			t.Fatalf("CA mount = %v", mount)
		}
	}
}

func TestKubernetesTrustedCAFilenameUsesContainerFileWithoutMount(t *testing.T) {
	const filename = "/etc/pki/tls/certs/ca-bundle.crt"
	c := loadConfigCase(t, "jwt-auth")
	c.Authenticators[0].JWT.JWKS.TrustedCA = &gatewayapi.TrustedCA{Filename: filename}

	resources, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	b := decodeBootstrap(t, []byte(resources.ConfigMap.Data["envoy.yaml"]))
	var gotFilename string
	for _, cluster := range b.StaticResources.Clusters {
		if cluster.Name != configuration.JwksClusterName(c.Authenticators[0].Name) {
			continue
		}
		var transport tls.UpstreamTlsContext
		if err := cluster.TransportSocket.GetTypedConfig().UnmarshalTo(&transport); err != nil {
			t.Fatal(err)
		}
		gotFilename = transport.CommonTlsContext.GetValidationContext().TrustedCa.GetFilename()
	}
	if gotFilename != filename {
		t.Fatalf("generated trusted CA filename = %q, want %q", gotFilename, filename)
	}

	configMapNames := map[string]bool{resources.ConfigMap.Name: true}
	if resources.OTelCollectorConfigMap != nil {
		configMapNames[resources.OTelCollectorConfigMap.Name] = true
	}
	configMapVolumeCount := 0
	for _, volume := range resources.Deployment.Spec.Template.Spec.Volumes {
		if volume.ConfigMap == nil {
			continue
		}
		configMapVolumeCount++
		if !configMapNames[volume.ConfigMap.Name] {
			t.Fatalf("unexpected ConfigMap volume for a trusted CA filename: %#v", volume)
		}
	}
	if configMapVolumeCount != len(configMapNames) {
		t.Fatalf("ConfigMap volume count = %d, want %d generated configuration volumes", configMapVolumeCount, len(configMapNames))
	}
}
