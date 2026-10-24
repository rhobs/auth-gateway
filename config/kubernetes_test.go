package config

import (
	"fmt"
	"math"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	jwt "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/jwt_authn/v3"
	connections "github.com/envoyproxy/go-control-plane/envoy/extensions/resource_monitors/downstream_connections/v3"
	heap "github.com/envoyproxy/go-control-plane/envoy/extensions/resource_monitors/fixed_heap/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
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
				resources, err := GenerateKubernetes(c)
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
	before, err := GenerateKubernetes(c)
	if err != nil {
		t.Fatal(err)
	}
	c.Node.Cluster = "another-envoy-cluster"
	after, err := GenerateKubernetes(c)
	if err != nil {
		t.Fatal(err)
	}
	assertConfigDiff(t, "Deployment selector after node.cluster update", before.Deployment.Spec.Selector, after.Deployment.Spec.Selector)
	assertConfigDiff(t, "Pod labels after node.cluster update", before.Deployment.Spec.Template.Labels, after.Deployment.Spec.Template.Labels)
	assertConfigDiff(t, "Service selector after node.cluster update", before.Service.Spec.Selector, after.Service.Spec.Selector)
}

func TestKubernetesImageDefaultsToSharedImages(t *testing.T) {
	c := loadConfigCase(t, "public-routing")
	c.Kubernetes.Image = ""
	c.Kubernetes.OTelCollectorImage = ""
	defaulted := c.withDefaults()
	got := []string{defaulted.Kubernetes.Image, defaulted.Kubernetes.OTelCollectorImage}
	want := []string{DefaultEnvoyImage, DefaultOTelCollectorImage}
	assertConfigDiff(t, "defaulted Kubernetes images", want, got)
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
	c, err := Load(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"mirror.example.com/envoy:approved",
		"mirror.example.com/otel-collector:approved",
	}

	resources, err := GenerateKubernetes(c)
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

func TestKubernetesResourceRequirementsRejectsInvalidQuantity(t *testing.T) {
	_, err := kubernetesResourceRequirements("kubernetes.resources", KubernetesResourceRequirements{
		Requests: map[string]string{"cpu": "not-a-quantity"},
	})
	if err == nil || !strings.Contains(err.Error(), "kubernetes.resources.requests.cpu") {
		t.Fatalf("resource requirements error = %v, want invalid CPU quantity error", err)
	}
}

func TestKubernetesResourcesObjectsReturnsApplyOrder(t *testing.T) {
	resources := &KubernetesResources{
		ConfigMap:              corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "gateway"}},
		OTelCollectorConfigMap: &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "collector"}},
		ServiceAccount:         corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "service-account"}},
		Deployment:             appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "deployment"}},
		Service:                corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "service"}},
	}

	for _, test := range []struct {
		name string
		want []string
		edit func(*KubernetesResources)
	}{
		{name: "all resources", want: []string{"gateway", "collector", "service-account", "deployment", "service"}},
		{name: "without optional config maps", want: []string{"gateway", "service-account", "deployment", "service"}, edit: func(r *KubernetesResources) {
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
	resources, err := GenerateKubernetes(c)
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
		if volume.Name != apiKeySecretVolumeName {
			continue
		}
		secretVolume++
		if volume.Secret == nil || volume.Secret.SecretName != "gateway-api-keys" ||
			len(volume.Secret.Items) != 1 || volume.Secret.Items[0].Key != apiKeySecretFilename ||
			volume.Secret.Items[0].Path != apiKeySecretFilename {
			t.Fatalf("API-key Secret volume = %#v", volume)
		}
	}
	for _, mount := range pod.Containers[0].VolumeMounts {
		if mount.Name != apiKeySecretVolumeName {
			continue
		}
		secretMount++
		if mount.MountPath != apiKeyDirectory || !mount.ReadOnly || mount.SubPath != "" || mount.SubPathExpr != "" {
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
	config, err := Load(strings.NewReader(readFixture(t, "public-routing/config.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := &ServerTLS{
		Secret:      "auth-gateway-tls",
		Certificate: "/etc/gateway-certs/tls.crt",
		PrivateKey:  "/etc/gateway-certs/tls.key",
	}
	config.Servers = []Server{
		{Hostname: "auth.example.com", APIs: []string{"metrics"}},
		{Hostname: "mts.auth.example.com", TLSConfig: tlsConfig, APIs: []string{"metrics"}},
	}
	resources, err := GenerateKubernetes(config)
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
	if got := ports["http"]; got.port != defaultServicePort || got.targetPort != "http" {
		t.Fatalf("HTTP Service port = %#v", got)
	}
	if got := ports["https"]; got.port != defaultHTTPSServicePort || got.targetPort != "http" {
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
	config, err := Load(strings.NewReader(readFixture(t, "public-routing/config.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	config.Servers = []Server{{
		Hostname:  "mts.auth.example.com",
		TLSConfig: &ServerTLS{Secret: "auth-gateway-tls"},
		APIs:      []string{"metrics"},
	}}
	resources, err := GenerateKubernetes(config)
	if err != nil {
		t.Fatal(err)
	}
	if resources.Service.Spec.Ports[0].Name != "https" || resources.Service.Spec.Ports[0].Port != defaultHTTPSServicePort {
		t.Fatalf("HTTPS-only Service port = %#v", resources.Service.Spec.Ports[0])
	}
	for _, port := range resources.Service.Spec.Ports {
		if port.Name == "http" {
			t.Fatalf("HTTPS-only Service exposes an HTTP port: %#v", resources.Service.Spec.Ports)
		}
	}
}

func TestGenerateKubernetesRequiresSettings(t *testing.T) {
	config, err := Load(strings.NewReader(readFixture(t, "public-routing/config.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	config.Kubernetes = nil
	if _, err := GenerateKubernetes(config); err == nil || !strings.Contains(err.Error(), "kubernetes settings are required") {
		t.Fatalf("GenerateKubernetes error = %v, want missing Kubernetes settings", err)
	}
}

func TestGenerateKubernetesSharesTLSSecretMount(t *testing.T) {
	config, err := Load(strings.NewReader(readFixture(t, "server-tls/config.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	config.Servers[2].TLSConfig = config.Servers[1].TLSConfig
	resources, err := GenerateKubernetes(config)
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
	config, err := Load(strings.NewReader(readFixture(t, "server-tls/config.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	config.Servers[2].TLSConfig = &ServerTLS{
		Secret: "auth-gateway-tls", Certificate: "/etc/query-tls/server.pem", PrivateKey: "/etc/query-tls/key.pem",
	}
	resources, err := GenerateKubernetes(config)
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
	config, err := Load(strings.NewReader(readFixture(t, "public-routing/config.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	config.Kubernetes.Name = strings.Repeat("a", 56)
	resources, err := GenerateKubernetes(config)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(resources.ConfigMap.Name); got != 63 {
		t.Fatalf("ConfigMap name length = %d, want 63", got)
	}
}

func TestOverloadGeneration(t *testing.T) {
	c := loadConfigCase(t, "public-routing")
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	if decodeBootstrap(t, files.EnvoyBootstrap.Contents).OverloadManager != nil {
		t.Fatal("overload enabled without explicit budgets")
	}
	c.Overload = &OverloadConfig{MaxHeapBytes: 128 << 20, MaxDownstreamConnections: 1024, HeapShrinkThreshold: new(0.8), RequestRejectThreshold: new(0.85)}
	files, err = Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	o := decodeBootstrap(t, files.EnvoyBootstrap.Contents).OverloadManager
	if o == nil || o.RefreshInterval.AsDuration() != 250*time.Millisecond || len(o.ResourceMonitors) != 2 || len(o.Actions) != 2 || len(o.LoadshedPoints) != 0 {
		t.Fatalf("overload manager = %v", o)
	}
	var h heap.FixedHeapConfig
	if err := o.ResourceMonitors[0].GetTypedConfig().UnmarshalTo(&h); err != nil {
		t.Fatal(err)
	}
	var connectionsConfig connections.DownstreamConnectionsConfig
	if err := o.ResourceMonitors[1].GetTypedConfig().UnmarshalTo(&connectionsConfig); err != nil {
		t.Fatal(err)
	}
	if h.MaxHeapSizeBytes != 128<<20 || connectionsConfig.MaxActiveDownstreamConnections != 1024 || o.ResourceMonitors[0].Name != "envoy.resource_monitors.fixed_heap" || o.ResourceMonitors[1].Name != "envoy.resource_monitors.global_downstream_max_connections" {
		t.Fatalf("resource monitors = %v", o.ResourceMonitors)
	}
	for i, want := range []struct {
		name      string
		threshold float64
	}{{"envoy.overload_actions.shrink_heap", 0.8}, {"envoy.overload_actions.stop_accepting_requests", 0.85}} {
		action := o.Actions[i]
		if action.Name != want.name || len(action.Triggers) != 1 || action.Triggers[0].Name != "envoy.resource_monitors.fixed_heap" || action.Triggers[0].GetThreshold().Value != want.threshold {
			t.Fatalf("action %d = %v", i, action)
		}
	}
}

func TestKubernetesValidationAndOverloadBudgets(t *testing.T) {
	tests := []struct {
		name  string
		field string
		edit  func(*Config)
	}{
		{"empty overload", "overload.max_heap_bytes", func(c *Config) { c.Overload.MaxHeapBytes = 0 }},
		{"zero connections", "overload.max_downstream_connections", func(c *Config) { c.Overload.MaxDownstreamConnections = 0 }},
		{"zero threshold", "overload.heap_shrink_threshold", func(c *Config) { c.Overload.HeapShrinkThreshold = new(0.0) }},
		{"unit threshold", "overload.request_reject_threshold", func(c *Config) { c.Overload.RequestRejectThreshold = new(1.0) }},
		{"negative threshold", "overload.request_reject_threshold", func(c *Config) { c.Overload.RequestRejectThreshold = new(-0.1) }},
		{"nan threshold", "overload.heap_shrink_threshold", func(c *Config) { c.Overload.HeapShrinkThreshold = new(math.NaN()) }},
		{"infinite threshold", "overload.request_reject_threshold", func(c *Config) { c.Overload.RequestRejectThreshold = new(math.Inf(1)) }},
		{"unordered thresholds", "overload.heap_shrink_threshold", func(c *Config) { c.Overload.RequestRejectThreshold = new(0.9) }},
		{"missing memory limit", "kubernetes.resources.limits.memory", func(c *Config) { c.Kubernetes.Resources.Limits = map[string]string{} }},
		{"zero memory limit", "kubernetes.resources.limits.memory", func(c *Config) {
			c.Kubernetes.Resources.Requests = map[string]string{}
			c.Kubernetes.Resources.Limits = map[string]string{"memory": "0"}
		}},
		{"zero concurrency", "kubernetes.envoy_concurrency", func(c *Config) { c.Kubernetes.EnvoyConcurrency = new(uint32(0)) }},
		{"envoy request exceeds limit", "kubernetes.resources.requests.cpu", func(c *Config) { c.Kubernetes.Resources.Requests["cpu"] = "1001m" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := loadConfigCase(t, "public-routing")
			c.Overload = &OverloadConfig{MaxHeapBytes: 128 << 20, MaxDownstreamConnections: 1024}
			tt.edit(&c)
			if err := c.Validate(); err == nil || !strings.Contains(err.Error(), tt.field) {
				t.Fatalf("validation = %v, want %s", err, tt.field)
			}
		})
	}
}

func TestHeapBudgetComparedExactly(t *testing.T) {
	for _, tt := range []struct {
		limit string
		heap  uint64
		valid bool
	}{
		{"256Mi", 268435455, true},
		{"256Mi", 268435456, false},
		{"256Mi", 268435457, false},
		{"100.1", 100, true},
		{"100", 100, false},
		{"9223372036854775808", uint64(1) << 63, false},
		{"9223372036854775809", uint64(1) << 63, true},
		{"18446744073709551615", math.MaxUint64, false},
		{"18446744073709551616", math.MaxUint64, true},
		{"256Mi", math.MaxUint64, false},
	} {
		t.Run(tt.limit, func(t *testing.T) {
			c := loadConfigCase(t, "public-routing")
			c.Kubernetes.Resources = KubernetesResourceRequirements{Requests: map[string]string{}, Limits: map[string]string{"memory": tt.limit}}
			c.Overload = &OverloadConfig{MaxHeapBytes: tt.heap, MaxDownstreamConnections: 1}
			if err := c.Validate(); (err == nil) != tt.valid {
				t.Fatalf("heap %d, limit %s: %v", tt.heap, tt.limit, err)
			}
			c.Kubernetes = nil
			if _, err := Generate(c); err != nil {
				t.Fatalf("file-only heap budget: %v", err)
			}
		})
	}
}

func TestEnvoyConcurrencyGeneration(t *testing.T) {
	c := loadConfigCase(t, "public-routing")
	c.Kubernetes.EnvoyConcurrency = new(uint32(3))
	r, err := GenerateKubernetes(c)
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
	r, err = GenerateKubernetes(c)
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
	c.Kubernetes.Resources = KubernetesResourceRequirements{
		Requests: map[string]string{"cpu": "250m", "memory": "128Mi"},
		Limits:   map[string]string{"cpu": "1", "memory": "512Mi"},
	}

	resources, err := GenerateKubernetes(c)
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
	wantPorts := map[string]int32{"http": 18080, "https": 18443, "metrics": defaultOTelMetricsPort}
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
	resources, err := GenerateKubernetes(c)
	if err != nil {
		t.Fatal(err)
	}
	podSpec := resources.Deployment.Spec.Template.Spec
	if podSpec.TerminationGracePeriodSeconds == nil || *podSpec.TerminationGracePeriodSeconds != terminationGracePeriodSeconds {
		t.Fatalf("termination grace period = %v, want %d seconds", podSpec.TerminationGracePeriodSeconds, terminationGracePeriodSeconds)
	}

	envoy := podSpec.Containers[0]
	if envoy.Lifecycle == nil || envoy.Lifecycle.PreStop == nil || envoy.Lifecycle.PreStop.Exec == nil {
		t.Fatalf("Envoy lifecycle = %#v, want a pre-stop drain delay", envoy.Lifecycle)
	}
	wantCommand := []string{"/bin/sh", "-c", fmt.Sprintf("sleep %d", preStopDrainDelaySeconds)}
	if !slices.Equal(envoy.Lifecycle.PreStop.Exec.Command, wantCommand) {
		t.Fatalf("Envoy pre-stop command = %v, want %v", envoy.Lifecycle.PreStop.Exec.Command, wantCommand)
	}
}

func TestEnvoyContainerRunsHardened(t *testing.T) {
	c := loadConfigCase(t, "server-tls")
	resources, err := GenerateKubernetes(c)
	if err != nil {
		t.Fatal(err)
	}
	envoy := resources.Deployment.Spec.Template.Spec.Containers[0]
	security := envoy.SecurityContext
	if security == nil {
		t.Fatal("Envoy SecurityContext = nil, want a hardened SecurityContext")
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
	if security.RunAsUser == nil || *security.RunAsUser != 101 {
		t.Errorf("RunAsUser = %v, want 101", security.RunAsUser)
	}
	if security.RunAsGroup == nil || *security.RunAsGroup != 101 {
		t.Errorf("RunAsGroup = %v, want 101", security.RunAsGroup)
	}
	if security.Capabilities == nil || !slices.Equal(security.Capabilities.Drop, []corev1.Capability{"ALL"}) {
		t.Errorf("Capabilities = %#v, want Drop: [ALL]", security.Capabilities)
	}
}

func TestJWKSTransportAndTrust(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-multiple-issuers")
	ca := &TrustedCA{ConfigMap: &CAConfigMap{Name: "issuer-ca", Key: "roots.pem"}}
	for i := range c.Authenticators {
		c.Authenticators[i].JWT.JWKS.TrustedCA = ca
	}
	j := &c.Authenticators[0].JWT.JWKS
	j.URI = "https://192.0.2.1:9443/keys"
	j.CacheDuration = duration(15 * time.Second)
	j.FetchTimeout = duration(2 * time.Second)
	j.ConnectTimeout = duration(500 * time.Millisecond)
	r, err := GenerateKubernetes(c)
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
		if validation.TrustedCa.GetFilename() != ca.filename() || len(validation.MatchTypedSubjectAltNames) != 1 {
			t.Fatalf("trust = %v", validation)
		}
		san := validation.MatchTypedSubjectAltNames[0]
		if cluster.Name == jwksClusterName(c.Authenticators[0].Name) {
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
		if strings.HasPrefix(mount.MountPath, caDirectory) && (!mount.ReadOnly || mount.SubPath != "") {
			t.Fatalf("CA mount = %v", mount)
		}
	}
}

func TestKubernetesTrustedCAFilenameUsesContainerFileWithoutMount(t *testing.T) {
	const filename = "/etc/pki/tls/certs/ca-bundle.crt"
	c := loadConfigCase(t, "jwt-auth")
	c.Authenticators[0].JWT.JWKS.TrustedCA = &TrustedCA{Filename: filename}

	resources, err := GenerateKubernetes(c)
	if err != nil {
		t.Fatal(err)
	}
	b := decodeBootstrap(t, []byte(resources.ConfigMap.Data["envoy.yaml"]))
	var gotFilename string
	for _, cluster := range b.StaticResources.Clusters {
		if cluster.Name != jwksClusterName(c.Authenticators[0].Name) {
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
