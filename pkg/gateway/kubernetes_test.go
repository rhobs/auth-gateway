package gateway

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	yaml "go.yaml.in/yaml/v3"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestKubernetesYAMLOptions(t *testing.T) {
	c := loadTestConfig(t, readFixture(t, "kubernetes-options/nested-null.yaml"), "nested nulls")
	if c.Overload != nil || c.Kubernetes.EnvoyConcurrency != nil {
		t.Fatalf("defaulted Kubernetes settings = %#v", c.Kubernetes)
	}

	c = loadTestConfig(t, readFixture(t, "kubernetes-options/empty-resource-maps.yaml"), "empty resource maps")
	if c.Kubernetes.Resources.Requests == nil || c.Kubernetes.Resources.Limits == nil ||
		len(c.Kubernetes.Resources.Requests) != 0 || len(c.Kubernetes.Resources.Limits) != 0 {
		t.Fatal("supplied empty resource maps were merged with defaults")
	}
	if _, err := Load(strings.NewReader(readFixture(t, "kubernetes-options/overload-empty.yaml"))); err == nil || !strings.Contains(err.Error(), "overload.max_heap_bytes") {
		t.Fatalf("empty overload accepted: %v", err)
	}
}

func TestKubernetesObservabilityDefaults(t *testing.T) {
	defaults := []struct {
		name string
		file string
	}{
		{name: "metrics omitted", file: "public-routing/config.yaml"},
		{name: "metrics null", file: "kubernetes-options/metrics-null.yaml"},
		{name: "metrics empty", file: "kubernetes-options/metrics-empty.yaml"},
		{name: "nested nulls", file: "kubernetes-options/nested-null.yaml"},
	}
	for _, test := range defaults {
		t.Run(test.name, func(t *testing.T) {
			c := loadTestConfig(t, readFixture(t, test.file), test.name)
			metrics := c.Observability.Metrics
			collectorResources := c.Kubernetes.Metrics.Resources
			wantResources := gatewayapi.KubernetesResourceRequirements{
				Requests: map[string]string{"cpu": "20m", "memory": "64Mi"},
				Limits:   map[string]string{"memory": "256Mi"},
			}
			type metricDefaults struct {
				Enabled        *bool
				ScrapeInterval *gatewayapi.Duration
				ScrapeTimeout  *gatewayapi.Duration
			}
			gotMetrics := metricDefaults{
				Enabled:        metrics.Enabled,
				ScrapeInterval: metrics.ScrapeInterval,
				ScrapeTimeout:  metrics.ScrapeTimeout,
			}
			wantMetrics := metricDefaults{
				Enabled:        new(true),
				ScrapeInterval: duration(30 * time.Second),
				ScrapeTimeout:  duration(10 * time.Second),
			}
			assertConfigDiff(t, "defaulted metrics", wantMetrics, gotMetrics)
			assertConfigDiff(t, "defaulted collector resources", wantResources, collectorResources)
			if got, want := c.Kubernetes.OTelCollectorImage, DefaultOTelCollectorImage; got != want {
				t.Errorf("collector image = %q, want %q", got, want)
			}
		})
	}
}

func TestKubernetesObservabilityDefaultsPreserveExplicitResourceMaps(t *testing.T) {
	c := loadTestConfig(t, readFixture(t, "kubernetes-options/empty-resource-maps.yaml"), "empty resource maps")
	resources := c.Kubernetes.Metrics.Resources
	if resources.Limits == nil {
		t.Error("collector resource defaults replaced the explicitly empty limits map with nil")
	}
	if len(resources.Limits) != 0 {
		t.Errorf("collector limits = %v, want an empty map", resources.Limits)
	}
	assertConfigDiff(t, "collector requests", map[string]string{"cpu": "5m"}, resources.Requests)
}

func TestKubernetesImageDefaultsToSharedImages(t *testing.T) {
	c := loadConfigCase(t, "public-routing")
	c.Kubernetes.Image = ""
	c.Kubernetes.OTelCollectorImage = ""
	defaulted := withDefaultsConfig(c)
	got := []string{defaulted.Kubernetes.Image, defaulted.Kubernetes.OTelCollectorImage}
	want := []string{DefaultEnvoyImage, DefaultOTelCollectorImage}
	assertConfigDiff(t, "defaulted Kubernetes images", want, got)
}

func TestKubernetesResourceRequirementsRejectsInvalidQuantity(t *testing.T) {
	_, err := kubernetesResourceRequirements("kubernetes.resources", gatewayapi.KubernetesResourceRequirements{
		Requests: map[string]string{"cpu": "not-a-quantity"},
	})
	if err == nil || !strings.Contains(err.Error(), "kubernetes.resources.requests.cpu") {
		t.Fatalf("resource requirements error = %v, want invalid CPU quantity error", err)
	}
}

func TestAdmissionControlUpdateRequiresBootstrapRollout(t *testing.T) {
	c := loadConfigCase(t, "admission-control")
	before, err := GenerateKubernetes(c)
	if err != nil {
		t.Fatal(err)
	}
	c.APIs[0].AdmissionControl.SrThreshold = new(90.0)
	after, err := GenerateKubernetes(c)
	if err != nil {
		t.Fatal(err)
	}
	if before.ConfigMap.Data["envoy.yaml"] == after.ConfigMap.Data["envoy.yaml"] {
		t.Fatal("admission update did not change the bootstrap ConfigMap")
	}
	if diff := cmp.Diff(before.Deployment.Spec.Template, after.Deployment.Spec.Template); diff != "" {
		t.Fatalf("admission update changed the Deployment template (-before +after):\n%s", diff)
	}
	if len(after.Deployment.Spec.Template.Annotations) != 0 {
		t.Fatal("admission update added a checksum annotation")
	}
}

func TestConfigurationDefaults(t *testing.T) {
	c := loadTestConfig(t, readFixture(t, "defaults.yaml"), "defaults fixture")
	if c.Node != (gatewayapi.EnvoyNode{ID: "auth-gateway", Cluster: "auth-gateway"}) {
		t.Fatalf("node defaults = %#v", c.Node)
	}
	wantListener := gatewayapi.Listener{
		Port: new(uint32(8080)), PerConnectionBufferLimitBytes: new(uint32(1048576)),
		MaxRequestHeadersKB: new(uint32(32)), MaxRequestHeadersCount: new(uint32(100)),
		RequestHeadersTimeout: duration(5 * time.Second), RequestTimeout: duration(30 * time.Second),
		ConnectionIdleTimeout: duration(60 * time.Second), StreamIdleTimeout: duration(60 * time.Second),
		MaxStreamDuration: duration(30 * time.Second), StreamFlushTimeout: duration(5 * time.Second),
		TLSHandshakeTimeout: duration(5 * time.Second),
	}
	assertConfigDiff(t, "listener defaults", wantListener, c.Listener)
	if c.Overload != nil {
		t.Fatal("overload must be opt-in")
	}
	wantBreakers := &gatewayapi.CircuitBreakerConfig{MaxConnections: new(uint32(1024)), MaxPendingRequests: new(uint32(1024)), MaxRequests: new(uint32(1024)), MaxRetries: new(uint32(0))}
	for _, a := range c.Authenticators {
		if a.JWT == nil {
			continue
		}
		want := gatewayapi.JWKSConfig{URI: a.JWT.JWKS.URI, DNSLookupFamily: jwksDNSLookupFamilyV4Only, CacheDuration: duration(5 * time.Minute), FetchTimeout: duration(5 * time.Second), ConnectTimeout: duration(5 * time.Second), CircuitBreakers: wantBreakers}
		assertConfigDiff(t, a.Name+" JWKS defaults", want, a.JWT.JWKS)
	}
	for _, api := range c.APIs {
		want := gatewayapi.Upstream{Address: api.Upstream.Address, Port: api.Upstream.Port, ConnectTimeout: duration(5 * time.Second), PerConnectionBufferLimitBytes: new(uint32(1048576)), HTTPProtocol: "http1"}
		assertConfigDiff(t, api.Name+" upstream defaults", want, api.Upstream)
		assertConfigDiff(t, api.Name+" circuit breaker defaults", wantBreakers, api.CircuitBreakers)
		if api.Timeouts != nil {
			t.Fatalf("default fixture API %s must inherit API timeouts", api.Name)
		}
		for _, r := range api.Routes {
			if r.Timeouts != nil {
				t.Fatal("default fixture must inherit route timeouts")
			}
		}
	}
	wantKubernetesResources := gatewayapi.KubernetesResourceRequirements{
		Requests: map[string]string{"cpu": "50m", "memory": "64Mi"},
		Limits:   map[string]string{"cpu": "1", "memory": "256Mi"},
	}
	type kubernetesDefaults struct {
		Name             string
		Namespace        string
		Replicas         *int32
		ServicePort      *int32
		HTTPSServicePort *int32
		EnvoyConcurrency *uint32
		Resources        gatewayapi.KubernetesResourceRequirements
	}
	gotKubernetes := kubernetesDefaults{
		Name:             c.Kubernetes.Name,
		Namespace:        c.Kubernetes.Namespace,
		Replicas:         c.Kubernetes.Replicas,
		ServicePort:      c.Kubernetes.ServicePort,
		HTTPSServicePort: c.Kubernetes.HTTPSServicePort,
		EnvoyConcurrency: c.Kubernetes.EnvoyConcurrency,
		Resources:        c.Kubernetes.Resources,
	}
	wantKubernetes := kubernetesDefaults{
		Name: "auth-gateway", Namespace: "observability",
		Replicas: new(int32(2)), ServicePort: new(int32(80)), HTTPSServicePort: new(int32(443)),
		Resources: wantKubernetesResources,
	}
	assertConfigDiff(t, "Kubernetes defaults", wantKubernetes, gotKubernetes)
	wantTLS := &gatewayapi.ServerTLS{Secret: "gateway-tls", Certificate: "/etc/gateway-tls/tls.crt", PrivateKey: "/etc/gateway-tls/tls.key"}
	assertConfigDiff(t, "server TLS defaults", wantTLS, c.Servers[0].TLSConfig)
	resolved, err := resolveConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	wantTimers := &gatewayapi.RouteTimeouts{ResponseTimeout: duration(30 * time.Second), IdleTimeout: duration(60 * time.Second), MaxStreamDuration: duration(30 * time.Second)}
	for _, api := range resolved.APIs {
		for _, r := range api.Routes {
			assertConfigDiff(t, api.Name+" effective timeouts", wantTimers, r.Timeouts)
		}
	}
	if _, err := GenerateKubernetes(c); err != nil {
		t.Fatalf("generate defaulted resources: %v", err)
	}
}

func TestPublicOperationsPreserveConfiguration(t *testing.T) {
	c := loadAuthValidationFixture(t)
	before, err := yaml.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(c); err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(c); err != nil {
		t.Fatal(err)
	}
	resources, err := GenerateKubernetes(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resources.YAML(); err != nil {
		t.Fatal(err)
	}
	after, err := yaml.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("validation or generation mutated the caller's configuration")
	}
}

func TestFaultInjectionToggleChangesOnlyBootstrapConfigMap(t *testing.T) {
	c := loadConfigCase(t, "fault-injection")
	before, err := GenerateKubernetes(c)
	if err != nil {
		t.Fatal(err)
	}
	c.APIs[0].FaultInjection.Enabled = false
	after, err := GenerateKubernetes(c)
	if err != nil {
		t.Fatal(err)
	}
	if before.ConfigMap.Data[envoyConfigFilename] == after.ConfigMap.Data[envoyConfigFilename] {
		t.Fatal("fault toggle did not change the Envoy bootstrap")
	}
	if !reflect.DeepEqual(before.Deployment.Spec.Template, after.Deployment.Spec.Template) {
		t.Fatal("fault toggle changed the Deployment template")
	}
	if len(before.Deployment.Spec.Template.Annotations) != 0 || len(after.Deployment.Spec.Template.Annotations) != 0 {
		t.Fatal("fault toggle added a Deployment checksum annotation")
	}
}

func TestGeneratedKubernetesReferenceFiles(t *testing.T) {
	cases, err := filepath.Glob(filepath.Join("testdata", "*", "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, inputPath := range cases {
		name := filepath.Base(filepath.Dir(inputPath))
		t.Run(name, func(t *testing.T) {
			input, err := os.Open(inputPath)
			if err != nil {
				t.Fatal(err)
			}
			gatewayConfig, err := Load(input)
			closeErr := input.Close()
			if err != nil {
				t.Fatal(err)
			}
			if closeErr != nil {
				t.Fatal(closeErr)
			}

			caseDir := filepath.Dir(inputPath)
			resources, err := GenerateKubernetes(gatewayConfig)
			if err != nil {
				t.Fatal(err)
			}
			manifest, err := resources.YAML()
			if err != nil {
				t.Fatal(err)
			}
			checkReference(t, filepath.Join(caseDir, "kubernetes.yaml.golden"), manifest)
		})
	}
}

func TestGenerationIsDeterministic(t *testing.T) {
	buildAttributes := func(t *testing.T, reverse bool) gatewayapi.Config {
		t.Helper()
		c := loadConfigCase(t, "jwt-auth-with-attributes")
		sources := c.Authenticators[0].Attributes
		names := []string{"tenant_id", "writer_id"}
		if reverse {
			slices.Reverse(names)
		}
		c.Authenticators[0].Attributes = nil
		for _, name := range names {
			setTestAttribute(&c.Authenticators[0], *testAttribute(&gatewayapi.Authenticator{Attributes: sources}, name))
		}
		return c
	}
	buildMultipleCAs := func(t *testing.T, reverse bool) gatewayapi.Config {
		t.Helper()
		c := loadConfigCase(t, "jwt-auth-multiple-issuers")
		c.Authenticators[0].JWT.JWKS.TrustedCA = &gatewayapi.TrustedCA{ConfigMap: &gatewayapi.CAConfigMap{Name: "issuer-one-ca", Key: "ca.crt"}}
		c.Authenticators[1].JWT.JWKS.TrustedCA = &gatewayapi.TrustedCA{ConfigMap: &gatewayapi.CAConfigMap{Name: "issuer-two-ca", Key: "ca.crt"}}
		c.APIs[0].Upstream.TLSConfig = &gatewayapi.UpstreamTLS{
			ServerName: "backend.example.test",
			TrustedCA:  &gatewayapi.TrustedCA{ConfigMap: &gatewayapi.CAConfigMap{Name: "backend-ca", Key: "ca.crt"}},
		}
		requests := []struct{ name, value string }{{name: "cpu", value: "50m"}, {name: "memory", value: "64Mi"}}
		limits := []struct{ name, value string }{{name: "cpu", value: "1"}, {name: "memory", value: "256Mi"}}
		c.Kubernetes.Resources.Requests = resourceMap(requests, reverse)
		c.Kubernetes.Resources.Limits = resourceMap(limits, reverse)
		return c
	}
	tests := []struct {
		name  string
		build func(*testing.T, bool) gatewayapi.Config
	}{
		{name: "public routing", build: func(t *testing.T, _ bool) gatewayapi.Config { return loadConfigCase(t, "public-routing") }},
		{name: "attribute insertion order", build: buildAttributes},
		{name: "multiple CA mounts", build: buildMultipleCAs},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			firstConfig := test.build(t, false)
			secondConfig := test.build(t, true)
			firstFiles, err := Generate(firstConfig)
			if err != nil {
				t.Fatal(err)
			}
			secondFiles, err := Generate(secondConfig)
			if err != nil {
				t.Fatal(err)
			}
			assertGeneratedFilesEqual(t, firstFiles, secondFiles)

			firstResources, err := GenerateKubernetes(firstConfig)
			if err != nil {
				t.Fatal(err)
			}
			secondResources, err := GenerateKubernetes(secondConfig)
			if err != nil {
				t.Fatal(err)
			}
			firstManifest, err := firstResources.YAML()
			if err != nil {
				t.Fatal(err)
			}
			secondManifest, err := secondResources.YAML()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(firstManifest, secondManifest) {
				t.Fatal("Kubernetes manifest changed with map insertion order")
			}
		})
	}
}

func TestReferenceErrorsFollowConfiguredOrder(t *testing.T) {
	for _, test := range []struct {
		name  string
		field string
		edit  func(*gatewayapi.Config)
	}{
		{
			name: "API binding", field: "servers[0].apis",
			edit: func(c *gatewayapi.Config) {
				c.Servers[0].APIs = []gatewayapi.APIBinding{{Name: "z-missing"}, {Name: "a-missing"}}
			},
		},
		{
			name: "JWT provider", field: "servers[0].apis[0].access[0].authentication.jwt.providers",
			edit: func(c *gatewayapi.Config) {
				c.Servers[0].APIs[0].Access[0].Authentication.JWT.Providers = []string{"z-missing", "a-missing"}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := loadConfigCase(t, "access-control")
			test.edit(&c)
			for _, operation := range []struct {
				name string
				run  func(gatewayapi.Config) error
			}{
				{name: "validate", run: Validate},
				{name: "Envoy", run: func(c gatewayapi.Config) error { _, err := Generate(c); return err }},
				{name: "Kubernetes", run: func(c gatewayapi.Config) error { _, err := GenerateKubernetes(c); return err }},
				{name: "collector", run: func(c gatewayapi.Config) error { _, err := GenerateOTelCollectorConfig(c); return err }},
			} {
				t.Run(operation.name, func(t *testing.T) {
					err := operation.run(c)
					if err == nil || !strings.Contains(err.Error(), test.field) || !strings.Contains(err.Error(), `"z-missing"`) {
						t.Fatalf("error = %v, want %s to report the first configured reference", err, test.field)
					}
				})
			}
		})
	}
}

func TestResolvedRouteTimeoutsAndReuse(t *testing.T) {
	c := loadConfigCase(t, "public-routing")
	c.Listener.StreamIdleTimeout = duration(75 * time.Second)
	c.Listener.MaxStreamDuration = duration(45 * time.Second)
	c.APIs[0].Timeouts = &gatewayapi.RouteTimeouts{ResponseTimeout: duration(60 * time.Second), MaxStreamDuration: duration(90 * time.Second)}
	c.APIs[0].Routes = []gatewayapi.Route{
		{Methods: []string{"GET", "POST"}, Path: gatewayapi.PathMatch{Exact: "/query"}},
		{Methods: []string{"GET"}, Path: gatewayapi.PathMatch{Exact: "/range"}, Timeouts: &gatewayapi.RouteTimeouts{ResponseTimeout: duration(80 * time.Second), IdleTimeout: duration(95 * time.Second), MaxStreamDuration: duration(120 * time.Second)}},
	}
	c.Servers = append(c.Servers, gatewayapi.Server{Hostname: "second.example.test", APIs: slices.Clone(c.Servers[0].APIs)})
	before, _ := yaml.Marshal(c)
	effective, err := resolveConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	if *effective.APIs[0].Routes[0].Timeouts.IdleTimeout != gatewayapi.Duration(75*time.Second) {
		t.Fatal("API overrides lost listener idle fallback")
	}
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	m := decodeHTTPManager(t, decodeBootstrap(t, files.EnvoyBootstrap.Contents).StaticResources.Listeners[0].FilterChains[0])
	for _, host := range m.GetRouteConfig().VirtualHosts {
		for i, route := range host.Routes {
			if route.GetRoute() == nil {
				if route.StatPrefix != "" {
					t.Fatal("local responses should not get forwarding stats")
				}
				continue
			}
			want := []time.Duration{60 * time.Second, 75 * time.Second, 90 * time.Second}
			if i == 2 {
				want = []time.Duration{80 * time.Second, 95 * time.Second, 120 * time.Second}
			}
			a := route.GetRoute()
			type routeSettings struct {
				ResponseTimeout   time.Duration
				IdleTimeout       time.Duration
				MaxStreamDuration time.Duration
				StatPrefix        string
				HasRetryPolicy    bool
			}
			got := routeSettings{
				ResponseTimeout:   a.Timeout.AsDuration(),
				IdleTimeout:       a.IdleTimeout.AsDuration(),
				MaxStreamDuration: a.MaxStreamDuration.MaxStreamDuration.AsDuration(),
				StatPrefix:        route.StatPrefix,
				HasRetryPolicy:    a.RetryPolicy != nil,
			}
			wantSettings := routeSettings{
				ResponseTimeout:   want[0],
				IdleTimeout:       want[1],
				MaxStreamDuration: want[2],
				StatPrefix:        route.Name,
			}
			assertConfigDiff(t, "route settings for "+route.Name, wantSettings, got)
		}
	}
	resources, err := GenerateKubernetes(c)
	if err != nil {
		t.Fatalf("generate Kubernetes resources: %v", err)
	}
	if got, want := resources.ConfigMap.Data["envoy.yaml"], string(files.EnvoyBootstrap.Contents); got != want {
		t.Fatal("Envoy and Kubernetes generators produced different bootstraps")
	}
	after, _ := yaml.Marshal(c)
	if string(before) != string(after) {
		t.Fatal("resolution changed the serialized configuration")
	}
	if c.APIs[0].Routes[0].Timeouts != nil {
		t.Fatal("resolution added a timeout override to the public configuration")
	}
	*effective.APIs[0].Routes[0].Timeouts.ResponseTimeout = gatewayapi.Duration(time.Second)
	if *c.APIs[0].Timeouts.ResponseTimeout != gatewayapi.Duration(60*time.Second) {
		t.Fatal("resolved timeout aliases caller")
	}
	c.APIs[0].Timeouts.MaxStreamDuration = nil
	if err := Validate(c); err == nil || !strings.Contains(err.Error(), "1m0s") || !strings.Contains(err.Error(), "45s") || !strings.Contains(err.Error(), "apis[0].routes[0]") {
		t.Fatalf("incompatible effective timers: %v", err)
	}
}

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

func TestGenerateKubernetesPreservesYAMLImageOverrides(t *testing.T) {
	const input = `version: 1
servers:
- hostname: auth.example.com
  apis:
  - name: status
    public: true
apis:
- name: status
  upstream:
    address: httpbin
    port: 8080
  routes:
  - methods:
    - GET
    path:
      exact: "/status"
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
	tlsConfig := &gatewayapi.ServerTLS{
		Secret:      "auth-gateway-tls",
		Certificate: "/etc/gateway-certs/tls.crt",
		PrivateKey:  "/etc/gateway-certs/tls.key",
	}
	config.Servers = []gatewayapi.Server{
		{Hostname: "auth.example.com", APIs: []gatewayapi.APIBinding{{Name: "metrics", Public: true}}},
		{Hostname: "mts.auth.example.com", TLSConfig: tlsConfig, APIs: []gatewayapi.APIBinding{{Name: "metrics", Public: true}}},
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
	config.Servers = []gatewayapi.Server{{
		Hostname:  "mts.auth.example.com",
		TLSConfig: &gatewayapi.ServerTLS{Secret: "auth-gateway-tls"},
		APIs:      []gatewayapi.APIBinding{{Name: "metrics", Public: true}},
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
	config.Servers[2].TLSConfig = &gatewayapi.ServerTLS{
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
			resources, err := GenerateKubernetes(c)
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

func TestGenerateKubernetesTracingWithoutMetrics(t *testing.T) {
	c := loadConfigCase(t, "public-routing")
	c.Observability.Metrics.Enabled = new(false)
	c.Observability.Tracing = gatewayapi.ObservabilityTracing{
		Enabled:            new(true),
		Endpoint:           "jaeger:4317",
		ServiceName:        "auth-gateway-test",
		SamplingPercentage: new(100.0),
		Insecure:           new(true),
	}

	resources, err := GenerateKubernetes(c)
	if err != nil {
		t.Fatal(err)
	}
	if resources.OTelCollectorConfigMap == nil {
		t.Fatal("trace-only configuration did not generate a collector ConfigMap")
	}
	containers := resources.Deployment.Spec.Template.Spec.Containers
	if len(containers) != 2 {
		t.Fatalf("deployment has %d containers, want Envoy and collector", len(containers))
	}
	collectorContainer := containers[1]
	if len(collectorContainer.Ports) != 1 || collectorContainer.Ports[0].Name != tracesPortName || collectorContainer.Ports[0].ContainerPort != defaultOTelTracePort {
		t.Fatalf("trace-only collector ports = %#v", collectorContainer.Ports)
	}
	for _, port := range resources.Service.Spec.Ports {
		if port.Name == metricsPortName || port.Name == tracesPortName {
			t.Fatalf("trace-only Service exposes collector port %q", port.Name)
		}
	}

	var collector struct {
		Receivers struct {
			OTLP struct {
				Protocols struct {
					GRPC struct {
						Endpoint string `yaml:"endpoint"`
					} `yaml:"grpc"`
				} `yaml:"protocols"`
			} `yaml:"otlp"`
		} `yaml:"receivers"`
		Exporters struct {
			OTLP struct {
				Endpoint string `yaml:"endpoint"`
				TLS      struct {
					Insecure bool `yaml:"insecure"`
				} `yaml:"tls"`
			} `yaml:"otlp"`
		} `yaml:"exporters"`
		Service struct {
			Pipelines map[string]struct {
				Receivers []string `yaml:"receivers"`
				Exporters []string `yaml:"exporters"`
			} `yaml:"pipelines"`
		} `yaml:"service"`
	}
	if err := yaml.Unmarshal([]byte(resources.OTelCollectorConfigMap.Data[collectorConfigFilename]), &collector); err != nil {
		t.Fatal(err)
	}
	if collector.Receivers.OTLP.Protocols.GRPC.Endpoint != "127.0.0.1:4317" || collector.Exporters.OTLP.Endpoint != "jaeger:4317" || !collector.Exporters.OTLP.TLS.Insecure {
		t.Fatalf("collector OTLP config = %#v", collector)
	}
	tracePipeline, exists := collector.Service.Pipelines["traces"]
	if !exists || len(tracePipeline.Receivers) != 1 || tracePipeline.Receivers[0] != "otlp" || len(tracePipeline.Exporters) != 1 || tracePipeline.Exporters[0] != "otlp" {
		t.Fatalf("collector trace pipeline = %#v", tracePipeline)
	}
}

func TestGenerateKubernetesExposesMetricsWithoutAdminPort(t *testing.T) {
	config, err := Load(strings.NewReader(readFixture(t, "public-routing/config.yaml")))
	if err != nil {
		t.Fatal(err)
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
	if len(ports) != 2 {
		t.Fatalf("Service ports = %#v, want only HTTP and metrics ports", ports)
	}
	if got := ports["http"]; got.port != defaultServicePort || got.targetPort != "http" {
		t.Fatalf("HTTP Service port = %#v, want port %d targeting Envoy HTTP", got, defaultServicePort)
	}
	if got := ports["metrics"]; got.port != defaultOTelMetricsPort || got.targetPort != "metrics" {
		t.Fatalf("metrics Service port = %#v, want port %d targeting the collector", got, defaultOTelMetricsPort)
	}
}

func TestGenerateKubernetesOmitsCollectorWhenMetricsAreDisabled(t *testing.T) {
	c := loadConfigCase(t, "api-key-auth")
	enabled, err := GenerateKubernetes(c)
	if err != nil {
		t.Fatal(err)
	}
	c.Observability.Metrics.Enabled = new(false)
	// With no collector port reserved, the HTTP Service can use 8889.
	c.Kubernetes.ServicePort = new(int32(defaultOTelMetricsPort))
	disabled, err := GenerateKubernetes(c)
	if err != nil {
		t.Fatal(err)
	}
	if enabled.OTelCollectorConfigMap == nil || disabled.OTelCollectorConfigMap != nil {
		t.Fatalf("collector ConfigMaps when enabled/disabled = %v/%v", enabled.OTelCollectorConfigMap != nil, disabled.OTelCollectorConfigMap != nil)
	}
	if got := len(disabled.Deployment.Spec.Template.Spec.Containers); got != 1 {
		t.Fatalf("disabled metrics deployment has %d containers, want only Envoy", got)
	}
	for _, volume := range disabled.Deployment.Spec.Template.Spec.Volumes {
		if volume.Name == metricsConfigVolumeName {
			t.Fatal("disabled metrics generated a collector config volume")
		}
	}
	servicePorts := make(map[string]int32, len(disabled.Service.Spec.Ports))
	for _, port := range disabled.Service.Spec.Ports {
		servicePorts[port.Name] = port.Port
	}
	if servicePorts["http"] != defaultOTelMetricsPort {
		t.Fatalf("disabled metrics HTTP Service port = %d, want %d", servicePorts["http"], defaultOTelMetricsPort)
	}
	if _, exists := servicePorts[metricsPortName]; exists {
		t.Fatalf("disabled metrics Service still exposes the collector port: %#v", servicePorts)
	}
	if !reflect.DeepEqual(enabled.ConfigMap.Data, disabled.ConfigMap.Data) {
		t.Fatal("disabling collector metrics changed the Envoy bootstrap")
	}
}

func TestRequestMetricBindingChangesBootstrapOnly(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-with-attributes")
	before, err := GenerateKubernetes(c)
	if err != nil {
		t.Fatal(err)
	}
	c.APIs[0].Metrics.Labels["tenant"] = "writer_id"
	after, err := GenerateKubernetes(c)
	if err != nil {
		t.Fatal(err)
	}
	if before.ConfigMap.Data[envoyConfigFilename] == after.ConfigMap.Data[envoyConfigFilename] {
		t.Fatal("changing a metric label binding did not change the static Envoy bootstrap")
	}
	if !reflect.DeepEqual(before.Deployment.Spec.Template, after.Deployment.Spec.Template) {
		t.Fatal("changing a metric label binding changed the Deployment template")
	}
}

func TestRequestMetricNameChangesBootstrapOnly(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-with-attributes")
	before, err := GenerateKubernetes(c)
	if err != nil {
		t.Fatal(err)
	}
	*c.Observability.Metrics.CustomMetricName = "renamed_gateway_requests_total"
	after, err := GenerateKubernetes(c)
	if err != nil {
		t.Fatal(err)
	}
	if before.ConfigMap.Data[envoyConfigFilename] == after.ConfigMap.Data[envoyConfigFilename] {
		t.Fatal("changing the request metric name did not change the static Envoy bootstrap")
	}
	if !reflect.DeepEqual(before.Deployment.Spec.Template, after.Deployment.Spec.Template) {
		t.Fatal("changing the request metric name changed the Deployment template")
	}
}

func TestOTelCollectorScrapeSettingsAndResourceOverrides(t *testing.T) {
	c := loadConfigCase(t, "public-routing")
	c.Observability.Metrics.ScrapeInterval = duration(1500 * time.Millisecond)
	c.Observability.Metrics.ScrapeTimeout = duration(250 * time.Millisecond)
	c.Kubernetes.Metrics = gatewayapi.KubernetesMetrics{Resources: gatewayapi.KubernetesResourceRequirements{Requests: map[string]string{"cpu": "30m"}, Limits: map[string]string{}}}
	r, err := GenerateKubernetes(c)
	if err != nil {
		t.Fatal(err)
	}
	var collector struct {
		Receivers struct {
			Prometheus struct {
				Config struct {
					Scrapes []struct {
						Interval string `yaml:"scrape_interval"`
						Timeout  string `yaml:"scrape_timeout"`
					} `yaml:"scrape_configs"`
				} `yaml:"config"`
			} `yaml:"prometheus"`
		} `yaml:"receivers"`
	}
	if err := yaml.Unmarshal([]byte(r.OTelCollectorConfigMap.Data[collectorConfigFilename]), &collector); err != nil {
		t.Fatal(err)
	}
	scrapes := collector.Receivers.Prometheus.Config.Scrapes
	if len(scrapes) != 1 || scrapes[0].Interval != "1500ms" || scrapes[0].Timeout != "250ms" {
		t.Fatalf("scrape timing = %+v", scrapes)
	}
	resources := r.Deployment.Spec.Template.Spec.Containers[1].Resources
	if len(resources.Requests) != 1 || resources.Requests.Cpu().Cmp(resource.MustParse("30m")) != 0 || len(resources.Limits) != 0 {
		t.Fatalf("collector resource overrides = %v", resources)
	}
}

func TestOTelCollectorConfigMapUpdateLeavesPodTemplateUnchanged(t *testing.T) {
	c := loadConfigCase(t, "public-routing")
	before, err := GenerateKubernetes(c)
	if err != nil {
		t.Fatal(err)
	}
	if before.OTelCollectorConfigMap == nil {
		t.Fatal("metrics-enabled configuration did not generate a collector ConfigMap")
	}

	c.Observability.Metrics.ScrapeInterval = duration(45 * time.Second)
	after, err := GenerateKubernetes(c)
	if err != nil {
		t.Fatal(err)
	}
	if after.OTelCollectorConfigMap == nil {
		t.Fatal("updated metrics configuration did not generate a collector ConfigMap")
	}
	if before.OTelCollectorConfigMap.Name != after.OTelCollectorConfigMap.Name {
		t.Fatalf("collector ConfigMap name changed from %q to %q", before.OTelCollectorConfigMap.Name, after.OTelCollectorConfigMap.Name)
	}
	if before.OTelCollectorConfigMap.Data[collectorConfigFilename] == after.OTelCollectorConfigMap.Data[collectorConfigFilename] {
		t.Fatal("changing the scrape interval did not update the collector ConfigMap")
	}
	var collector struct {
		Receivers struct {
			Prometheus struct {
				Config struct {
					ScrapeConfigs []struct {
						ScrapeInterval string `yaml:"scrape_interval"`
					} `yaml:"scrape_configs"`
				} `yaml:"config"`
			} `yaml:"prometheus"`
		} `yaml:"receivers"`
	}
	if err := yaml.Unmarshal([]byte(after.OTelCollectorConfigMap.Data[collectorConfigFilename]), &collector); err != nil {
		t.Fatal(err)
	}
	scrapes := collector.Receivers.Prometheus.Config.ScrapeConfigs
	if len(scrapes) != 1 || scrapes[0].ScrapeInterval != "45s" {
		t.Fatalf("updated collector scrape interval = %+v, want 45s", scrapes)
	}
	if !reflect.DeepEqual(before.ConfigMap.Data, after.ConfigMap.Data) {
		t.Fatal("changing the scrape interval changed the Envoy ConfigMap")
	}
	if !reflect.DeepEqual(before.Deployment.Spec.Template, after.Deployment.Spec.Template) {
		t.Fatal("changing the scrape interval changed the Deployment Pod template")
	}
	if len(after.Deployment.Spec.Template.Annotations) != 0 {
		t.Fatalf("collector ConfigMap update unexpectedly has rollout annotations: %#v", after.Deployment.Spec.Template.Annotations)
	}

	var configVolumeMatches, configMountMatches bool
	containers := after.Deployment.Spec.Template.Spec.Containers
	if len(containers) != 2 {
		t.Fatalf("metrics-enabled deployment has %d containers, want Envoy and collector", len(containers))
	}
	for _, volume := range after.Deployment.Spec.Template.Spec.Volumes {
		if volume.Name == metricsConfigVolumeName {
			configVolumeMatches = volume.ConfigMap != nil && volume.ConfigMap.Name == after.OTelCollectorConfigMap.Name
		}
	}
	for _, mount := range containers[1].VolumeMounts {
		if mount.Name == metricsConfigVolumeName {
			configMountMatches = mount.MountPath == collectorConfigDirectory && mount.ReadOnly && mount.SubPath == "" && mount.SubPathExpr == ""
		}
	}
	if !configVolumeMatches || !configMountMatches {
		t.Fatalf("collector ConfigMap volume and mount = %t/%t, want a projected directory mount", configVolumeMatches, configMountMatches)
	}
}
