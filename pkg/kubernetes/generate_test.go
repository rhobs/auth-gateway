package kubernetes

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	upstreamhttp "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	"github.com/google/go-cmp/cmp"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	configuration "github.com/rhobs/auth-gateway/pkg/config"
	envoyimpl "github.com/rhobs/auth-gateway/pkg/envoy"
	otel "github.com/rhobs/auth-gateway/pkg/otel"
	yaml "go.yaml.in/yaml/v3"
)

func TestAdmissionControlUpdateRequiresBootstrapRollout(t *testing.T) {
	c := loadConfigCase(t, "admission-control")
	before, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	c.APIs[0].AdmissionControl.SrThreshold = new(90.0)
	after, err := Generate(c)
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
		want := gatewayapi.JWKSConfig{URI: a.JWT.JWKS.URI, DNSLookupFamily: configuration.JwksDNSLookupFamilyV4Only, CacheDuration: duration(5 * time.Minute), FetchTimeout: duration(5 * time.Second), ConnectTimeout: duration(5 * time.Second), CircuitBreakers: wantBreakers}
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
	resolved, err := configuration.ResolveConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	wantTimers := &gatewayapi.RouteTimeouts{ResponseTimeout: duration(30 * time.Second), IdleTimeout: duration(60 * time.Second), MaxStreamDuration: duration(30 * time.Second)}
	for _, api := range resolved.APIs {
		for _, r := range api.Routes {
			assertConfigDiff(t, api.Name+" effective timeouts", wantTimers, r.Timeouts)
		}
	}
	if _, err := Generate(c); err != nil {
		t.Fatalf("generate defaulted resources: %v", err)
	}
}

func TestPublicOperationsPreserveConfiguration(t *testing.T) {
	c := loadAuthValidationFixture(t)
	before, err := yaml.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := configuration.Validate(c); err != nil {
		t.Fatal(err)
	}
	if _, err := envoyimpl.Generate(c); err != nil {
		t.Fatal(err)
	}
	resources, err := Generate(c)
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
	before, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	c.APIs[0].FaultInjection.Enabled = false
	after, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	if before.ConfigMap.Data[configuration.EnvoyConfigFilename] == after.ConfigMap.Data[configuration.EnvoyConfigFilename] {
		t.Fatal("fault toggle did not change the Envoy bootstrap")
	}
	if !reflect.DeepEqual(before.Deployment.Spec.Template, after.Deployment.Spec.Template) {
		t.Fatal("fault toggle changed the Deployment template")
	}
	if len(before.Deployment.Spec.Template.Annotations) != 0 || len(after.Deployment.Spec.Template.Annotations) != 0 {
		t.Fatal("fault toggle added a Deployment checksum annotation")
	}
}

var updateGoldens = flag.Bool("update", false, "update generated reference files")

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
			gatewayConfig, err := configuration.Load(input)
			closeErr := input.Close()
			if err != nil {
				t.Fatal(err)
			}
			if closeErr != nil {
				t.Fatal(closeErr)
			}

			caseDir := filepath.Dir(inputPath)
			resources, err := Generate(gatewayConfig)
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

func checkReference(t *testing.T, path string, generated []byte) {
	t.Helper()
	if *updateGoldens {
		if err := os.WriteFile(path, generated, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	reference, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	referenceLines := strings.Split(string(reference), "\n")
	generatedLines := strings.Split(string(generated), "\n")
	if diff := cmp.Diff(referenceLines, generatedLines); diff != "" {
		t.Errorf("%s is out of date; run make update-golden (-reference +generated):\n%s", path, diff)
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
		c.Authenticators[0].Attributes = make(map[string]gatewayapi.AttributeSource, len(names))
		for _, name := range names {
			c.Authenticators[0].Attributes[name] = sources[name]
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
			firstFiles, err := envoyimpl.Generate(firstConfig)
			if err != nil {
				t.Fatal(err)
			}
			secondFiles, err := envoyimpl.Generate(secondConfig)
			if err != nil {
				t.Fatal(err)
			}
			assertGeneratedFilesEqual(t, firstFiles, secondFiles)

			firstResources, err := Generate(firstConfig)
			if err != nil {
				t.Fatal(err)
			}
			secondResources, err := Generate(secondConfig)
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
			name: "API binding", field: "servers[2].apis",
			edit: func(c *gatewayapi.Config) { c.Servers[2].APIs = []string{"z-missing", "a-missing"} },
		},
		{
			name: "authenticator binding", field: "servers[2].authentication.any_of",
			edit: func(c *gatewayapi.Config) { c.Servers[2].Authentication.AnyOf = []string{"z-missing", "a-missing"} },
		},
		{
			name: "policy binding", field: "servers[2].authorization.any_of",
			edit: func(c *gatewayapi.Config) { c.Servers[2].Authorization.AnyOf = []string{"z-missing", "a-missing"} },
		},
		{
			name: "grant API", field: "authorization_policies[0].grants[0].apis",
			edit: func(c *gatewayapi.Config) {
				c.AuthorizationPolicies[0].Grants[0].APIs = []string{"z-missing", "a-missing"}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := loadConfigCase(t, "api-key-auth")
			test.edit(&c)
			for _, operation := range []struct {
				name string
				run  func(gatewayapi.Config) error
			}{
				{name: "validate", run: configuration.Validate},
				{name: "Envoy", run: func(c gatewayapi.Config) error { _, err := envoyimpl.Generate(c); return err }},
				{name: "Kubernetes", run: func(c gatewayapi.Config) error { _, err := Generate(c); return err }},
				{name: "collector", run: func(c gatewayapi.Config) error { _, err := otel.Generate(c); return err }},
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
	effective, err := configuration.ResolveConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	if *effective.APIs[0].Routes[0].Timeouts.IdleTimeout != gatewayapi.Duration(75*time.Second) {
		t.Fatal("API overrides lost listener idle fallback")
	}
	files, err := envoyimpl.Generate(c)
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
	resources, err := Generate(c)
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
	if err := configuration.Validate(c); err == nil || !strings.Contains(err.Error(), "1m0s") || !strings.Contains(err.Error(), "45s") || !strings.Contains(err.Error(), "apis[0].routes[0]") {
		t.Fatalf("incompatible effective timers: %v", err)
	}
}

func TestUpstreamTLSAndExplicitProtocols(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-multiple-issuers")
	ca := &gatewayapi.TrustedCA{ConfigMap: &gatewayapi.CAConfigMap{Name: "shared-ca", Key: "ca.pem"}}
	c.Authenticators[0].JWT.JWKS.TrustedCA = ca
	c.APIs[0].Upstream = gatewayapi.Upstream{Address: "192.0.2.2", Port: 443, HTTPProtocol: "http2", HTTP2: &gatewayapi.HTTP2Options{MaxConcurrentStreams: new(uint32(8)), InitialStreamWindowSize: new(uint32(65535))}, ConnectTimeout: duration(2 * time.Second), PerConnectionBufferLimitBytes: new(uint32(65536)), TLSConfig: &gatewayapi.UpstreamTLS{ServerName: "backend.example.test", TrustedCA: ca}}
	second := c.APIs[0]
	second.Name = "ip-backend"
	second.Upstream = gatewayapi.Upstream{Address: "2001:db8::1", Port: 443, TLSConfig: &gatewayapi.UpstreamTLS{TrustedCA: ca}}
	c.APIs = append(c.APIs, second)
	r, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	b := decodeBootstrap(t, []byte(r.ConfigMap.Data["envoy.yaml"]))
	for i, cluster := range b.StaticResources.Clusters[:2] {
		var protocol upstreamhttp.HttpProtocolOptions
		if err := cluster.TypedExtensionProtocolOptions["envoy.extensions.upstreams.http.v3.HttpProtocolOptions"].UnmarshalTo(&protocol); err != nil {
			t.Fatal(err)
		}
		if protocol.RetryPolicy != nil {
			t.Fatal("retries emitted")
		}
		var transport tls.UpstreamTlsContext
		if err := cluster.TransportSocket.GetTypedConfig().UnmarshalTo(&transport); err != nil {
			t.Fatal(err)
		}
		validation := transport.CommonTlsContext.GetValidationContext()
		if validation.TrustedCa.GetFilename() != configuration.FilenameTrustedCA(*ca) {
			t.Fatalf("CA path = %v", validation)
		}
		if i == 0 {
			if protocol.GetExplicitHttpConfig().GetHttp2ProtocolOptions().MaxConcurrentStreams.Value != 8 || transport.Sni != "backend.example.test" || transport.CommonTlsContext.AlpnProtocols[0] != "h2" || cluster.ConnectTimeout.AsDuration() != 2*time.Second || cluster.PerConnectionBufferLimitBytes.Value != 65536 {
				t.Fatalf("HTTP/2 TLS upstream = %v / %v", cluster, &transport)
			}
		} else if protocol.GetExplicitHttpConfig().GetHttpProtocolOptions() == nil || transport.Sni != "" || validation.MatchTypedSubjectAltNames[0].SanType != tls.SubjectAltNameMatcher_IP_ADDRESS || validation.MatchTypedSubjectAltNames[0].Matcher.GetExact() != "2001:db8::1" {
			t.Fatalf("HTTP/1 IP TLS upstream = %v / %v", cluster, &transport)
		}
	}
	count := 0
	for _, v := range r.Deployment.Spec.Template.Spec.Volumes {
		if v.ConfigMap != nil && v.ConfigMap.Name == "shared-ca" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("shared JWKS/backend CA mount count = %d", count)
	}
}

func TestCircuitBreakerConfigAppliesToJWKSCluster(t *testing.T) {
	c := loadConfigCase(t, "jwt-auth-multiple-issuers")
	c.Authenticators[0].JWT.JWKS.CircuitBreakers = &gatewayapi.CircuitBreakerConfig{
		MaxConnections: new(uint32(3)), MaxRequests: new(uint32(0)), MaxRetries: new(uint32(7)),
	}
	resources, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := decodeBootstrap(t, []byte(resources.ConfigMap.Data[configuration.EnvoyConfigFilename]))
	name := configuration.JwksClusterName(c.Authenticators[0].Name)
	for _, cluster := range bootstrap.StaticResources.Clusters {
		if cluster.Name != name {
			continue
		}
		if len(cluster.CircuitBreakers.Thresholds) != 1 {
			t.Fatalf("JWKS circuit breaker thresholds = %v, want one threshold", cluster.CircuitBreakers.Thresholds)
		}
		limits := cluster.CircuitBreakers.Thresholds[0]
		if limits.MaxConnections.Value != 3 || limits.MaxPendingRequests.Value != 1024 ||
			limits.MaxRequests.Value != 0 || limits.MaxRetries.Value != 7 {
			t.Fatalf("JWKS circuit breaker limits = %v", limits)
		}
		return
	}
	t.Fatalf("JWKS cluster %q not found", name)
}
