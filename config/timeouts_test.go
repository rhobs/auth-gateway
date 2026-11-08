package config

import (
	"slices"
	"strings"
	"testing"
	"time"

	yaml "go.yaml.in/yaml/v3"
)

func TestLoadKeepsTimeoutOverridesUnresolved(t *testing.T) {
	c := loadConfigCase(t, "production-tuning")
	if c.Listener.Port == nil || *c.Listener.Port != 8080 {
		t.Fatalf("listener port default = %v", c.Listener.Port)
	}
	if c.APIs[0].Routes[0].Timeouts != nil {
		t.Fatal("Load filled omitted route timeouts")
	}
	timeouts := c.APIs[0].Routes[1].Timeouts
	wantTimeouts := &RouteTimeouts{ResponseTimeout: duration(20 * time.Second), MaxStreamDuration: duration(30 * time.Second)}
	assertConfigDiff(t, "partial route timeout overrides", wantTimeouts, timeouts)
}

func TestLoadRejectsIncompatibleEffectiveRouteTimeouts(t *testing.T) {
	input := `version: 1
listener:
  max_stream_duration: 10s
servers:
  - hostname: auth.example.test
    apis: [metrics]
apis:
  - name: metrics
    upstream: {address: httpbin, port: 80}
    timeouts: {response_timeout: 20s}
    routes:
      - methods: [GET]
        path: {exact: /metrics}
`
	if _, err := Load(strings.NewReader(input)); err == nil ||
		!strings.Contains(err.Error(), "apis[0].routes[0].timeouts.response_timeout (20s)") ||
		!strings.Contains(err.Error(), "max_stream_duration (10s)") {
		t.Fatalf("Load error = %v, want effective route timeout conflict", err)
	}
}

func TestResolvedRouteTimeoutsAndReuse(t *testing.T) {
	c := loadConfigCase(t, "public-routing")
	c.Listener.StreamIdleTimeout = duration(75 * time.Second)
	c.Listener.MaxStreamDuration = duration(45 * time.Second)
	c.APIs[0].Timeouts = &RouteTimeouts{ResponseTimeout: duration(60 * time.Second), MaxStreamDuration: duration(90 * time.Second)}
	c.APIs[0].Routes = []Route{
		{Methods: []string{"GET", "POST"}, Path: PathMatch{Exact: "/query"}},
		{Methods: []string{"GET"}, Path: PathMatch{Exact: "/range"}, Timeouts: &RouteTimeouts{ResponseTimeout: duration(80 * time.Second), IdleTimeout: duration(95 * time.Second), MaxStreamDuration: duration(120 * time.Second)}},
	}
	c.Servers = append(c.Servers, Server{Hostname: "second.example.test", APIs: slices.Clone(c.Servers[0].APIs)})
	before, _ := yaml.Marshal(c)
	effective, err := resolveConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	if *effective.APIs[0].Routes[0].Timeouts.IdleTimeout != Duration(75*time.Second) {
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
	*effective.APIs[0].Routes[0].Timeouts.ResponseTimeout = Duration(time.Second)
	if *c.APIs[0].Timeouts.ResponseTimeout != Duration(60*time.Second) {
		t.Fatal("resolved timeout aliases caller")
	}
	c.APIs[0].Timeouts.MaxStreamDuration = nil
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "1m0s") || !strings.Contains(err.Error(), "45s") || !strings.Contains(err.Error(), "apis[0].routes[0]") {
		t.Fatalf("incompatible effective timers: %v", err)
	}
}
