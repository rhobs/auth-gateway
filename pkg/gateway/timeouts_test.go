package gateway

import (
	"strings"
	"testing"
	"time"

	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
)

func TestDurationErrorIncludesFieldPath(t *testing.T) {
	if _, err := Load(strings.NewReader(readFixture(t, "jwks-duration-invalid.yaml"))); err == nil || !strings.Contains(err.Error(), "authenticators[0].jwt.jwks.fetch_timeout") {
		t.Fatalf("duration field error = %v, want the complete field path", err)
	}
}

func TestLoadKeepsTimeoutOverridesUnresolved(t *testing.T) {
	c := loadConfigCase(t, "production-tuning")
	if c.Listener.Port == nil || *c.Listener.Port != 8080 {
		t.Fatalf("listener port default = %v", c.Listener.Port)
	}
	if c.APIs[0].Routes[0].Timeouts != nil {
		t.Fatal("Load filled omitted route timeouts")
	}
	timeouts := c.APIs[0].Routes[1].Timeouts
	wantTimeouts := &gatewayapi.RouteTimeouts{ResponseTimeout: duration(20 * time.Second), MaxStreamDuration: duration(30 * time.Second)}
	assertConfigDiff(t, "partial route timeout overrides", wantTimeouts, timeouts)
}

func TestLoadRejectsIncompatibleEffectiveRouteTimeouts(t *testing.T) {
	input := `version: 1
listener:
  max_stream_duration: 10s
servers:
- hostname: auth.example.test
  apis:
  - name: metrics
    public: true
apis:
- name: metrics
  upstream:
    address: httpbin
    port: 80
  timeouts:
    response_timeout: 20s
  routes:
  - methods:
    - GET
    path:
      exact: "/metrics"
`
	if _, err := Load(strings.NewReader(input)); err == nil ||
		!strings.Contains(err.Error(), "apis[0].routes[0].timeouts.response_timeout (20s)") ||
		!strings.Contains(err.Error(), "max_stream_duration (10s)") {
		t.Fatalf("Load error = %v, want effective route timeout conflict", err)
	}
}
