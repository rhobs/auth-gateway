package config

import (
	"strings"
	"testing"
)

func TestLoadRejectsMissingRouteMethods(t *testing.T) {
	input := `version: 1
servers:
  - hostname: auth.example.com
    apis: [metrics]
apis:
  - name: metrics
    upstream:
      address: thanos-receive
      port: 19291
    routes:
      - path:
          exact: /metrics/api/v1/receive
`
	if _, err := Load(strings.NewReader(input)); err == nil || !strings.Contains(err.Error(), ".methods") {
		t.Fatalf("Load error = %v, want a missing route methods error", err)
	}
}

func TestValidateRejectsInvalidRouteConfiguration(t *testing.T) {
	routeListConfig := readFixture(t, "route-lists/config.yaml")
	tests := []struct {
		name string
		want string
		edit func(*Config)
	}{
		{name: "multiple path matchers", want: "apis[0].routes[0].path", edit: func(c *Config) { c.APIs[0].Routes[0].Path.Prefix = "/metrics/" }},
		{name: "invalid path regex", want: "apis[0].routes[0].path.regex", edit: func(c *Config) { c.APIs[0].Routes[0].Path.Regex = "[" }},
		{name: "duplicate method", want: "apis[0].routes[0].methods", edit: func(c *Config) { c.APIs[0].Routes[0].Methods = []string{"GET", "GET"} }},
		{name: "missing path matcher", want: "apis[0].routes[0].path", edit: func(c *Config) { c.APIs[0].Routes[0].Path = PathMatch{} }},
		{name: "multiple rewrite types", want: "apis[0].routes[0].rewrite", edit: func(c *Config) { c.APIs[0].Routes[0].Rewrite = &PathRewrite{Path: "/query", Prefix: "/api/"} }},
		{name: "duplicate route", want: "duplicate API route", edit: func(c *Config) { c.APIs[0].Routes = append(c.APIs[0].Routes, c.APIs[0].Routes[0]) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := loadTestConfig(t, routeListConfig, "valid route baseline")
			test.edit(&config)
			if err := config.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validation error = %v, want %q", err, test.want)
			}
		})
	}
}
