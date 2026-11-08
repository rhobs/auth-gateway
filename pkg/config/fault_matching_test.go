package config

import (
	"strings"
	"testing"

	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
)

func faultSelectorConfig(t testing.TB) gatewayapi.Config {
	t.Helper()
	return loadTestConfig(t, readFixture(t, "fault-selectors.yaml"), "fault selectors")
}

func TestLoadFaultMatchSelectors(t *testing.T) {
	c := faultSelectorConfig(t)
	want := &gatewayapi.FaultMatchConfig{
		Headers:    map[string]string{"X-Inject-Fault": "true"},
		Attributes: map[string][]string{"tenant_id": {"tenant-a", "tenant-c"}, "writer_id": {"writer-a"}},
	}
	assertConfigDiff(t, "fault selectors", want, c.APIs[0].FaultInjection.Match)
}

func TestFaultMatchDefaultsCloneInput(t *testing.T) {
	c := faultSelectorConfig(t)
	defaulted := withDefaultsConfig(c)
	defaulted.APIs[0].FaultInjection.Match.Headers["X-Inject-Fault"] = "changed"
	defaulted.APIs[0].FaultInjection.Match.Attributes["tenant_id"][0] = "changed"
	defaulted.APIs[0].FaultInjection.Match.Attributes["writer_id"] = []string{"changed"}
	want := &gatewayapi.FaultMatchConfig{
		Headers:    map[string]string{"X-Inject-Fault": "true"},
		Attributes: map[string][]string{"tenant_id": {"tenant-a", "tenant-c"}, "writer_id": {"writer-a"}},
	}
	assertConfigDiff(t, "original fault selectors", want, c.APIs[0].FaultInjection.Match)
}

func TestFaultMatchValidation(t *testing.T) {
	for _, test := range []struct {
		name  string
		field string
		edit  func(*gatewayapi.FaultMatchConfig)
	}{
		{name: "empty match", field: "match must contain", edit: func(c *gatewayapi.FaultMatchConfig) { *c = gatewayapi.FaultMatchConfig{} }},
		{name: "invalid header", field: "match.headers", edit: func(c *gatewayapi.FaultMatchConfig) { c.Headers[":path"] = "/" }},
		{name: "credential header", field: "match.headers", edit: func(c *gatewayapi.FaultMatchConfig) { c.Headers["Authorization"] = "test" }},
		{name: "internal header", field: "match.headers", edit: func(c *gatewayapi.FaultMatchConfig) { c.Headers["X-Auth-Gateway-Tenant"] = "test" }},
		{name: "removed header", field: "match.headers", edit: func(c *gatewayapi.FaultMatchConfig) { c.Headers["X-Envoy-Max-Retries"] = "1" }},
		{name: "duplicate header case", field: "match.headers", edit: func(c *gatewayapi.FaultMatchConfig) { c.Headers["x-inject-fault"] = "true" }},
		{name: "empty header value", field: "match.headers.X-Inject-Fault", edit: func(c *gatewayapi.FaultMatchConfig) { c.Headers["X-Inject-Fault"] = "" }},
		{name: "header control character", field: "match.headers.X-Inject-Fault", edit: func(c *gatewayapi.FaultMatchConfig) { c.Headers["X-Inject-Fault"] = "yes\n" }},
		{name: "invalid attribute name", field: "match.attributes", edit: func(c *gatewayapi.FaultMatchConfig) { c.Attributes["Tenant"] = []string{"a"} }},
		{name: "empty values", field: "match.attributes.tenant_id", edit: func(c *gatewayapi.FaultMatchConfig) { c.Attributes["tenant_id"] = nil }},
		{name: "empty attribute value", field: "match.attributes.tenant_id", edit: func(c *gatewayapi.FaultMatchConfig) { c.Attributes["tenant_id"] = []string{""} }},
		{name: "attribute control character", field: "match.attributes.tenant_id", edit: func(c *gatewayapi.FaultMatchConfig) { c.Attributes["tenant_id"] = []string{"a\x7f"} }},
		{name: "duplicate attribute values", field: "match.attributes.tenant_id", edit: func(c *gatewayapi.FaultMatchConfig) { c.Attributes["tenant_id"] = []string{"a", "a"} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := faultSelectorConfig(t)
			test.edit(c.APIs[0].FaultInjection.Match)
			want := "apis[0].fault_injection." + test.field
			if err := Validate(c); err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("validation error = %v, want %q", err, want)
			}
		})
	}
}

func TestFaultMatchReferences(t *testing.T) {
	for _, test := range []struct {
		name string
		want string
		edit func(*gatewayapi.Config)
	}{
		{name: "API key trigger", want: "apis[0].fault_injection.match.headers.X-Partner-Key is reserved", edit: func(c *gatewayapi.Config) {
			c.APIs[0].FaultInjection.Match.Headers["X-Partner-Key"] = "key-a"
		}},
		{name: "overwritten trigger", want: "apis[0].fault_injection.match.headers.X-Inject-Fault is overwritten", edit: func(c *gatewayapi.Config) {
			c.APIs[0].Routes[0].Processing = &gatewayapi.RouteProcessing{RequestHeaders: []gatewayapi.RequestHeaderMapping{{Name: "x-inject-fault", FromAttribute: "tenant_id"}}}
		}},
		{name: "unknown attribute", want: "servers[0] authentication does not provide fault_injection.match.attributes.unknown", edit: func(c *gatewayapi.Config) {
			c.APIs[0].FaultInjection.Match.Attributes["unknown"] = []string{"a"}
		}},
		{name: "unbound provider", want: "servers[0] authentication does not provide fault_injection.match.attributes.writer_id", edit: func(c *gatewayapi.Config) {
			c.Servers[0].Authentication = &gatewayapi.Authentication{AnyOf: []string{"partner-key"}}
			delete(c.Authenticators[1].Attributes, "writer_id")
		}},
		{name: "public binding", want: "servers[0] authentication does not provide fault_injection.match.attributes.tenant_id", edit: func(c *gatewayapi.Config) {
			c.Servers[0].Authentication = nil
			c.Servers[0].Authorization = nil
		}},
		{name: "request header tenant", want: "fault_injection.match.attributes.tenant_id requires an identity attribute", edit: func(c *gatewayapi.Config) {
			c.Authenticators[0].Attributes["tenant_id"] = gatewayapi.AttributeSource{Header: new("X-Tenant-ID")}
		}},
		{name: "invalid disabled match", want: "fault_injection.match.attributes.unknown", edit: func(c *gatewayapi.Config) {
			c.APIs[0].FaultInjection.Enabled = false
			c.APIs[0].FaultInjection.Match.Attributes["unknown"] = []string{"a"}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := faultSelectorConfig(t)
			test.edit(&c)
			if err := Validate(c); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validation error = %v, want %q", err, test.want)
			}
		})
	}
}
