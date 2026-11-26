package gateway

import (
	"slices"
	"strings"
	"testing"
	"time"

	extproc "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	lua "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/lua/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	upstreamhttp "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
)

func TestExternalProcessingValidation(t *testing.T) {
	for _, test := range []struct {
		name, want string
		edit       func(*gatewayapi.Config)
	}{
		{"unknown service", "processing.ext_proc.service references unknown", func(c *gatewayapi.Config) { c.APIs[0].Routes[0].Processing.ExtProc.Service = "missing" }},
		{"unbound unknown service", "processing.ext_proc.service references unknown", func(c *gatewayapi.Config) {
			c.Servers[0].APIs = c.Servers[0].APIs[1:]
			c.APIs[0].Routes[0].Processing.ExtProc.Service = "missing"
		}},
		{"empty service", "ext_proc.service is required", func(c *gatewayapi.Config) { c.APIs[0].Routes[0].Processing.ExtProc.Service = "" }},
		{"duplicate service", "name duplicates", func(c *gatewayapi.Config) { c.ExtProcServices = append(c.ExtProcServices, c.ExtProcServices[0]) }},
		{"invalid name", "name must start", func(c *gatewayapi.Config) { c.ExtProcServices[0].Name = "Invalid" }},
		{"HTTP1", "upstream.http_protocol must be http2", func(c *gatewayapi.Config) { c.ExtProcServices[0].Upstream.HTTPProtocol = "http1" }},
		{"invalid port", "upstream must have a valid address and port", func(c *gatewayapi.Config) { c.ExtProcServices[0].Upstream.Port = 0 }},
		{"invalid host", "upstream must have a valid address and port", func(c *gatewayapi.Config) { c.ExtProcServices[0].Upstream.Address = "https://processor" }},
		{"invalid timeout", "message_timeout", func(c *gatewayapi.Config) { c.ExtProcServices[0].MessageTimeout = duration(-time.Second) }},
		{"invalid TLS", "tls_config.server_name", func(c *gatewayapi.Config) { c.ExtProcServices[1].Upstream.TLSConfig.ServerName = "*" }},
		{"invalid header mode", "request_header_mode", func(c *gatewayapi.Config) { c.APIs[0].Routes[0].Processing.ExtProc.RequestHeaderMode = "all" }},
		{"invalid body mode", "request_body_mode", func(c *gatewayapi.Config) { c.APIs[0].Routes[0].Processing.ExtProc.RequestBodyMode = "all" }},
		{"invalid trailer mode", "request_trailer_mode", func(c *gatewayapi.Config) { c.APIs[0].Routes[0].Processing.ExtProc.RequestTrailerMode = "all" }},
		{"duplex without trailers", "request_trailer_mode must be send", func(c *gatewayapi.Config) {
			c.APIs[0].Routes[0].Processing.ExtProc.RequestBodyMode = "full_duplex_streamed"
		}},
		{"zero buffer limit", "request_body_buffer_limit_bytes must be positive", func(c *gatewayapi.Config) {
			c.APIs[0].Routes[0].Processing.ExtProc.RequestBodyBufferLimitBytes = new(uint64(0))
		}},
		{"buffer below listener", "request_body_buffer_limit_bytes must be at least listener.per_connection_buffer_limit_bytes", func(c *gatewayapi.Config) {
			c.APIs[0].Routes[0].Processing.ExtProc.RequestBodyBufferLimitBytes = new(uint64(1024))
		}},
		{"duplicate native properties", "request_attributes", func(c *gatewayapi.Config) {
			c.ExtProcServices[0].RequestAttributes = []string{"request.path", "request.path"}
		}},
		{"empty native property", "request_attributes", func(c *gatewayapi.Config) { c.ExtProcServices[0].RequestAttributes = []string{""} }},
		{"duplicate permissions", "mutable_request_headers", func(c *gatewayapi.Config) { c.ExtProcServices[0].MutableRequestHeaders = []string{"x-one", "X-One"} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := loadConfigCase(t, "ext-proc")
			test.edit(&c)
			if err := Validate(c); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate() = %v, want %q", err, test.want)
			}
		})
	}
	for _, header := range []string{"authorization", "cookie", "proxy-authorization", "host", ":authority", ":method", ":scheme", ":status", "x-envoy-retry-on", "x-envoy-anything", "x-auth-gateway-anything", "connection", "transfer-encoding", "x_subject", "x-api-key", "X-Subject", "bad header"} {
		t.Run(header, func(t *testing.T) {
			c := loadConfigCase(t, "ext-proc")
			c.ExtProcServices[0].MutableRequestHeaders = []string{header}
			if err := Validate(c); err == nil || !strings.Contains(err.Error(), "mutable_request_headers") {
				t.Fatalf("Validate() = %v, want forbidden mutation", err)
			}
		})
	}
	t.Run("external credential", func(t *testing.T) {
		c := loadConfigCase(t, "ext-authz")
		c.ExtAuthzServices[0].RequestHeaders = append(c.ExtAuthzServices[0].RequestHeaders, "x-external-secret")
		c.ExtAuthzServices[0].CredentialHeaders = append(c.ExtAuthzServices[0].CredentialHeaders, "x-external-secret")
		c.ExtProcServices = []gatewayapi.ExternalProcessingService{{Name: "process", Upstream: gatewayapi.Upstream{Address: "processor", Port: 9000, HTTPProtocol: "http2"}, MutableRequestHeaders: []string{"X-External-Secret"}}}
		if err := Validate(c); err == nil || !strings.Contains(err.Error(), "mutable_request_headers") {
			t.Fatalf("Validate() = %v", err)
		}
	})
}

func TestExternalProcessingModes(t *testing.T) {
	for _, mode := range []string{"none", "buffered", "buffered_partial", "streamed", "full_duplex_streamed"} {
		for _, header := range []string{"send", "skip"} {
			t.Run(mode+"/"+header, func(t *testing.T) {
				c := loadConfigCase(t, "ext-proc")
				p := c.APIs[0].Routes[0].Processing.ExtProc
				p.RequestHeaderMode, p.RequestBodyMode, p.RequestTrailerMode = header, mode, "send"
				files, err := Generate(c)
				if err != nil {
					t.Fatal(err)
				}
				generated := firstHTTPManager(t, files.EnvoyBootstrap.Contents).GetRouteConfig().GetVirtualHosts()[0].Routes[0]
				var perRoute extproc.ExtProcPerRoute
				if err := generated.TypedPerFilterConfig[extProcFilterName("transform")].UnmarshalTo(&perRoute); err != nil {
					t.Fatal(err)
				}
				got := perRoute.GetOverrides().GetProcessingMode()
				if strings.ToLower(got.GetRequestBodyMode().String()) != mode || strings.ToLower(got.GetRequestHeaderMode().String()) != header || got.GetRequestTrailerMode() != extproc.ProcessingMode_SEND || got.GetResponseHeaderMode() != extproc.ProcessingMode_SKIP || got.GetResponseBodyMode() != extproc.ProcessingMode_NONE || got.GetResponseTrailerMode() != extproc.ProcessingMode_SKIP {
					t.Fatalf("processing mode = %v", got)
				}
			})
		}
	}
}

func TestExternalProcessingGeneratedFiltersAndRoutes(t *testing.T) {
	c := loadConfigCase(t, "ext-proc")
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	manager := firstHTTPManager(t, files.EnvoyBootstrap.Contents)
	positions := make(map[string]int)
	for index, filter := range manager.HttpFilters {
		positions[filter.Name] = index
		if !strings.HasPrefix(filter.Name, extProcFilterPrefix) || filter.Name == extProcAttributeBridgeName {
			continue
		}
		if !filter.Disabled {
			t.Fatal("processor must be disabled by default")
		}
		var p extproc.ExternalProcessor
		if err := filter.GetTypedConfig().UnmarshalTo(&p); err != nil {
			t.Fatal(err)
		}
		if p.GetRouteCacheAction() != extproc.ExternalProcessor_RETAIN || p.GetAllowModeOverride() || p.GetObservabilityMode() || p.GetMetadataOptions().GetReceivingNamespaces() != nil || p.GetForwardRules() != nil || p.GetDisableImmediateResponse() {
			t.Fatalf("unsafe processor configuration: %v", &p)
		}
		if !p.GetMutationRules().GetDisallowAll().GetValue() || !p.GetMutationRules().GetDisallowIsError().GetValue() {
			t.Fatal("missing native mutation restrictions")
		}
		if !slices.Equal(p.GetMetadataOptions().GetForwardingNamespaces().GetUntyped(), []string{extProcInputMetadataName, jwtAuthnFilterName}) {
			t.Fatal("missing processor metadata")
		}
		if filter.Name == extProcFilterName("transform") {
			if p.GetFailureModeAllow() || p.GetMessageTimeout().AsDuration() != 200*time.Millisecond {
				t.Fatal("incorrect defaults")
			}
			if !slices.Equal(p.GetRequestAttributes(), []string{"request.method", "request.path"}) {
				t.Fatal("native properties lost")
			}
		} else if !p.GetFailureModeAllow() || p.GetMessageTimeout().AsDuration() != 500*time.Millisecond || p.GetMutationRules().GetAllowExpression() != nil {
			t.Fatal("inspection service settings lost")
		}
	}
	for _, pair := range [][2]string{{authorizationFilterName, credentialCleanupFilterName}, {credentialCleanupFilterName, headerMutationFilterName}, {headerMutationFilterName, extProcAttributeBridgeName}, {extProcAttributeBridgeName, extProcFilterName("transform")}, {extProcFilterName("inspect"), routerFilterName}} {
		if positions[pair[0]] >= positions[pair[1]] {
			t.Fatalf("filter order: %v", positions)
		}
	}
	for _, r := range manager.GetRouteConfig().VirtualHosts[0].Routes {
		transform := r.TypedPerFilterConfig[extProcFilterName("transform")]
		inspect := r.TypedPerFilterConfig[extProcFilterName("inspect")]
		if r.GetDirectResponse() != nil || r.Match.GetPath() == "/unprocessed" {
			if transform != nil || inspect != nil || r.TypedPerFilterConfig[extProcAttributeBridgeName] != nil {
				t.Fatalf("unprocessed route %s invokes processor", r.Name)
			}
			continue
		}
		if (transform == nil) == (inspect == nil) {
			t.Fatalf("route %s must select exactly one service", r.Name)
		}
		var bridge lua.LuaPerRoute
		if err := r.TypedPerFilterConfig[extProcAttributeBridgeName].UnmarshalTo(&bridge); err != nil {
			t.Fatal(err)
		}
		want := []any{"origin", "role", "subject"}
		if strings.Contains(r.Name, "-access-1-") {
			want = []any{"role", "subject"}
		}
		if r.Match.GetPath() == "/public" {
			want = []any{"audience"}
		}
		assertConfigDiff(t, r.Name+" attributes", map[string]any{"attributes": want}, bridge.GetFilterContext().AsMap())
		if r.Match.GetPath() == "/buffered" {
			if r.GetRequestBodyBufferLimit().GetValue() != 2097152 {
				t.Fatal("route buffer override lost")
			}
		} else if r.GetRequestBodyBufferLimit() != nil {
			t.Fatal("route must inherit listener buffer limit")
		}
	}
	bootstrap := decodeBootstrap(t, files.EnvoyBootstrap.Contents)
	for _, cluster := range bootstrap.GetStaticResources().Clusters {
		switch cluster.Name {
		case "ext-proc-transform":
			var protocol upstreamhttp.HttpProtocolOptions
			if err := cluster.TypedExtensionProtocolOptions["envoy.extensions.upstreams.http.v3.HttpProtocolOptions"].UnmarshalTo(&protocol); err != nil {
				t.Fatal(err)
			}
			if protocol.GetExplicitHttpConfig().GetHttp2ProtocolOptions() == nil {
				t.Fatal("processor does not use HTTP/2")
			}
			if cluster.GetTransportSocket() != nil {
				t.Fatal("plaintext processor uses TLS")
			}
		case "ext-proc-inspect":
			var transport tls.UpstreamTlsContext
			if err := cluster.GetTransportSocket().GetTypedConfig().UnmarshalTo(&transport); err != nil {
				t.Fatal(err)
			}
			validation := transport.GetCommonTlsContext().GetValidationContext()
			if transport.Sni != "inspector.example.test" || !slices.Equal(transport.GetCommonTlsContext().GetAlpnProtocols(), []string{"h2"}) || validation.GetTrustedCa().GetFilename() == "" || len(validation.GetMatchTypedSubjectAltNames()) != 1 || validation.GetMatchTypedSubjectAltNames()[0].GetMatcher().GetExact() != "inspector.example.test" {
				t.Fatal("processor TLS identity or trust missing")
			}
			if cluster.GetTransportSocket() == nil {
				t.Fatal("TLS processor lacks verified transport")
			}
		}
	}
	mounts := resolveTestConfig(t, c).caMounts()
	if !slices.Contains(mounts, gatewayapi.CAConfigMap{Name: "processor-ca", Key: "ca.pem"}) {
		t.Fatal("processor CA not mounted")
	}
}

func TestExternalProcessingCloningAndDefaults(t *testing.T) {
	c := loadConfigCase(t, "ext-proc")
	c.ExtProcServices[0].MessageTimeout = nil
	c.APIs[0].Routes[0].Processing.ExtProc.RequestHeaderMode = ""
	cloned := withDefaultsConfig(c)
	if c.ExtProcServices[0].MessageTimeout != nil || c.APIs[0].Routes[0].Processing.ExtProc.RequestHeaderMode != "" {
		t.Fatal("defaulting mutated input")
	}
	if *cloned.ExtProcServices[0].MessageTimeout != gatewayapi.Duration(200*time.Millisecond) || cloned.APIs[0].Routes[0].Processing.ExtProc.RequestHeaderMode != "send" {
		t.Fatal("defaults missing")
	}
	cloned.ExtProcServices[0].MutableRequestHeaders[0] = "changed"
	cloned.ExtProcServices[0].RequestAttributes[0] = "changed"
	*cloned.APIs[0].Routes[0].Processing.ExtProc.RequestBodyBufferLimitBytes = 10
	cloned.ExtProcServices[1].Upstream.TLSConfig.TrustedCA.ConfigMap.Name = "changed"
	if c.ExtProcServices[0].MutableRequestHeaders[0] != "x-processed" || c.ExtProcServices[0].RequestAttributes[0] != "request.method" || *c.APIs[0].Routes[0].Processing.ExtProc.RequestBodyBufferLimitBytes != 2097152 || c.ExtProcServices[1].Upstream.TLSConfig.TrustedCA.ConfigMap.Name != "processor-ca" {
		t.Fatal("cloned configuration aliases input")
	}
}

func TestExternalProcessingAfterExternalAuthorization(t *testing.T) {
	c := loadConfigCase(t, "ext-authz")
	c.APIs[0].Attributes = []gatewayapi.AttributeSource{testTextAttribute("operation", "fixed", "ingest")}
	c.ExtProcServices = []gatewayapi.ExternalProcessingService{{Name: "process", Upstream: gatewayapi.Upstream{Address: "processor", Port: 9000, HTTPProtocol: "http2"}}}
	c.APIs[0].Routes[0].Processing.ExtProc = &gatewayapi.ExternalProcessing{Service: "process"}
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	manager := firstHTTPManager(t, files.EnvoyBootstrap.Contents)
	positions := make(map[string]int)
	for i, filter := range manager.HttpFilters {
		positions[filter.Name] = i
	}
	if positions[extAuthzFilterName("policy")] >= positions[extAuthzCredentialCleanupName] || positions[extAuthzCredentialCleanupName] >= positions[extProcFilterName("process")] {
		t.Fatalf("processing precedes authorization or credential cleanup: %v", positions)
	}
	host := manager.GetRouteConfig().VirtualHosts[0]
	for _, test := range []struct {
		name string
		want []any
	}{
		{"api-0-metrics-route-0-access-0-match-0", []any{"auth_origin", "operation", "requested_tenant", "tenant_id"}},
		{"api-0-metrics-route-0-access-1-match-0", []any{"auth_origin", "operation", "requested_tenant", "tenant_id"}},
	} {
		generated := namedRoute(host.Routes, test.name)
		if generated == nil {
			t.Fatalf("route %s missing", test.name)
		}
		var bridge lua.LuaPerRoute
		if err := generated.TypedPerFilterConfig[extProcAttributeBridgeName].UnmarshalTo(&bridge); err != nil {
			t.Fatal(err)
		}
		assertConfigDiff(t, test.name+" processor context", map[string]any{"attributes": test.want}, bridge.GetFilterContext().AsMap())
	}
}

func TestExternalProcessingWithoutSelectedAttributes(t *testing.T) {
	c := loadConfigCase(t, "public-routing")
	c.ExtProcServices = []gatewayapi.ExternalProcessingService{{Name: "inspect", Upstream: gatewayapi.Upstream{Address: "processor", Port: 9000, HTTPProtocol: "http2"}}}
	c.APIs[0].Routes[0].Processing = &gatewayapi.RouteProcessing{ExtProc: &gatewayapi.ExternalProcessing{Service: "inspect"}}
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := decodeBootstrap(t, files.EnvoyBootstrap.Contents)
	manager := decodeHTTPManager(t, bootstrap.StaticResources.Listeners[0].FilterChains[0])
	var bridge lua.LuaPerRoute
	if err := manager.GetRouteConfig().VirtualHosts[0].Routes[0].TypedPerFilterConfig[extProcAttributeBridgeName].UnmarshalTo(&bridge); err != nil {
		t.Fatal(err)
	}
	assertConfigDiff(t, "empty processor context", map[string]any{"attributes": []any{}}, bridge.GetFilterContext().AsMap())
}
