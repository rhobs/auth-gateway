package gateway

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	mutationrules "github.com/envoyproxy/go-control-plane/envoy/config/common/mutation_rules/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	extproc "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	lua "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/lua/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	extProcModeSend              = "send"
	extProcFilterPrefix          = "auth_gateway.ext_proc."
	extProcInputMetadataName     = "auth_gateway.ext_proc.attributes"
	extProcAttributeBridgeName   = "auth_gateway.ext_proc.attribute_bridge"
	extProcAttributeBridgeScript = `function envoy_on_request(handle)
  local context = handle:filterContext()
  local attributes = context and context:get("attributes")
  if attributes == nil then
    return
  end
  local state = handle:streamInfo():filterState()
  local metadata = handle:streamInfo():dynamicMetadata()
  for _, name in ipairs(attributes) do
    local value = state:get("auth_gateway.attributes." .. name)
    if value ~= nil and value ~= "" then
      metadata:set("auth_gateway.ext_proc.attributes", name, value)
    end
  end
end
`
)

func extProcFilterName(service string) string  { return extProcFilterPrefix + service }
func extProcClusterName(service string) string { return "ext-proc-" + service }

func cloneExtProcService(s gatewayapi.ExternalProcessingService) gatewayapi.ExternalProcessingService {
	s.Upstream = cloneUpstream(s.Upstream)
	s.MessageTimeout = clonePointer(s.MessageTimeout)
	s.RequestAttributes = slices.Clone(s.RequestAttributes)
	s.MutableRequestHeaders = slices.Clone(s.MutableRequestHeaders)
	return s
}

func cloneExtProc(p gatewayapi.ExternalProcessing) gatewayapi.ExternalProcessing {
	p.RequestBodyBufferLimitBytes = clonePointer(p.RequestBodyBufferLimitBytes)
	return p
}

func withDefaultsExtProcService(s gatewayapi.ExternalProcessingService) gatewayapi.ExternalProcessingService {
	s.Upstream = withDefaultsUpstream(s.Upstream)
	s.MessageTimeout = withDefaultDuration(s.MessageTimeout, 200*time.Millisecond)
	return s
}

func withDefaultsExtProc(p gatewayapi.ExternalProcessing) gatewayapi.ExternalProcessing {
	if p.RequestHeaderMode == "" {
		p.RequestHeaderMode = extProcModeSend
	}
	if p.RequestBodyMode == "" {
		p.RequestBodyMode = "none"
	}
	if p.RequestTrailerMode == "" {
		p.RequestTrailerMode = "skip"
	}
	return p
}

func validateExtProc(field string, p gatewayapi.ExternalProcessing) error {
	if p.Service == "" {
		return fmt.Errorf("%s.service is required", field)
	}
	if p.RequestHeaderMode != extProcModeSend && p.RequestHeaderMode != "skip" {
		return fmt.Errorf("%s.request_header_mode must be send or skip", field)
	}
	if p.RequestTrailerMode != extProcModeSend && p.RequestTrailerMode != "skip" {
		return fmt.Errorf("%s.request_trailer_mode must be send or skip", field)
	}
	switch p.RequestBodyMode {
	case "none", "buffered", "buffered_partial", "streamed":
	case "full_duplex_streamed":
		if p.RequestTrailerMode != extProcModeSend {
			return fmt.Errorf("%s.request_trailer_mode must be send for full_duplex_streamed", field)
		}
	default:
		return fmt.Errorf("%s.request_body_mode must be none, buffered, buffered_partial, streamed, or full_duplex_streamed", field)
	}
	if p.RequestBodyBufferLimitBytes != nil && *p.RequestBodyBufferLimitBytes == 0 {
		return fmt.Errorf("%s.request_body_buffer_limit_bytes must be positive", field)
	}
	return nil
}

func validateExtProcServices(c gatewayapi.Config) error {
	protected := extProcProtectedHeaders(c)
	known := make(map[string]bool, len(c.ExtProcServices))
	for index, service := range c.ExtProcServices {
		field := fmt.Sprintf("ext_proc_services[%d]", index)
		if err := validateGatewayName(field, service.Name); err != nil {
			return err
		}
		if known[service.Name] {
			return fmt.Errorf("%s.name duplicates ext_proc service %q", field, service.Name)
		}
		known[service.Name] = true
		if !validHost(service.Upstream.Address) || service.Upstream.Port == 0 || service.Upstream.Port > 65535 {
			return fmt.Errorf("%s.upstream must have a valid address and port", field)
		}
		if service.Upstream.HTTPProtocol != http2Protocol {
			return fmt.Errorf("%s.upstream.http_protocol must be http2", field)
		}
		if err := validateUpstream(service.Upstream, field+".upstream", c.Kubernetes != nil); err != nil {
			return err
		}
		if err := validateDuration(field+".message_timeout", service.MessageTimeout, true); err != nil {
			return err
		}
		seen := make(map[string]bool)
		for _, attribute := range service.RequestAttributes {
			if attribute == "" || strings.ContainsAny(attribute, " \t\r\n\x00") || seen[attribute] {
				return fmt.Errorf("%s.request_attributes must contain distinct nonempty property names", field)
			}
			seen[attribute] = true
		}
		seen = make(map[string]bool)
		for _, header := range service.MutableRequestHeaders {
			name := strings.ToLower(header)
			pathOrLength := name == ":path" || name == "content-length"
			if (!pathOrLength && (!validHeaderFieldName(header) || forbiddenIdentityHeader(name))) ||
				strings.Contains(name, "_") || strings.HasPrefix(name, "x-envoy") || protected[name] || seen[name] {
				return fmt.Errorf("%s.mutable_request_headers contains forbidden or duplicate header %q", field, header)
			}
			seen[name] = true
		}
	}
	for ai, api := range c.APIs {
		for ri, r := range api.Routes {
			if r.Processing == nil || r.Processing.ExtProc == nil {
				continue
			}
			p := r.Processing.ExtProc
			if !known[p.Service] {
				return fmt.Errorf("apis[%d].routes[%d].processing.ext_proc.service references unknown service %q", ai, ri, p.Service)
			}
			if p.RequestBodyBufferLimitBytes != nil && *p.RequestBodyBufferLimitBytes < uint64(*c.Listener.PerConnectionBufferLimitBytes) {
				return fmt.Errorf("apis[%d].routes[%d].processing.ext_proc.request_body_buffer_limit_bytes must be at least listener.per_connection_buffer_limit_bytes (%d)", ai, ri, *c.Listener.PerConnectionBufferLimitBytes)
			}
		}
	}
	return nil
}

func extProcProtectedHeaders(c gatewayapi.Config) map[string]bool {
	headers := make(map[string]bool)
	for _, a := range c.Authenticators {
		if a.APIKey != nil {
			headers[strings.ToLower(a.APIKey.Header)] = true
		}
	}
	for _, service := range c.ExtAuthzServices {
		for _, name := range service.CredentialHeaders {
			headers[strings.ToLower(name)] = true
		}
	}
	for _, api := range c.APIs {
		for _, r := range api.Routes {
			if r.Processing == nil {
				continue
			}
			for _, mapping := range r.Processing.RequestHeaders {
				headers[strings.ToLower(mapping.Name)] = true
			}
		}
	}
	return headers
}

func extProcCluster(service gatewayapi.ExternalProcessingService) (*cluster.Cluster, error) {
	clusters, err := apiClusters([]gatewayapi.API{{Name: service.Name, Upstream: service.Upstream, CircuitBreakers: withDefaultsCircuitBreakerConfig(nil)}})
	if err != nil {
		return nil, err
	}
	result := clusters[0]
	result.Name = extProcClusterName(service.Name)
	result.LoadAssignment.ClusterName = result.Name
	return result, nil
}

func extProcProcessingMode(p gatewayapi.ExternalProcessing) *extproc.ProcessingMode {
	return &extproc.ProcessingMode{
		RequestHeaderMode:   extproc.ProcessingMode_HeaderSendMode(extproc.ProcessingMode_HeaderSendMode_value[strings.ToUpper(p.RequestHeaderMode)]),
		RequestBodyMode:     extproc.ProcessingMode_BodySendMode(extproc.ProcessingMode_BodySendMode_value[strings.ToUpper(p.RequestBodyMode)]),
		RequestTrailerMode:  extproc.ProcessingMode_HeaderSendMode(extproc.ProcessingMode_HeaderSendMode_value[strings.ToUpper(p.RequestTrailerMode)]),
		ResponseHeaderMode:  extproc.ProcessingMode_SKIP,
		ResponseBodyMode:    extproc.ProcessingMode_NONE,
		ResponseTrailerMode: extproc.ProcessingMode_SKIP,
	}
}

func extProcHTTPFilter(service gatewayapi.ExternalProcessingService) (*hcm.HttpFilter, error) {
	rules := &mutationrules.HeaderMutationRules{DisallowAll: wrapperspb.Bool(true), DisallowIsError: wrapperspb.Bool(true)}
	if len(service.MutableRequestHeaders) != 0 {
		names := make([]string, len(service.MutableRequestHeaders))
		for i, name := range service.MutableRequestHeaders {
			names[i] = regexp.QuoteMeta(strings.ToLower(name))
		}
		slices.Sort(names)
		rules.AllowExpression = envoySafeRegex("^(?:" + strings.Join(names, "|") + ")$")
	}
	config, err := packEnvoy(&extproc.ExternalProcessor{
		GrpcService:       &core.GrpcService{TargetSpecifier: &core.GrpcService_EnvoyGrpc_{EnvoyGrpc: &core.GrpcService_EnvoyGrpc{ClusterName: extProcClusterName(service.Name)}}},
		MessageTimeout:    protobufDuration(service.MessageTimeout),
		FailureModeAllow:  service.FailureModeAllow,
		ProcessingMode:    extProcProcessingMode(withDefaultsExtProc(gatewayapi.ExternalProcessing{})),
		RequestAttributes: service.RequestAttributes,
		MutationRules:     rules,
		RouteCacheAction:  extproc.ExternalProcessor_RETAIN,
		MetadataOptions:   &extproc.MetadataOptions{ForwardingNamespaces: &extproc.MetadataOptions_MetadataNamespaces{Untyped: []string{extProcInputMetadataName, jwtAuthnFilterName}}},
		StatPrefix:        service.Name,
	})
	if err != nil {
		return nil, err
	}
	return &hcm.HttpFilter{Name: extProcFilterName(service.Name), Disabled: true, ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: config}}, nil
}

func extProcAttributeBridgeFilter() (*hcm.HttpFilter, error) {
	config, err := packEnvoy(&lua.Lua{DefaultSourceCode: &core.DataSource{Specifier: &core.DataSource_InlineString{InlineString: extProcAttributeBridgeScript}}, ClearRouteCache: wrapperspb.Bool(false)})
	if err != nil {
		return nil, err
	}
	return &hcm.HttpFilter{Name: extProcAttributeBridgeName, ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: config}}, nil
}

func addExtProcAPIRouteConfigs(routes []*route.Route, apis []gatewayapi.API) error {
	byName := make(map[string]*route.Route, len(routes))
	for _, r := range routes {
		byName[r.Name] = r
	}
	for ai, api := range apis {
		for ri, r := range api.Routes {
			if r.Processing == nil || r.Processing.ExtProc == nil {
				continue
			}
			p := r.Processing.ExtProc
			generated := byName[apiRouteName(ai, api.Name, ri)]
			config, err := packEnvoy(&extproc.ExtProcPerRoute{Override: &extproc.ExtProcPerRoute_Overrides{Overrides: &extproc.ExtProcOverrides{ProcessingMode: extProcProcessingMode(*p)}}})
			if err != nil {
				return err
			}
			if generated.TypedPerFilterConfig == nil {
				generated.TypedPerFilterConfig = make(map[string]*anypb.Any)
			}
			generated.TypedPerFilterConfig[extProcFilterName(p.Service)] = config
			if p.RequestBodyBufferLimitBytes != nil {
				generated.RequestBodyBufferLimit = wrapperspb.UInt64(*p.RequestBodyBufferLimitBytes)
			}
			bridge, err := extProcAttributeBridgePerRouteConfig(api.Attributes)
			if err != nil {
				return err
			}
			generated.TypedPerFilterConfig[extProcAttributeBridgeName] = bridge
		}
	}
	return nil
}

func addExtProcAccessRouteConfig(c resolvedConfig, generated *route.Route, api gatewayapi.API, access resolvedAccess) error {
	if generated.TypedPerFilterConfig[extProcAttributeBridgeName] == nil {
		return nil
	}
	attributes := slices.Clone(api.Attributes)
	for _, a := range access.authenticators {
		attributes = append(attributes, a.Attributes...)
	}
	if external := access.Authorization.ExtAuthz; external != nil {
		attributes = append(attributes, c.extAuthzIndex[external.Service].Attributes...)
	}
	bridge, err := extProcAttributeBridgePerRouteConfig(attributes)
	if err != nil {
		return err
	}
	generated.TypedPerFilterConfig[extProcAttributeBridgeName] = bridge
	return nil
}

func extProcAttributeBridgePerRouteConfig(attributes []gatewayapi.AttributeSource) (*anypb.Any, error) {
	unique := make(map[string]gatewayapi.AttributeSource, len(attributes))
	for _, a := range attributes {
		unique[a.Name] = a
	}
	sources := make([]gatewayapi.AttributeSource, 0, len(unique))
	for _, a := range unique {
		sources = append(sources, a)
	}
	return extAuthzAttributeBridgePerRouteConfig(sources, nil)
}
