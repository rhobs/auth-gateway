package envoy

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	setfilterstatecommon "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/common/set_filter_state/v3"
	setfilterstate "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	configuration "github.com/rhobs/auth-gateway/pkg/config"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	jwtMetadataExpressionPrefix = `metadata.filter_metadata["envoy.filters.http.jwt_authn"]`
	selectedAuthenticatorKey    = "auth_gateway.authenticator"
	attributeFilterName         = "envoy.filters.http.set_filter_state"
	managedAttributePrefix      = "auth_gateway.attributes."
)

func attributeInitializationFilterName(index int) string {
	return "auth_gateway.attributes.server-" + strconv.Itoa(index)
}

func jwtClaimExpression(claimPath []string) string {
	current := jwtMetadataExpressionPrefix
	checks := make([]string, 0, len(claimPath))
	for _, key := range claimPath {
		literal := celStringLiteral(key)
		checks = append(checks, literal+" in "+current)
		current += "[" + literal + "]"
	}
	return "((" + strings.Join(checks, celAndSeparator) + ") && type(" + current + ") == string && " + current + " != \"\") ? " + current + " : \"\""
}

func headerAttributeExpression(authenticator gatewayapi.Authenticator, header string) string {
	verified := authenticatorVerifiedExpression(authenticator)
	current, checks := metadataStringPathExpression(configuration.RequestHeaderMetadataNamespace, []string{strings.ToLower(header)})
	return "((" + verified + " && " + checks + " && " + current + " != \"\") ? " + current + " : \"\")"
}

func authenticatorVerifiedExpression(authenticator gatewayapi.Authenticator) string {
	if authenticator.JWT != nil {
		current, checks := metadataStringPathExpression(configuration.JwtAuthnFilterName, []string{authenticator.Name, configuration.JwtIssuerClaimName})
		return checks + " && " + current + " == " + celStringLiteral(authenticator.JWT.Issuer)
	}
	if authenticator.MTLS != nil {
		return mtlsPresentExpression()
	}
	current, checks := metadataStringPathExpression(configuration.ApiKeyMetadataNamespace, []string{configuration.ApiKeyMetadataKey})
	return checks + " && " + current + " != \"\""
}

func mtlsPresentExpression() string {
	current, checks := metadataStringPathExpression(configuration.MtlsMetadataNamespace, []string{configuration.MtlsFingerprintMetadataKey})
	return checks + " && size(" + current + ") >= 64"
}

func mtlsSANAttributeExpression(source gatewayapi.AttributeSource) string {
	key := configuration.MtlsDNSMetadataKey
	if source.URISAN != nil {
		key = configuration.MtlsURIMetadataKey
	}
	current, checks := metadataStringPathExpression(configuration.MtlsMetadataNamespace, []string{key})
	return "((" + mtlsPresentExpression() + " && " + checks + " && " + current + " != \"\") ? " + current + " : \"\")"
}

func metadataStringPathExpression(namespace string, path []string) (string, string) {
	current := "metadata.filter_metadata"
	keys := append([]string{namespace}, path...)
	checks := make([]string, 0, len(keys)+1)
	for _, key := range keys {
		literal := celStringLiteral(key)
		checks = append(checks, literal+" in "+current)
		current += "[" + literal + "]"
	}
	checks = append(checks, "type("+current+") == string")
	return current, strings.Join(checks, celAndSeparator)
}

func apiKeyAttributeExpression(attribute string) string {
	namespace := `metadata.filter_metadata["` + configuration.ApiKeyMetadataNamespace + `"]`
	key := celStringLiteral(configuration.ApiKeyAttributeMetadataKey(attribute))
	current := namespace + "[" + key + "]"
	return "((\"" + configuration.ApiKeyMetadataNamespace + "\" in metadata.filter_metadata" + celAndSeparator + key + " in " + namespace + ") && type(" + current + ") == string && " + current + " != \"\") ? " + current + " : \"\""
}

func needsWorkingAttributes(c configuration.ResolvedConfig) bool {
	return configuration.HasRequestHeaderProcessing(c.APIs) || configuration.HasRequestMetricLabels(c.APIs) || configuration.HasFaultMatchAttributes(c.APIs)
}

func filterStateKey(attribute string) string {
	return managedAttributePrefix + attribute
}

func toServerAttributeInitializationConfig(c configuration.ResolvedConfig, server configuration.ResolvedServer) *setfilterstate.Config {
	config := &setfilterstate.Config{}
	selectIdentity := server.MixedAnyOf()
	authenticators := slices.Clone(server.Authenticators)
	if selectIdentity || server.UsesMTLS() {
		slices.SortStableFunc(authenticators, func(a, b gatewayapi.Authenticator) int {
			return configuration.AuthenticatorPriority(a) - configuration.AuthenticatorPriority(b)
		})
	}
	if selectIdentity {
		// Finish identity selection before any identity can supply attributes.
		for _, authenticator := range authenticators {
			expression := "((" + authenticatorVerifiedExpression(authenticator) + ") ? " + celStringLiteral(authenticator.Name) + " : \"\")"
			config.OnRequestHeaders = append(config.OnRequestHeaders, filterStateValue(selectedAuthenticatorKey, expression))
		}
	}
	for _, authenticator := range authenticators {
		appendAttributeInitialization(config, authenticator, selectIdentity)
	}
	return config
}

func appendAttributeInitialization(config *setfilterstate.Config, authenticator gatewayapi.Authenticator, selectIdentity bool) {
	for _, attribute := range slices.Sorted(maps.Keys(authenticator.Attributes)) {
		source := authenticator.Attributes[attribute]
		var expression string
		switch {
		case source.Header != nil:
			expression = headerAttributeExpression(authenticator, *source.Header)
		case authenticator.JWT != nil:
			expression = jwtClaimExpression(append([]string{authenticator.Name}, source.ClaimPath...))
		case authenticator.MTLS != nil:
			expression = mtlsSANAttributeExpression(source)
		default:
			expression = apiKeyAttributeExpression(attribute)
		}
		if selectIdentity {
			key := celStringLiteral(selectedAuthenticatorKey)
			expression = "(" + key + " in filter_state && filter_state[" + key + "] == " + celBytesLiteral(authenticator.Name) + ") ? (" + expression + ") : \"\""
		}
		config.OnRequestHeaders = append(config.OnRequestHeaders, filterStateValue(filterStateKey(attribute), expression))
	}
}

func toAttributeInitializationConfig(c configuration.ResolvedConfig) *setfilterstate.Config {
	config := &setfilterstate.Config{}
	for _, authenticator := range c.Authenticators {
		if !c.AuthenticatorUsed(authenticator.Name) || authenticator.JWT == nil {
			continue
		}
		appendAttributeInitialization(config, authenticator, false)
	}
	return config
}

func filterStateValue(key, expression string) *setfilterstatecommon.FilterStateValue {
	return &setfilterstatecommon.FilterStateValue{
		Key:        &setfilterstatecommon.FilterStateValue_ObjectKey{ObjectKey: key},
		FactoryKey: "envoy.string",
		Value: &setfilterstatecommon.FilterStateValue_FormatString{FormatString: &core.SubstitutionFormatString{
			Format: &core.SubstitutionFormatString_TextFormatSource{TextFormatSource: &core.DataSource{
				Specifier: &core.DataSource_InlineString{InlineString: "%CEL(" + expression + ")%"},
			}},
			OmitEmptyValues: true,
		}},
		SkipIfEmpty: true,
	}
}

func attributeHTTPFilters(c configuration.ResolvedConfig, filters []*hcm.HttpFilter, hosts []indexedVirtualHost) ([]*hcm.HttpFilter, error) {
	if c.UsesAPIKeys() || c.UsesMTLS() {
		return apiKeyAttributeFilters(c, filters, hosts)
	}
	attributeConfig, err := packEnvoy(toAttributeInitializationConfig(c))
	if err != nil {
		return nil, fmt.Errorf("encode attribute initialization filter: %w", err)
	}
	return append(filters, &hcm.HttpFilter{Name: attributeFilterName, ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: attributeConfig}}), nil
}

func apiKeyAttributeFilters(c configuration.ResolvedConfig, filters []*hcm.HttpFilter, hosts []indexedVirtualHost) ([]*hcm.HttpFilter, error) {
	for _, indexedHost := range hosts {
		serverIndex := indexedHost.serverIndex
		attributes := toServerAttributeInitializationConfig(c, c.ResolvedServers[serverIndex])
		if len(attributes.OnRequestHeaders) == 0 {
			continue
		}
		packed, err := packEnvoy(attributes)
		if err != nil {
			return nil, fmt.Errorf("servers[%d] attribute initialization: %w", serverIndex, err)
		}
		name := attributeInitializationFilterName(serverIndex)
		filters = append(filters, &hcm.HttpFilter{Name: name, Disabled: true, ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: packed}})
		enableConfig, err := packEnvoy(&setfilterstate.Config{})
		if err != nil {
			return nil, fmt.Errorf("servers[%d] enable attributes: %w", serverIndex, err)
		}
		enabled, err := packEnvoy(&route.FilterConfig{Config: enableConfig})
		if err != nil {
			return nil, fmt.Errorf("servers[%d] enable attributes: %w", serverIndex, err)
		}
		if indexedHost.host == nil {
			return nil, fmt.Errorf("servers[%d] enable attributes: virtual host is nil", serverIndex)
		}
		if indexedHost.host.TypedPerFilterConfig == nil {
			indexedHost.host.TypedPerFilterConfig = make(map[string]*anypb.Any)
		}
		indexedHost.host.TypedPerFilterConfig[name] = enabled
	}
	return filters, nil
}
