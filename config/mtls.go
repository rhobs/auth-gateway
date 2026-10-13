package config

import (
	"path"
	"strconv"

	accesslog "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	mutationrules "github.com/envoyproxy/go-control-plane/envoy/config/common/mutation_rules/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	rbac "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	headermutation "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/header_mutation/v3"
	headertometadata "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/header_to_metadata/v3"
	httpRBAC "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rbac/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	mtlsauthenticated "github.com/envoyproxy/go-control-plane/envoy/extensions/rbac/principals/mtls_authenticated/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	mtlsPeerHeadersFilterName      = "auth_gateway.mtls.peer_headers"
	mtlsSANCardinalityFilterName   = "auth_gateway.mtls.san_cardinality"
	mtlsSharedAttributesFilterName = "auth_gateway.mtls.shared_attributes"
	mtlsPendingCleanupFilterName   = "auth_gateway.mtls.authentication_complete"
	mtlsPrincipalName              = "envoy.rbac.principals.mtls_authenticated"
	mtlsMetadataNamespace          = "auth_gateway.mtls"
	mtlsFingerprintMetadataKey     = "fingerprint"
	mtlsURIMetadataKey             = "uri_san"
	mtlsDNSMetadataKey             = "dns_san"
	mtlsFingerprintHeaderName      = "x-auth-gateway-mtls-fingerprint"
	mtlsURIHeaderName              = "x-auth-gateway-mtls-uri-san"
	mtlsDNSHeaderName              = "x-auth-gateway-mtls-dns-san"
	mtlsPendingHeaderName          = "x-auth-gateway-mtls-authentication-pending"
	// Request-control and peer filters remove client values and overwrite this
	// header from TLS state. Keep the matcher below Envoy's RE2 size limit.
	mtlsFingerprintPattern = "^[0-9A-Fa-f:]+$"
)

func (c Config) serverMTLSAuthenticator(server Server) (Authenticator, bool) {
	for _, name := range selectedAuthenticatorNames(server) {
		if authenticator := findAuthenticator(c, name); authenticator.MTLS != nil {
			return authenticator, true
		}
	}
	return Authenticator{}, false
}

func serverUsesMTLS(c Config, server Server) bool {
	_, selected := c.serverMTLSAuthenticator(server)
	return selected
}

func requiresClientCertificate(server Server) bool {
	return server.Authentication.AllOf != nil || len(server.Authentication.AnyOf) == 1
}

func clientCASecretName(index int) string {
	return "gateway_client_ca_" + strconv.Itoa(index)
}

func clientCAResourceFilename(index int) string {
	return "client-ca-" + strconv.Itoa(index) + ".yaml"
}

func (m MTLSAuthenticator) toEnvoySecret(index int) *tls.Secret {
	filename := m.TrustedCA.filename()
	return &tls.Secret{
		Name: clientCASecretName(index),
		Type: &tls.Secret_ValidationContext{ValidationContext: &tls.CertificateValidationContext{
			TrustedCa:        fileDataSource(filename),
			WatchedDirectory: &core.WatchedDirectory{Path: path.Dir(filename)},
		}},
	}
}

func mtlsPeerHeadersFilter() (*hcm.HttpFilter, error) {
	values := []struct{ name, format string }{
		{mtlsPendingHeaderName, "true"},
		{mtlsFingerprintHeaderName, "%DOWNSTREAM_PEER_FINGERPRINT_256%"},
		{mtlsURIHeaderName, "%DOWNSTREAM_PEER_URI_SAN%"},
		{mtlsDNSHeaderName, "%DOWNSTREAM_PEER_DNS_SAN%"},
	}
	mutations := make([]*mutationrules.HeaderMutation, 0, len(values))
	for _, value := range values {
		mutations = append(mutations, &mutationrules.HeaderMutation{Action: &mutationrules.HeaderMutation_Append{Append: &core.HeaderValueOption{
			Header:       &core.HeaderValue{Key: value.name, Value: value.format},
			AppendAction: core.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		}}})
	}
	packed, err := packEnvoy(&headermutation.HeaderMutation{Mutations: &headermutation.Mutations{RequestMutations: mutations}})
	if err != nil {
		return nil, err
	}
	return &hcm.HttpFilter{Name: mtlsPeerHeadersFilterName, ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: packed}}, nil
}

func mtlsPeerMetadataRules() []*headertometadata.Config_Rule {
	values := []struct{ header, key string }{
		{mtlsFingerprintHeaderName, mtlsFingerprintMetadataKey},
		{mtlsURIHeaderName, mtlsURIMetadataKey},
		{mtlsDNSHeaderName, mtlsDNSMetadataKey},
	}
	rules := make([]*headertometadata.Config_Rule, 0, len(values))
	for _, value := range values {
		rules = append(rules, &headertometadata.Config_Rule{
			Header: value.header,
			OnHeaderPresent: &headertometadata.Config_KeyValuePair{
				MetadataNamespace: mtlsMetadataNamespace, Key: value.key,
			},
		})
	}
	return rules
}

func mtlsHeaderPrincipal(name, value string) *rbac.Principal {
	return &rbac.Principal{Identifier: &rbac.Principal_Header{Header: &route.HeaderMatcher{
		Name: name,
		HeaderMatchSpecifier: &route.HeaderMatcher_StringMatch{StringMatch: &matcher.StringMatcher{
			MatchPattern: &matcher.StringMatcher_Exact{Exact: value}, IgnoreCase: true,
		}},
	}}}
}

func mtlsPresentPrincipal() *rbac.Principal {
	return &rbac.Principal{Identifier: &rbac.Principal_Header{Header: &route.HeaderMatcher{
		Name: mtlsFingerprintHeaderName,
		HeaderMatchSpecifier: &route.HeaderMatcher_StringMatch{StringMatch: &matcher.StringMatcher{
			MatchPattern: &matcher.StringMatcher_SafeRegex{SafeRegex: &matcher.RegexMatcher{Regex: mtlsFingerprintPattern}},
		}},
	}}}
}

func mtlsValidatedPrincipal() (*rbac.Principal, error) {
	packed, err := packEnvoy(&mtlsauthenticated.Config{AnyValidatedClientCertificate: true})
	if err != nil {
		return nil, err
	}
	return &rbac.Principal{Identifier: &rbac.Principal_Custom{Custom: &core.TypedExtensionConfig{
		Name: mtlsPrincipalName, TypedConfig: packed,
	}}}, nil
}

func mtlsSANCardinalityFilter() (*hcm.HttpFilter, error) {
	principals := make([]*rbac.Principal, 0, 2)
	for _, name := range []string{mtlsURIHeaderName, mtlsDNSHeaderName} {
		principals = append(principals, &rbac.Principal{Identifier: &rbac.Principal_Header{Header: &route.HeaderMatcher{
			Name: name,
			HeaderMatchSpecifier: &route.HeaderMatcher_StringMatch{StringMatch: &matcher.StringMatcher{
				MatchPattern: &matcher.StringMatcher_SafeRegex{SafeRegex: &matcher.RegexMatcher{Regex: ".*,.*"}},
			}},
		}}})
	}
	rules := &rbac.RBAC{Action: rbac.RBAC_DENY, Policies: map[string]*rbac.Policy{
		"multiple-san": {
			Permissions: []*rbac.Permission{{Rule: &rbac.Permission_Any{Any: true}}},
			Principals:  []*rbac.Principal{{Identifier: &rbac.Principal_OrIds{OrIds: &rbac.Principal_Set{Ids: principals}}}},
		},
	}}
	packed, err := packEnvoy(&httpRBAC.RBAC{Rules: rules})
	if err != nil {
		return nil, err
	}
	return &hcm.HttpFilter{Name: mtlsSANCardinalityFilterName, ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: packed}}, nil
}

func mtlsPendingCleanupFilter() (*hcm.HttpFilter, error) {
	// A denial before this filter is an authentication failure; successful
	// authentication reaches it before authorization runs.
	packed, err := packEnvoy(&headermutation.HeaderMutation{Mutations: &headermutation.Mutations{RequestMutations: []*mutationrules.HeaderMutation{{
		Action: &mutationrules.HeaderMutation_Remove{Remove: mtlsPendingHeaderName},
	}}}})
	if err != nil {
		return nil, err
	}
	return &hcm.HttpFilter{Name: mtlsPendingCleanupFilterName, ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: packed}}, nil
}

func mtlsMissingCredentialReply() *hcm.LocalReplyConfig {
	status := &accesslog.AccessLogFilter{FilterSpecifier: &accesslog.AccessLogFilter_StatusCodeFilter{StatusCodeFilter: &accesslog.StatusCodeFilter{
		Comparison: &accesslog.ComparisonFilter{Op: accesslog.ComparisonFilter_EQ, Value: &core.RuntimeUInt32{DefaultValue: 403}},
	}}}
	pending := &accesslog.AccessLogFilter{FilterSpecifier: &accesslog.AccessLogFilter_HeaderFilter{HeaderFilter: &accesslog.HeaderFilter{
		Header: mtlsHeaderPrincipal(mtlsPendingHeaderName, "true").GetHeader(),
	}}}
	return &hcm.LocalReplyConfig{Mappers: []*hcm.ResponseMapper{{
		Filter: &accesslog.AccessLogFilter{FilterSpecifier: &accesslog.AccessLogFilter_AndFilter{AndFilter: &accesslog.AndFilter{Filters: []*accesslog.AccessLogFilter{
			status,
			pending,
		}}}},
		StatusCode: wrapperspb.UInt32(401),
	}}}
}
