package gateway

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	setfilterstatecommon "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/common/set_filter_state/v3"
	headertometadata "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/header_to_metadata/v3"
	setfilterstate "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	attributeNameValidationErrorFormat = "%s.attributes contains invalid attribute name %q"
	// Envoy's header_to_metadata filter rejects values of 8 KiB or more.
	apiKeyMaxAttributeBytes     = 8*1024 - 1
	headerToMetadataFilterName  = "envoy.filters.http.header_to_metadata"
	jwtMetadataExpressionPrefix = `metadata.filter_metadata["envoy.filters.http.jwt_authn"]`
	attributeFilterName         = "envoy.filters.http.set_filter_state"
	managedAttributePrefix      = "auth_gateway.attributes."
)

var (
	attributeNamePattern = regexp.MustCompile("^[a-z][a-z0-9_-]{0,63}$")
)

func validateAuthenticatorAttributes(name string, authenticator gatewayapi.Authenticator, apiKeyHeader string) error {
	for _, attribute := range slices.Sorted(maps.Keys(authenticator.Attributes)) {
		if !attributeNamePattern.MatchString(attribute) {
			return fmt.Errorf(attributeNameValidationErrorFormat, name, attribute)
		}
		source := authenticator.Attributes[attribute]
		field := name + ".attributes." + attribute
		if authenticator.JWT != nil {
			if source.Credential != nil || source.URISAN != nil || source.DNSSAN != nil || (source.ClaimPath == nil) == (source.Header == nil) {
				return fmt.Errorf("%s must set exactly one of claim_path or header", field)
			}
		} else if authenticator.APIKey != nil {
			if source.ClaimPath != nil || source.URISAN != nil || source.DNSSAN != nil || (source.Credential == nil) == (source.Header == nil) {
				return fmt.Errorf("%s must set exactly one of credential: true or header", field)
			}
		} else {
			sources := 0
			for _, present := range []bool{source.Header != nil, source.URISAN != nil, source.DNSSAN != nil} {
				if present {
					sources++
				}
			}
			if source.ClaimPath != nil || source.Credential != nil || sources != 1 {
				return fmt.Errorf("%s must set exactly one of uri_san: true, dns_san: true, or header", field)
			}
		}
		if source.ClaimPath != nil {
			if len(source.ClaimPath) == 0 {
				return fmt.Errorf("%s.claim_path must contain at least one literal object key", field)
			}
			if slices.Contains(source.ClaimPath, "") {
				return fmt.Errorf("%s.claim_path keys must not be empty", field)
			}
		}
		if source.Credential != nil && !*source.Credential {
			return fmt.Errorf("%s.credential must be true", field)
		}
		if source.URISAN != nil && !*source.URISAN {
			return fmt.Errorf("%s.uri_san must be true", field)
		}
		if source.DNSSAN != nil && !*source.DNSSAN {
			return fmt.Errorf("%s.dns_san must be true", field)
		}
		if source.Header != nil {
			header := *source.Header
			lower := strings.ToLower(header)
			if !validHeaderFieldName(header) || strings.Contains(header, "_") || forbiddenIdentityHeader(lower) {
				return fmt.Errorf("%s.header must be a safe HTTP request header name", field)
			}
			if strings.EqualFold(header, apiKeyHeader) {
				return fmt.Errorf("%s.header is reserved for API-key credentials", field)
			}
		}
	}
	return nil
}

func attributeMetadataPath(authenticator gatewayapi.Authenticator, attribute string) (string, []string) {
	source := authenticator.Attributes[attribute]
	if source.Header != nil {
		return requestHeaderMetadataNamespace, []string{strings.ToLower(*source.Header)}
	}
	if authenticator.JWT != nil {
		return jwtAuthnFilterName, append([]string{authenticator.Name}, source.ClaimPath...)
	}
	if authenticator.MTLS != nil {
		if source.URISAN != nil {
			return mtlsMetadataNamespace, []string{mtlsURIMetadataKey}
		}
		return mtlsMetadataNamespace, []string{mtlsDNSMetadataKey}
	}
	return apiKeyMetadataNamespace, []string{apiKeyAttributeMetadataKey(attribute)}
}

func cloneAttributeSource(a gatewayapi.AttributeSource) gatewayapi.AttributeSource {
	a.ClaimPath = slices.Clone(a.ClaimPath)
	a.Header = clonePointer(a.Header)
	a.Credential = clonePointer(a.Credential)
	a.URISAN = clonePointer(a.URISAN)
	a.DNSSAN = clonePointer(a.DNSSAN)
	return a
}

func validateAuthenticatorAttributesConfig(c gatewayapi.Config, apiKeyHeader string) error {
	for i, authenticator := range c.Authenticators {
		if err := validateAuthenticatorAttributes(fmt.Sprintf(authenticatorFieldPathFormat, i), authenticator, apiKeyHeader); err != nil {
			return err
		}
	}
	return nil
}

func requestMetadataFilter(authenticator gatewayapi.Authenticator, headers []string, includeMTLS bool) (*hcm.HttpFilter, error) {
	var rules []*headertometadata.Config_Rule
	if authenticator.APIKey != nil {
		attributeNames := credentialAttributeNamesAuthenticator(authenticator)
		rules = append(rules, &headertometadata.Config_Rule{
			Header: apiKeyClientHeader, Remove: len(attributeNames) == 0,
			OnHeaderPresent: &headertometadata.Config_KeyValuePair{
				MetadataNamespace: apiKeyMetadataNamespace, Key: apiKeyMetadataKey,
				Value: apiKeyVerifiedIdentity,
			},
		})
		for index, attribute := range attributeNames {
			rules = append(rules, &headertometadata.Config_Rule{
				Header: apiKeyClientHeader, Remove: index == len(attributeNames)-1,
				OnHeaderPresent: &headertometadata.Config_KeyValuePair{
					MetadataNamespace: apiKeyMetadataNamespace,
					Key:               apiKeyAttributeMetadataKey(attribute),
					RegexValueRewrite: &matcher.RegexMatchAndSubstitute{
						Pattern:      &matcher.RegexMatcher{Regex: apiKeyAttributePattern(attribute)},
						Substitution: `\1`,
					},
				},
			})
		}
	}
	if includeMTLS {
		rules = append(rules, mtlsPeerMetadataRules()...)
	}
	for _, header := range headers {
		rules = append(rules, &headertometadata.Config_Rule{
			Header: header,
			OnHeaderPresent: &headertometadata.Config_KeyValuePair{
				MetadataNamespace: requestHeaderMetadataNamespace,
				Key:               header,
			},
		})
	}
	config, err := packEnvoy(&headertometadata.Config{RequestRules: rules})
	if err != nil {
		return nil, err
	}
	return &hcm.HttpFilter{Name: headerToMetadataFilterName, ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: config}}, nil
}

func requestHeaderSources(c resolvedConfig, serverIndexes []int) []string {
	headers := make(map[string]struct{})
	for _, index := range serverIndexes {
		for _, authenticator := range c.servers[index].authenticators {
			for _, source := range authenticator.Attributes {
				if source.Header != nil {
					headers[strings.ToLower(*source.Header)] = struct{}{}
				}
			}
		}
	}
	return slices.Sorted(maps.Keys(headers))
}

func apiKeyAttributePattern(attribute string) string {
	// The fallback leaves an absent field's capture empty.
	return `^(?:(?:[^;]*;)*` + regexp.QuoteMeta(attribute) + `=([^;]*)(?:;[^;]*)*|.*)$`
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
	current, checks := metadataStringPathExpression(requestHeaderMetadataNamespace, []string{strings.ToLower(header)})
	return "((" + verified + " && " + checks + " && " + current + " != \"\") ? " + current + " : \"\")"
}

func authenticatorVerifiedExpression(authenticator gatewayapi.Authenticator) string {
	if authenticator.JWT != nil {
		current, checks := metadataStringPathExpression(jwtAuthnFilterName, []string{authenticator.Name, jwtIssuerClaimName})
		return checks + " && " + current + " == " + celStringLiteral(authenticator.JWT.Issuer)
	}
	if authenticator.MTLS != nil {
		return mtlsPresentExpression()
	}
	current, checks := metadataStringPathExpression(apiKeyMetadataNamespace, []string{apiKeyMetadataKey})
	return checks + " && " + current + " != \"\""
}

func mtlsPresentExpression() string {
	current, checks := metadataStringPathExpression(mtlsMetadataNamespace, []string{mtlsFingerprintMetadataKey})
	return checks + " && size(" + current + ") >= 64"
}

func mtlsSANAttributeExpression(source gatewayapi.AttributeSource) string {
	key := mtlsDNSMetadataKey
	if source.URISAN != nil {
		key = mtlsURIMetadataKey
	}
	current, checks := metadataStringPathExpression(mtlsMetadataNamespace, []string{key})
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
	namespace := `metadata.filter_metadata["` + apiKeyMetadataNamespace + `"]`
	key := celStringLiteral(apiKeyAttributeMetadataKey(attribute))
	current := namespace + "[" + key + "]"
	return "((\"" + apiKeyMetadataNamespace + "\" in metadata.filter_metadata" + celAndSeparator + key + " in " + namespace + ") && type(" + current + ") == string && " + current + " != \"\") ? " + current + " : \"\""
}

func needsWorkingAttributes(c resolvedConfig) bool {
	return hasRequestHeaderProcessing(c.APIs) || hasRequestMetricLabels(c.APIs) || hasFaultMatchAttributes(c.APIs)
}

func filterStateKey(attribute string) string {
	return managedAttributePrefix + attribute
}

func appendAttributeInitialization(config *setfilterstate.Config, authenticator gatewayapi.Authenticator) {
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

		config.OnRequestHeaders = append(config.OnRequestHeaders, filterStateValue(filterStateKey(attribute), expression))
	}
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

func attributeHTTPFilter() (*hcm.HttpFilter, error) {
	packed, err := packEnvoy(&setfilterstate.Config{})
	if err != nil {
		return nil, err
	}
	return &hcm.HttpFilter{Name: attributeFilterName, Disabled: true, ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: packed}}, nil
}

func attributePerRouteConfig(access resolvedAccess) (*anypb.Any, error) {
	config := &setfilterstate.Config{}
	for _, authenticator := range access.authenticators {
		appendAttributeInitialization(config, authenticator)
	}
	packed, err := packEnvoy(config)
	if err != nil {
		return nil, err
	}
	return packEnvoy(&route.FilterConfig{Config: packed})
}
