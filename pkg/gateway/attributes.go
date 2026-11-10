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
	// Envoy's header_to_metadata filter rejects values of 8 KiB or more.
	apiKeyMaxAttributeBytes     = 8*1024 - 1
	headerToMetadataFilterName  = "envoy.filters.http.header_to_metadata"
	jwtMetadataExpressionPrefix = `metadata.filter_metadata["envoy.filters.http.jwt_authn"]`
	attributeFilterName         = "envoy.filters.http.set_filter_state"
	managedAttributePrefix      = "auth_gateway.attributes."
	attributeSourceHeader       = "header"
)

var (
	attributeNamePattern = regexp.MustCompile("^[a-z][a-z0-9_-]{0,63}$")
)

func validateAuthenticatorAttributes(name string, authenticator gatewayapi.Authenticator, apiKeyHeader string) error {
	seen := make(map[string]bool)
	for i, source := range authenticator.Attributes {
		field := fmt.Sprintf("%s.attributes[%d]", name, i)
		if !attributeNamePattern.MatchString(source.Name) {
			return fmt.Errorf("%s.name must be a valid attribute name", field)
		}
		if seen[source.Name] {
			return fmt.Errorf("%s.name duplicates attribute %q", field, source.Name)
		}
		seen[source.Name] = true
		switch source.FromSource {
		case "claim":
			if authenticator.JWT == nil || !source.Value.IsPath || len(source.Value.Path) == 0 || slices.Contains(source.Value.Path, "") {
				return fmt.Errorf("%s.value must contain one or more nonempty JWT claim keys", field)
			}
		case "credential":
			if authenticator.APIKey == nil || source.Value.IsPath || !attributeNamePattern.MatchString(source.Value.Text) {
				return fmt.Errorf("%s.value must name an API-key credential attribute", field)
			}
		case "certificate":
			if authenticator.MTLS == nil || source.Value.IsPath || (source.Value.Text != "uri_san" && source.Value.Text != "dns_san") {
				return fmt.Errorf("%s.value must be uri_san or dns_san for mTLS", field)
			}
		case attributeSourceHeader:
			if source.Value.IsPath {
				return fmt.Errorf("%s.value must be a request header name", field)
			}
			header := source.Value.Text
			lower := strings.ToLower(header)
			if !validHeaderFieldName(header) || strings.Contains(header, "_") || forbiddenIdentityHeader(lower) {
				return fmt.Errorf("%s.value must be a safe HTTP request header name", field)
			}
			if strings.EqualFold(header, apiKeyHeader) {
				return fmt.Errorf("%s.value is reserved for API-key credentials", field)
			}
		default:
			return fmt.Errorf("%s.from_source must be claim, credential, certificate, or header", field)
		}
	}
	return nil
}

func authenticatorAttribute(authenticator gatewayapi.Authenticator, name string) (gatewayapi.AttributeSource, bool) {
	for _, source := range authenticator.Attributes {
		if source.Name == name {
			return source, true
		}
	}
	return gatewayapi.AttributeSource{}, false
}

func attributeMetadataPath(authenticator gatewayapi.Authenticator, attribute string) (string, []string) {
	source, _ := authenticatorAttribute(authenticator, attribute)
	if source.FromSource == attributeSourceHeader {
		return requestHeaderMetadataNamespace, []string{strings.ToLower(source.Value.Text)}
	}
	if authenticator.JWT != nil {
		return jwtAuthnFilterName, append([]string{authenticator.Name}, source.Value.Path...)
	}
	if authenticator.MTLS != nil {
		if source.Value.Text == "uri_san" {
			return mtlsMetadataNamespace, []string{mtlsURIMetadataKey}
		}
		return mtlsMetadataNamespace, []string{mtlsDNSMetadataKey}
	}
	return apiKeyMetadataNamespace, []string{apiKeyAttributeMetadataKey(source.Value.Text)}
}

func cloneAttributeSource(a gatewayapi.AttributeSource) gatewayapi.AttributeSource {
	a.Value.Path = slices.Clone(a.Value.Path)
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
				if source.FromSource == attributeSourceHeader {
					headers[strings.ToLower(source.Value.Text)] = struct{}{}
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
	if source.Value.Text == "uri_san" {
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
	attributes := slices.Clone(authenticator.Attributes)
	slices.SortFunc(attributes, func(a, b gatewayapi.AttributeSource) int { return strings.Compare(a.Name, b.Name) })
	for _, source := range attributes {
		attribute := source.Name
		var expression string
		switch {
		case source.FromSource == attributeSourceHeader:
			expression = headerAttributeExpression(authenticator, source.Value.Text)
		case authenticator.JWT != nil:
			expression = jwtClaimExpression(append([]string{authenticator.Name}, source.Value.Path...))
		case authenticator.MTLS != nil:
			expression = mtlsSANAttributeExpression(source)
		default:
			expression = apiKeyAttributeExpression(source.Value.Text)
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
