package config

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	rbac "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	setfilterstatecommon "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/common/set_filter_state/v3"
	setfilterstate "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"
	expr "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

const (
	jwtMetadataExpressionPrefix = `metadata.filter_metadata["envoy.filters.http.jwt_authn"]`
	celAndSeparator             = " && "
)

func (c Config) toServerAttributeInitializationConfig(server Server) *setfilterstate.Config {
	config := &setfilterstate.Config{}
	for _, name := range selectedAuthenticatorNames(server) {
		authenticator := findAuthenticator(c, name)
		for _, attribute := range slices.Sorted(maps.Keys(authenticator.Attributes)) {
			source := authenticator.Attributes[attribute]
			var expression string
			switch {
			case source.Header != nil:
				expression = headerAttributeExpression(authenticator, *source.Header)
			case authenticator.JWT != nil:
				expression = jwtClaimExpression(append([]string{name}, source.ClaimPath...))
			default:
				expression = apiKeyAttributeExpression(attribute)
			}
			config.OnRequestHeaders = append(config.OnRequestHeaders, filterStateValue(filterStateKey(attribute), expression))
		}
	}
	return config
}

func (c Config) toAttributeInitializationConfig() *setfilterstate.Config {
	config := &setfilterstate.Config{}
	for _, authenticator := range c.Authenticators {
		if !authenticatorUsed(c.Servers, authenticator.Name) || authenticator.JWT == nil {
			continue
		}
		for _, attribute := range slices.Sorted(maps.Keys(authenticator.Attributes)) {
			source := authenticator.Attributes[attribute]
			var expression string
			if source.Header != nil {
				expression = headerAttributeExpression(authenticator, *source.Header)
			} else {
				claimPath := append([]string{authenticator.Name}, source.ClaimPath...)
				expression = jwtClaimExpression(claimPath)
			}
			config.OnRequestHeaders = append(config.OnRequestHeaders, filterStateValue(filterStateKey(attribute), expression))
		}
	}
	return config
}

func (c Config) toAttributeProcessingConfig() *setfilterstate.Config {
	config := &setfilterstate.Config{}
	if !c.usesAPIKeys() {
		config = c.toAttributeInitializationConfig()
	}
	if c.hasAttributeMappings() {
		config.OnRequestHeaders = append(config.OnRequestHeaders, c.toProcessingMappingConfig().OnRequestHeaders...)
	}
	return config
}

func (c Config) toProcessingECDSResource() (*core.TypedExtensionConfig, error) {
	filterConfig, err := packEnvoy(c.toAttributeProcessingConfig())
	if err != nil {
		return nil, fmt.Errorf("encode set_filter_state config: %w", err)
	}
	return &core.TypedExtensionConfig{Name: attributeFilterName, TypedConfig: filterConfig}, nil
}

func (c Config) toProcessingMappingConfig() *setfilterstate.Config {
	config := &setfilterstate.Config{}
	for _, processor := range c.Processing {
		for _, attribute := range slices.Sorted(maps.Keys(processor.Attributes)) {
			mappings := processor.Attributes[attribute].Mappings
			if len(mappings) == 0 {
				continue
			}
			config.OnRequestHeaders = append(config.OnRequestHeaders, filterStateValue(filterStateKey(attribute), attributeMappingExpression(attribute, mappings)))
		}
	}
	return config
}

func filterStateValue(key, expression string) *setfilterstatecommon.FilterStateValue {
	return &setfilterstatecommon.FilterStateValue{
		Key:        &setfilterstatecommon.FilterStateValue_ObjectKey{ObjectKey: key},
		FactoryKey: "envoy.string",
		Value: &setfilterstatecommon.FilterStateValue_FormatString{FormatString: &core.SubstitutionFormatString{
			Format:          &core.SubstitutionFormatString_TextFormat{TextFormat: "%CEL(" + expression + ")%"}, //nolint:staticcheck // Keep the Envoy wire form stable during this cleanup.
			OmitEmptyValues: true,
		}},
		SkipIfEmpty: true,
	}
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

func headerAttributeExpression(authenticator Authenticator, header string) string {
	var verified string
	if authenticator.JWT != nil {
		current, checks := metadataStringPathExpression(jwtAuthnFilterName, []string{authenticator.Name, jwtIssuerClaimName})
		verified = checks + " && " + current + " == " + celStringLiteral(authenticator.JWT.Issuer)
	} else {
		current, checks := metadataStringPathExpression(apiKeyMetadataNamespace, []string{apiKeyMetadataKey})
		verified = checks + " && " + current + " != \"\""
	}
	current, checks := metadataStringPathExpression(requestHeaderMetadataNamespace, []string{strings.ToLower(header)})
	return "((" + verified + " && " + checks + " && " + current + " != \"\") ? " + current + " : \"\")"
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

func attributeMappingExpression(attribute string, mappings map[string]string) string {
	key := celStringLiteral(filterStateKey(attribute))
	value := "filter_state[" + key + "]"
	// An unmatched value returns empty so skip_if_empty preserves the current value.
	result := `""`
	for _, source := range slices.Sorted(maps.Keys(mappings)) {
		result = "(" + value + " == " + celBytesLiteral(source) + " ? " + celStringLiteral(mappings[source]) + " : " + result + ")"
	}
	return "(" + key + " in filter_state && type(" + value + ") == bytes && " + value + " != b\"\") ? " + result + " : \"\""
}

func apiKeyAttributeExpression(attribute string) string {
	namespace := `metadata.filter_metadata["` + apiKeyMetadataNamespace + `"]`
	key := celStringLiteral(apiKeyAttributeMetadataKey(attribute))
	current := namespace + "[" + key + "]"
	return "((\"" + apiKeyMetadataNamespace + "\" in metadata.filter_metadata" + celAndSeparator + key + " in " + namespace + ") && type(" + current + ") == string && " + current + " != \"\") ? " + current + " : \"\""
}

func celStringLiteral(value string) string {
	var out strings.Builder
	out.WriteByte('"')
	for _, character := range value {
		switch character {
		case '\\', '"':
			out.WriteByte('\\')
			out.WriteRune(character)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		case '\b':
			out.WriteString(`\b`)
		case '\f':
			out.WriteString(`\f`)
		default:
			if character < 0x20 || character == 0x7f {
				fmt.Fprintf(&out, `\u%04x`, character)
			} else {
				out.WriteRune(character)
			}
		}
	}
	out.WriteByte('"')
	return out.String()
}

func celBytesLiteral(value string) string {
	var out strings.Builder
	out.WriteString(`b"`)
	for _, character := range []byte(value) {
		switch character {
		case '\\', '"':
			out.WriteByte('\\')
			out.WriteByte(character)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		case '\b':
			out.WriteString(`\b`)
		case '\f':
			out.WriteString(`\f`)
		default:
			if character < 0x20 || character > 0x7e {
				fmt.Fprintf(&out, `\x%02x`, character)
			} else {
				out.WriteByte(character)
			}
		}
	}
	out.WriteByte('"')
	return out.String()
}

type celExpressionBuilder struct{ next int64 }

func (b *celExpressionBuilder) id() int64 {
	b.next++
	return b.next
}

func (b *celExpressionBuilder) call(name string, args ...*expr.Expr) *expr.Expr {
	return &expr.Expr{Id: b.id(), ExprKind: &expr.Expr_CallExpr{CallExpr: &expr.Expr_Call{Function: name, Args: args}}}
}

func (b *celExpressionBuilder) metadataValue(namespace string, keys []string) *expr.Expr {
	value := &expr.Expr{Id: b.id(), ExprKind: &expr.Expr_IdentExpr{IdentExpr: &expr.Expr_Ident{Name: "metadata"}}}
	value = &expr.Expr{Id: b.id(), ExprKind: &expr.Expr_SelectExpr{SelectExpr: &expr.Expr_Select{Operand: value, Field: "filter_metadata"}}}
	for _, key := range append([]string{namespace}, keys...) {
		literal := &expr.Expr{Id: b.id(), ExprKind: &expr.Expr_ConstExpr{ConstExpr: &expr.Constant{ConstantKind: &expr.Constant_StringValue{StringValue: key}}}}
		value = b.call("_[_]", value, literal)
	}
	return value
}

func sharedAttributeConditions(jwtAuthenticator, keyAuthenticator Authenticator) ([]*rbac.Principal, *expr.Expr) {
	builder := &celExpressionBuilder{}
	var principals []*rbac.Principal
	var equality []*expr.Expr
	for _, attribute := range slices.Sorted(maps.Keys(keyAuthenticator.Attributes)) {
		if _, shared := jwtAuthenticator.Attributes[attribute]; !shared {
			continue
		}
		jwtNamespace, jwtPath := attributeMetadataPath(jwtAuthenticator, attribute)
		keyNamespace, keyPath := attributeMetadataPath(keyAuthenticator, attribute)
		valueMatcher := nonemptyScalarValueMatcher()
		principals = append(principals,
			dynamicMetadataPrincipal(jwtNamespace, jwtPath, valueMatcher),
			dynamicMetadataPrincipal(keyNamespace, keyPath, valueMatcher))
		equality = append(equality, builder.call("_==_",
			builder.metadataValue(jwtNamespace, jwtPath),
			builder.metadataValue(keyNamespace, keyPath)))
	}
	if len(equality) == 0 {
		return principals, nil
	}
	condition := equality[0]
	for _, next := range equality[1:] {
		condition = builder.call("_&&_", condition, next)
	}
	return principals, condition
}
