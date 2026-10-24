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
	selectedAuthenticatorKey    = "auth_gateway.authenticator"
	celAndSeparator             = " && "
)

func (c Config) toServerAttributeInitializationConfig(server Server) *setfilterstate.Config {
	config := &setfilterstate.Config{}
	selectIdentity := mixedAnyOf(c, server)
	names := slices.Clone(selectedAuthenticatorNames(server))
	if selectIdentity || serverUsesMTLS(c, server) {
		slices.SortStableFunc(names, func(a, b string) int {
			return authenticatorPriority(findAuthenticator(c, a)) - authenticatorPriority(findAuthenticator(c, b))
		})
	}
	if selectIdentity {
		// Finish identity selection before any identity can supply attributes.
		for _, name := range names {
			authenticator := findAuthenticator(c, name)
			expression := "((" + authenticatorVerifiedExpression(authenticator) + ") ? " + celStringLiteral(name) + " : \"\")"
			config.OnRequestHeaders = append(config.OnRequestHeaders, filterStateValue(selectedAuthenticatorKey, expression))
		}
	}
	for _, name := range names {
		authenticator := findAuthenticator(c, name)
		for _, attribute := range slices.Sorted(maps.Keys(authenticator.Attributes)) {
			source := authenticator.Attributes[attribute]
			var expression string
			switch {
			case source.Header != nil:
				expression = headerAttributeExpression(authenticator, *source.Header)
			case authenticator.JWT != nil:
				expression = jwtClaimExpression(append([]string{name}, source.ClaimPath...))
			case authenticator.MTLS != nil:
				expression = mtlsSANAttributeExpression(source)
			default:
				expression = apiKeyAttributeExpression(attribute)
			}
			if selectIdentity {
				key := celStringLiteral(selectedAuthenticatorKey)
				expression = "(" + key + " in filter_state && filter_state[" + key + "] == " + celBytesLiteral(name) + ") ? (" + expression + ") : \"\""
			}
			config.OnRequestHeaders = append(config.OnRequestHeaders, filterStateValue(filterStateKey(attribute), expression))
		}
	}
	return config
}

func authenticatorPriority(authenticator Authenticator) int {
	switch {
	case authenticator.JWT != nil:
		return 3
	case authenticator.MTLS != nil:
		return 2
	default:
		return 1
	}
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
	verified := authenticatorVerifiedExpression(authenticator)
	current, checks := metadataStringPathExpression(requestHeaderMetadataNamespace, []string{strings.ToLower(header)})
	return "((" + verified + " && " + checks + " && " + current + " != \"\") ? " + current + " : \"\")"
}

func authenticatorVerifiedExpression(authenticator Authenticator) string {
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

func mtlsSANAttributeExpression(source AttributeSource) string {
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

func sharedAttributeConditions(authenticators ...Authenticator) ([]*rbac.Principal, *expr.Expr) {
	builder := &celExpressionBuilder{}
	var principals []*rbac.Principal
	var equality []*expr.Expr
	for first := range authenticators {
		for second := first + 1; second < len(authenticators); second++ {
			for _, attribute := range slices.Sorted(maps.Keys(authenticators[second].Attributes)) {
				if _, shared := authenticators[first].Attributes[attribute]; !shared {
					continue
				}
				firstNamespace, firstPath := attributeMetadataPath(authenticators[first], attribute)
				secondNamespace, secondPath := attributeMetadataPath(authenticators[second], attribute)
				valueMatcher := nonemptyScalarValueMatcher()
				principals = append(principals,
					dynamicMetadataPrincipal(firstNamespace, firstPath, valueMatcher),
					dynamicMetadataPrincipal(secondNamespace, secondPath, valueMatcher))
				equality = append(equality, builder.call("_==_",
					builder.metadataValue(firstNamespace, firstPath),
					builder.metadataValue(secondNamespace, secondPath)))
			}
		}
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
