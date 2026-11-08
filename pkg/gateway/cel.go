package gateway

import (
	"fmt"
	"strings"

	expr "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

const (
	celAndSeparator = " && "
)

type celExpressionBuilder struct{ next int64 }

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
