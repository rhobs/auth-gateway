package gateway

import (
	"strings"
	"testing"

	rbac "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	expr "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

func TestJWTExpressionsUseEnvoyCELVariablesAndGuardMissingAttributes(t *testing.T) {
	claim := jwtClaimExpression([]string{"issuer-one", "organization", "id"})
	claimMetadata := `metadata.filter_metadata["envoy.filters.http.jwt_authn"]`
	claimValue := claimMetadata + `["issuer-one"]["organization"]["id"]`
	if !strings.Contains(claim, `"issuer-one" in `+claimMetadata) || !strings.Contains(claim, `"organization" in `+claimMetadata+`["issuer-one"]`) || !strings.Contains(claim, `"id" in `+claimMetadata+`["issuer-one"]["organization"]`) || !strings.Contains(claim, "type("+claimValue+") == string") || !strings.Contains(claim, claimValue+` != ""`) || strings.Contains(claim, "dynamicMetadata(") || strings.Contains(claim, "dynamic_metadata[") {
		t.Fatalf("JWT claim expression does not use Envoy CEL metadata: %s", claim)
	}
}

func testServerAuthenticationRules(t *testing.T, c gatewayapi.Config, serverIndex int) *rbac.RBAC {
	t.Helper()
	effective := resolveTestConfig(t, c)
	rules, err := serverAuthenticationRBACRules(effective, effective.servers[serverIndex])
	if err != nil {
		t.Fatal(err)
	}
	return rules
}

func metadataReference(value *expr.Expr) []string {
	if call := value.GetCallExpr(); call != nil && call.Function == "_[_]" && len(call.Args) == 2 {
		return append(metadataReference(call.Args[0]), call.Args[1].GetConstExpr().GetStringValue())
	}
	if selectExpr := value.GetSelectExpr(); selectExpr != nil {
		return append(metadataReference(selectExpr.Operand), selectExpr.Field)
	}
	if identifier := value.GetIdentExpr(); identifier != nil {
		return []string{identifier.Name}
	}
	return nil
}
