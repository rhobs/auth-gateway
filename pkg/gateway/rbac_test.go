package gateway

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	httpRBAC "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rbac/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
)

func TestRequiredHeaderRBACRulesRejectsEmptyMappings(t *testing.T) {
	_, err := requiredHeaderRBACRules(nil)
	if err == nil || !strings.Contains(err.Error(), "at least one request header mapping") {
		t.Fatalf("required header rules error = %v, want empty mapping error", err)
	}
}

func TestGrantEqualityUsesOriginalScalarSources(t *testing.T) {
	c := loadConfigCase(t, "access-control")
	for _, test := range []struct {
		name, namespace string
		index           int
		path            []string
	}{
		{"internal JWT", "envoy.filters.http.jwt_authn", 0, []string{"issuer-one", "tenant"}},
		{"external JWT", "envoy.filters.http.jwt_authn", 1, []string{"issuer-two", "organization", "id"}},
		{"API key", "auth_gateway.api_key", 2, []string{"attribute.tenant_id"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			grant := gatewayapi.AuthorizationGrant{Authenticator: c.Authenticators[test.index].Name, Attributes: []gatewayapi.MatchExpression{{Name: "tenant_id", Expression: "equals-attribute", Value: gatewayapi.MatchValue{Text: "requested_tenant"}}}}
			policy, err := grantPolicy(c.Authenticators[test.index], grant)
			if err != nil {
				t.Fatal(err)
			}
			comparison := policy.GetCondition().GetCallExpr()
			if comparison == nil || comparison.Function != "_==_" || len(comparison.Args) != 2 {
				t.Fatalf("equality expression = %v", policy.GetCondition())
			}
			want := append([]string{"metadata", "filter_metadata", test.namespace}, test.path...)
			if got := metadataReference(comparison.Args[0]); !slices.Equal(got, want) {
				t.Fatalf("credential source = %v, want %v", got, want)
			}
			if got := metadataReference(comparison.Args[1]); !slices.Equal(got, []string{"metadata", "filter_metadata", "auth_gateway.request_headers", "x-tenant"}) {
				t.Fatalf("request source = %v", got)
			}
			principals := policy.Principals[0].GetAndIds().GetIds()
			if len(principals) != 3 {
				t.Fatalf("principals = %v, want verified identity and both scalar guards", principals)
			}
			for _, principal := range principals[1:] {
				value := principal.GetSourcedMetadata().GetMetadataMatcher().GetValue()
				if value.GetStringMatch().GetSafeRegex().GetRegex() != headerValuePattern || value.GetListMatch() != nil {
					t.Fatalf("comparison must require a nonempty scalar string: %v", value)
				}
			}
		})
	}
}

func TestGrantLiteralExpressionsMatchScalarStrings(t *testing.T) {
	c := loadConfigCase(t, "access-control")
	for _, test := range []struct {
		name       string
		expression string
		value      gatewayapi.MatchValue
		want       []string
	}{
		{name: "equals", expression: "equals", value: gatewayapi.MatchValue{Text: "writer"}, want: []string{"writer"}},
		{name: "in", expression: "in", value: gatewayapi.MatchValue{IsList: true, Items: []string{"reader", "writer"}}, want: []string{"reader", "writer"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			grant := gatewayapi.AuthorizationGrant{Authenticator: "issuer-one", Attributes: []gatewayapi.MatchExpression{{Name: "role", Expression: test.expression, Value: test.value}}}
			policy, err := grantPolicy(c.Authenticators[0], grant)
			if err != nil {
				t.Fatal(err)
			}
			principals := policy.Principals[0].GetAndIds().GetIds()
			if len(principals) != 2 {
				t.Fatalf("principals = %d, want verified issuer and role", len(principals))
			}
			value := principals[1].GetSourcedMetadata().GetMetadataMatcher().GetValue()
			if value.GetListMatch() != nil {
				t.Fatal("list-valued claims must not match")
			}
			if len(test.want) == 1 {
				if value.GetStringMatch().GetExact() != test.want[0] {
					t.Fatalf("exact match = %v", value)
				}
				return
			}
			choices := value.GetOrMatch().GetValueMatchers()
			if len(choices) != len(test.want) {
				t.Fatalf("choices = %v", choices)
			}
			for i, choice := range choices {
				if choice.GetStringMatch().GetExact() != test.want[i] || choice.GetListMatch() != nil {
					t.Fatalf("choice %d = %v, want %q", i, choice, test.want[i])
				}
			}
		})
	}
}

func TestMultiProviderGrantsKeepVerifiedClaimsSeparate(t *testing.T) {
	c := loadConfigCase(t, "access-control")
	effective := resolveTestConfig(t, c)
	access := effective.servers[0].bindings[1].access[0]
	packed, err := authorizationPerRouteConfig(effective, access)
	if err != nil {
		t.Fatal(err)
	}
	var config httpRBAC.RBACPerRoute
	if err := packed.UnmarshalTo(&config); err != nil {
		t.Fatal(err)
	}
	policies := config.GetRbac().GetRules().GetPolicies()
	for index, provider := range []string{"issuer-one", "issuer-two"} {
		policy := policies[fmt.Sprintf("grant-%d", index)]
		principals := policy.GetPrincipals()[0].GetAndIds().GetIds()
		verified := principals[0].GetSourcedMetadata().GetMetadataMatcher()
		if verified.GetFilter() != "envoy.filters.http.jwt_authn" || !slices.Equal(metadataMatcherPath(verified.GetPath()), []string{provider, "iss"}) {
			t.Fatalf("provider identity = %v", verified)
		}
		if verified.GetValue().GetStringMatch().GetExact() != c.Authenticators[index].JWT.Issuer {
			t.Fatal("grant does not require the verifying issuer")
		}
		if len(policies) != 2 || policy.Condition == nil {
			t.Fatalf("provider-specific grant is missing: %v", &config)
		}
	}
}
