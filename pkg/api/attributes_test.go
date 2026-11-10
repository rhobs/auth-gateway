package api

import (
	"reflect"
	"testing"

	yaml "go.yaml.in/yaml/v3"
)

func TestMatchExpressionsYAMLRoundTrip(t *testing.T) {
	want := []MatchExpression{
		{Name: "role", Expression: "equals", Value: MatchValue{Text: "reader"}},
		{Name: "tenant_id", Expression: "equals-attribute", Value: MatchValue{Text: "requested_tenant"}},
		{Name: "writer_id", Expression: "in", Value: MatchValue{IsList: true, Items: []string{"agent-17", "agent-18"}}},
	}
	data, err := yaml.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var document any
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	var expected any
	if err := yaml.Unmarshal([]byte("- name: role\n  expression: equals\n  value: reader\n- name: tenant_id\n  expression: equals-attribute\n  value: requested_tenant\n- name: writer_id\n  expression: in\n  value: [agent-17, agent-18]\n"), &expected); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(document, expected) {
		t.Fatalf("encoded conditions = %#v, want %#v", document, expected)
	}
	var got []MatchExpression
	if err := yaml.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("decoded conditions = %#v, want %#v", got, want)
	}
}

func TestMatchValueRejectsOtherTypes(t *testing.T) {
	for _, input := range []string{
		"[reader, 123]",
		"123",
	} {
		t.Run(input, func(t *testing.T) {
			var value MatchValue
			if err := yaml.Unmarshal([]byte(input), &value); err == nil {
				t.Fatal("invalid match value was accepted")
			}
		})
	}
}

func TestAuthenticatorAttributesUseNamedEntries(t *testing.T) {
	input := []byte("name: issuer\njwt: {issuer: https://issuer.example, jwks: {uri: https://issuer.example/jwks}}\nattributes:\n  - name: tenant_id\n    from_source: claim\n    value: [organization, id]\n  - name: requested_tenant\n    from_source: header\n    value: X-Tenant\n")
	var authenticator Authenticator
	if err := yaml.Unmarshal(input, &authenticator); err != nil {
		t.Fatal(err)
	}
	if len(authenticator.Attributes) != 2 || !reflect.DeepEqual(authenticator.Attributes[0].Value.Path, []string{"organization", "id"}) || authenticator.Attributes[1].Value.Text != "X-Tenant" {
		t.Fatalf("attributes = %#v", authenticator.Attributes)
	}
	data, err := yaml.Marshal(authenticator)
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip Authenticator
	if err := yaml.Unmarshal(data, &roundTrip); err != nil || !reflect.DeepEqual(roundTrip, authenticator) {
		t.Fatalf("round trip = %#v, error = %v", roundTrip, err)
	}
	for _, value := range []string{"123", "[tenant, 123]", "{key: tenant}"} {
		if err := yaml.Unmarshal([]byte("value: "+value), &struct {
			Value AttributeValue `yaml:"value"`
		}{}); err == nil {
			t.Errorf("accepted invalid attribute value %s", value)
		}
	}
}
