package api

import (
	"reflect"
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v3"
)

func TestAttributeConditionYAMLMapRoundTrip(t *testing.T) {
	want := map[string]*AttributeCondition{
		"role":      {Values: []string{"reader", "admin"}},
		"tenant_id": {EqualsAttribute: "requested_tenant"},
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
	if err := yaml.Unmarshal([]byte("role: [reader, admin]\ntenant_id: {equals_attribute: requested_tenant}\n"), &expected); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(document, expected) {
		t.Fatalf("encoded conditions = %#v, want %#v", document, expected)
	}
	var got map[string]*AttributeCondition
	if err := yaml.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("decoded conditions = %#v, want %#v", got, want)
	}
}

func TestAttributeConditionRejectsUnknownOrAmbiguousForms(t *testing.T) {
	for _, input := range []string{
		"[reader, 123]",
		"reader",
		"{unknown: requested_tenant}",
		"{equals_attribute: requested_tenant, values: [reader]}",
		"{equals_attribute: first, equals_attribute: second}",
		"{equals_attribute: 123}",
	} {
		t.Run(input, func(t *testing.T) {
			var condition AttributeCondition
			if err := yaml.Unmarshal([]byte(input), &condition); err == nil {
				t.Fatal("invalid attribute condition was accepted")
			}
		})
	}
}

func TestAttributeConditionRejectsMarshalingBothForms(t *testing.T) {
	condition := &AttributeCondition{Values: []string{"tenant-a"}, EqualsAttribute: "requested_tenant"}
	if _, err := yaml.Marshal(condition); err == nil || !strings.Contains(err.Error(), "cannot combine") {
		t.Fatalf("Marshal error = %v, want conflicting condition forms", err)
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
	if err := yaml.Unmarshal([]byte("attributes: {tenant_id: {claim_path: [sub]}}"), &Authenticator{}); err == nil {
		t.Fatal("legacy attribute map was accepted")
	}
}
