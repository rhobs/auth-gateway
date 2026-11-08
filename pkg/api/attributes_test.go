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
