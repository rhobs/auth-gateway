package api

import (
	"reflect"
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v3"
)

func TestMatchExpressionsYAMLRoundTrip(t *testing.T) {
	input := `- name: role
  expression: equals
  value: reader
- name: tenant_id
  expression: equals
  value_from: {attribute: requested_tenant}
- name: writer_id
  expression: in
  value: [agent-17, agent-18]
- name: groups
  expression: has
  value: metrics-writers
- name: scopes
  expression: has-one-of
  value: [metrics.write, metrics.admin]
- name: Authorization
  expression: present
- name: feature
  expression: nonempty
`
	want := []MatchExpression{
		{Name: "role", Expression: "equals", Value: &MatchValue{Text: "reader"}},
		{Name: "tenant_id", Expression: "equals", ValueFrom: &SourceReference{Attribute: new("requested_tenant")}},
		{Name: "writer_id", Expression: "in", Value: &MatchValue{IsList: true, Items: []string{"agent-17", "agent-18"}}},
		{Name: "groups", Expression: "has", Value: &MatchValue{Text: "metrics-writers"}},
		{Name: "scopes", Expression: "has-one-of", Value: &MatchValue{IsList: true, Items: []string{"metrics.write", "metrics.admin"}}},
		{Name: "Authorization", Expression: "present"},
		{Name: "feature", Expression: "nonempty"},
	}
	var got []MatchExpression
	if err := yaml.Unmarshal([]byte(input), &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("conditions = %#v, want %#v", got, want)
	}
	data, err := yaml.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip []MatchExpression
	if err := yaml.Unmarshal(data, &roundTrip); err != nil || !reflect.DeepEqual(roundTrip, want) {
		t.Fatalf("round trip = %#v, error = %v", roundTrip, err)
	}
}

func TestConditionRejectsInvalidOperands(t *testing.T) {
	for _, input := range []string{
		"expression: equals\nvalue: 123", "expression: in\nvalue: [reader, 123]",
		"expression: present\nvalue: null", "expression: equals\nvalue_from: null",
		"expression: equals\nvalue_from: {header: 123}", "expression: equals\nvalue_from: {attribute: role, unknown: x}",
		"expression: present\nunknown: x", "expression: present\nexpression: equals",
	} {
		t.Run(input, func(t *testing.T) {
			if err := yaml.Unmarshal([]byte(input), &MatchExpression{}); err == nil {
				t.Fatal("invalid condition was accepted")
			}
		})
	}
}

func TestSourceReferencesYAMLRoundTrip(t *testing.T) {
	input := `- name: tenant_id
  from: {claim: [organization, id]}
- name: requested_tenant
  from: {header: X-Tenant}
- name: writer_id
  from: {credential: writer_id}
- name: client
  from: {certificate: uri_san}
- name: origin
  from: {fixed: partner}
- name: role
  from: {attribute: role}
`
	var got []AttributeSource
	if err := yaml.Unmarshal([]byte(input), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 6 || !reflect.DeepEqual(got[0].From.Claim, []string{"organization", "id"}) || got[1].From.Scalar() != "X-Tenant" {
		t.Fatalf("sources = %#v", got)
	}
	data, err := yaml.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip []AttributeSource
	if err := yaml.Unmarshal(data, &roundTrip); err != nil || !reflect.DeepEqual(roundTrip, got) {
		t.Fatalf("round trip = %#v, error = %v", roundTrip, err)
	}
}

func TestSourceReferenceRejectsInvalidTypesAndKeys(t *testing.T) {
	for _, input := range []string{
		"{}", "{header: null}", "{header: 123}", "{header: true}", "{header: [X-Tenant]}",
		"{claim: tenant}", "{claim: [tenant, 123]}", "{claim: [tenant, null]}",
		"{header: X-Tenant, claim: [tenant]}", "{header: X-Tenant, header: X-Role}",
		"{header: X-Tenant, unknown: value}", "{header: X-Tenant, attribute: null}",
	} {
		t.Run(input, func(t *testing.T) {
			if err := yaml.Unmarshal([]byte(input), &SourceReference{}); err == nil {
				t.Fatal("invalid source was accepted")
			}
		})
	}
}

func TestSchemaRejectsLegacyFields(t *testing.T) {
	for _, test := range []struct {
		name, input string
		target      any
	}{
		{"source", "name: tenant_id\nfrom_source: claim\nvalue: [tenant]", &AttributeSource{}},
		{"forwarding", "name: X-Tenant\nfrom_attribute: tenant_id", &RequestHeaderMapping{}},
		{"path", "exact: /status", &PathMatch{}},
		{"grant", "authenticator: issuer\nattributes: []", &AuthorizationGrant{}},
		{"metric", "labels: {tenant: tenant_id}", &APIMetrics{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			decoder := yaml.NewDecoder(strings.NewReader(test.input))
			decoder.KnownFields(true)
			if err := decoder.Decode(test.target); err == nil {
				t.Fatal("legacy syntax was accepted")
			}
		})
	}
}
