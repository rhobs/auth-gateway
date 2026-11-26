package api

import (
	"fmt"
	"slices"

	yaml "go.yaml.in/yaml/v3"
)

const yamlStringTag = "!!str"

const (
	ExpressionEquals   = "equals"
	ExpressionNonempty = "nonempty"
	ExpressionPrefix   = "prefix"
	ExpressionRegex    = "regex"
	ExpressionHas      = "has"
	ExpressionHasOneOf = "has-one-of"
	ExpressionIn       = "in"
	ExpressionPresent  = "present"
)

// MatchValue holds a string or a list of strings.
type MatchValue struct {
	Text   string
	Items  []string
	IsList bool
}

func (v *MatchValue) UnmarshalYAML(node *yaml.Node) error {
	*v = MatchValue{}
	switch node.Kind {
	case yaml.ScalarNode:
		if node.Tag != yamlStringTag {
			return fmt.Errorf("match value must be a string or a list of strings")
		}
		v.Text = node.Value
	case yaml.SequenceNode:
		v.IsList = true
		for _, value := range node.Content {
			if value.Kind != yaml.ScalarNode || value.Tag != yamlStringTag {
				return fmt.Errorf("match value list must contain strings")
			}
			v.Items = append(v.Items, value.Value)
		}
	default:
		return fmt.Errorf("match value must be a string or a list of strings")
	}
	return nil
}

func (v *MatchValue) MarshalYAML() (any, error) {
	if v.IsList {
		return v.Items, nil
	}
	return v.Text, nil
}

// MatchExpression compares a named value or checks for a request header.
type MatchExpression struct {
	Name       string           `yaml:"name,omitempty"`
	Expression string           `yaml:"expression"`
	Value      *MatchValue      `yaml:"value,omitempty"`
	ValueFrom  *SourceReference `yaml:"value_from,omitempty"`
}

// UnmarshalYAML preserves strict fields and rejects null operands.
func (c *MatchExpression) UnmarshalYAML(node *yaml.Node) error {
	if err := strictMapping(node, "name", "expression", "value", "value_from"); err != nil {
		return err
	}
	*c = MatchExpression{}
	type plain MatchExpression
	return node.Decode((*plain)(c))
}

func strictMapping(node *yaml.Node, allowed ...string) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("expected an object")
	}
	seen := make(map[string]bool)
	for i := 0; i < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		if !slices.Contains(allowed, key.Value) || seen[key.Value] {
			return fmt.Errorf("unknown or duplicate field %q", key.Value)
		}
		seen[key.Value] = true
		if value.Tag == "!!null" {
			return fmt.Errorf("%s must not be null", key.Value)
		}
	}
	return nil
}

// SourceReference selects one typed source. Consumers restrict available keys.
type SourceReference struct {
	Claim       []string `yaml:"claim,omitempty"`
	Fixed       *string  `yaml:"fixed,omitempty"`
	Credential  *string  `yaml:"credential,omitempty"`
	Certificate *string  `yaml:"certificate,omitempty"`
	Header      *string  `yaml:"header,omitempty"`
	Attribute   *string  `yaml:"attribute,omitempty"`
}

func (r *SourceReference) UnmarshalYAML(node *yaml.Node) error {
	if err := strictMapping(node, "claim", "credential", "certificate", "header", "attribute", "fixed"); err != nil {
		return err
	}
	for i := 0; i < len(node.Content); i += 2 {
		key, value := node.Content[i].Value, node.Content[i+1]
		if key == "claim" {
			if value.Kind != yaml.SequenceNode {
				return fmt.Errorf("claim must be a list of strings")
			}
			for _, item := range value.Content {
				if item.Kind != yaml.ScalarNode || item.Tag != yamlStringTag {
					return fmt.Errorf("claim must contain strings")
				}
			}
		} else if value.Kind != yaml.ScalarNode || value.Tag != yamlStringTag {
			return fmt.Errorf("%s must be a string", key)
		}
	}
	*r = SourceReference{}
	type plain SourceReference
	if err := node.Decode((*plain)(r)); err != nil {
		return err
	}
	if r.Kind() == "" {
		return fmt.Errorf("source must set exactly one source key")
	}
	return nil
}

// Kind returns the selected key, or an empty string for an invalid selection.
func (r *SourceReference) Kind() string {
	kind, count := "", 0
	if r.Claim != nil {
		kind, count = "claim", count+1
	}
	for _, field := range []struct {
		name  string
		value *string
	}{
		{"fixed", r.Fixed}, {"credential", r.Credential}, {"certificate", r.Certificate}, {"header", r.Header}, {"attribute", r.Attribute},
	} {
		if field.value != nil {
			kind, count = field.name, count+1
		}
	}
	if count != 1 {
		return ""
	}
	return kind
}

// Scalar returns the selected scalar value.
func (r *SourceReference) Scalar() string {
	switch r.Kind() {
	case "fixed":
		return *r.Fixed
	case "credential":
		return *r.Credential
	case "certificate":
		return *r.Certificate
	case "header":
		return *r.Header
	case "attribute":
		return *r.Attribute
	default:
		return ""
	}
}
