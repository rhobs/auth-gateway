package api

import (
	"fmt"

	yaml "go.yaml.in/yaml/v3"
)

const yamlStringTag = "!!str"

const (
	ExpressionEquals          = "equals"
	ExpressionEqualsAttribute = "equals-attribute"
	ExpressionIn              = "in"
)

// AttributeValue is a claim key path or a scalar source name.
type AttributeValue struct {
	Text   string
	Path   []string
	IsPath bool
}

func (v *AttributeValue) UnmarshalYAML(node *yaml.Node) error {
	*v = AttributeValue{}
	switch node.Kind {
	case yaml.ScalarNode:
		if node.Tag != yamlStringTag {
			return fmt.Errorf("attribute value must be a string or a list of strings")
		}
		v.Text = node.Value
	case yaml.SequenceNode:
		v.IsPath = true
		for _, item := range node.Content {
			if item.Kind != yaml.ScalarNode || item.Tag != yamlStringTag {
				return fmt.Errorf("attribute value list must contain strings")
			}
			v.Path = append(v.Path, item.Value)
		}
	default:
		return fmt.Errorf("attribute value must be a string or a list of strings")
	}
	return nil
}

func (v AttributeValue) MarshalYAML() (any, error) {
	if v.IsPath {
		return v.Path, nil
	}
	return v.Text, nil
}

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

func (v MatchValue) MarshalYAML() (any, error) {
	if v.IsList {
		return v.Items, nil
	}
	return v.Text, nil
}

// MatchExpression compares a named header or attribute with its value.
type MatchExpression struct {
	Name       string     `yaml:"name"`
	Expression string     `yaml:"expression"`
	Value      MatchValue `yaml:"value"`
}
