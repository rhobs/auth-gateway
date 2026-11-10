package api

import (
	"fmt"

	yaml "go.yaml.in/yaml/v3"
)

const yamlStringTag = "!!str"

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

// AttributeCondition accepts literal values or equality with another source.
type AttributeCondition struct {
	Values          []string
	EqualsAttribute string
}

func (c *AttributeCondition) UnmarshalYAML(node *yaml.Node) error {
	*c = AttributeCondition{}
	switch node.Kind {
	case yaml.SequenceNode:
		for _, value := range node.Content {
			if value.Kind != yaml.ScalarNode || value.Tag != yamlStringTag {
				return fmt.Errorf("attribute allowlists must contain strings")
			}
		}
		return node.Decode(&c.Values)
	case yaml.MappingNode:
		if len(node.Content) != 2 || node.Content[0].Value != "equals_attribute" || node.Content[1].Tag != yamlStringTag {
			return fmt.Errorf("attribute condition must set only equals_attribute")
		}
		c.EqualsAttribute = node.Content[1].Value
		return nil
	default:
		return fmt.Errorf("attribute condition must be a string list or equals_attribute")
	}
}

func (c *AttributeCondition) MarshalYAML() (any, error) {
	if c.EqualsAttribute != "" {
		if c.Values != nil {
			return nil, fmt.Errorf("attribute condition cannot combine values and equals_attribute")
		}
		return struct {
			EqualsAttribute string `yaml:"equals_attribute"`
		}{c.EqualsAttribute}, nil
	}
	return c.Values, nil
}
