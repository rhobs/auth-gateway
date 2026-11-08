package api

import (
	"fmt"

	yaml "go.yaml.in/yaml/v3"
)

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
			if value.Kind != yaml.ScalarNode || value.Tag != "!!str" {
				return fmt.Errorf("attribute allowlists must contain strings")
			}
		}
		return node.Decode(&c.Values)
	case yaml.MappingNode:
		if len(node.Content) != 2 || node.Content[0].Value != "equals_attribute" || node.Content[1].Tag != "!!str" {
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
