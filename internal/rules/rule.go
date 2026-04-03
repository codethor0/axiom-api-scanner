package rules

import (
	"gopkg.in/yaml.v3"
)

// SafetyMode classifies how aggressively a rule may mutate or stress the target.
type SafetyMode string

const (
	SafetyPassive SafetyMode = "passive"
	SafetySafe    SafetyMode = "safe"
	SafetyFull    SafetyMode = "full"
)

// Rule is the validated in-memory representation of a YAML rule definition.
type Rule struct {
	ID            string     `yaml:"id" json:"id"`
	Name          string     `yaml:"name" json:"name"`
	Category      string     `yaml:"category" json:"category"`
	Severity      string     `yaml:"severity" json:"severity"`
	Confidence    string     `yaml:"confidence" json:"confidence"`
	Safety        RuleSafety `yaml:"safety" json:"safety"`
	Target        RuleTarget `yaml:"target" json:"target"`
	Prerequisites []string   `yaml:"prerequisites" json:"prerequisites"`
	Mutations     Mutations  `yaml:"mutations" json:"mutations"`
	Matchers      Matchers   `yaml:"matchers" json:"matchers"`
	References    []string   `yaml:"references" json:"references"`
	Tags          []string   `yaml:"tags" json:"tags"`
}

// Mutations is a typed list loaded from YAML via ParseMutationFromMap.
type Mutations []Mutation

// UnmarshalYAML decodes mutation documents strictly by kind.
func (m *Mutations) UnmarshalYAML(n *yaml.Node) error {
	var raw []map[string]any
	if err := n.Decode(&raw); err != nil {
		return err
	}
	out := make(Mutations, 0, len(raw))
	for _, item := range raw {
		mu, err := ParseMutationFromMap(item)
		if err != nil {
			return err
		}
		out = append(out, mu)
	}
	*m = out
	return nil
}

// Matchers is a typed list loaded from YAML.
type Matchers []Matcher

// UnmarshalYAML decodes matcher documents strictly by kind.
func (m *Matchers) UnmarshalYAML(n *yaml.Node) error {
	var raw []map[string]any
	if err := n.Decode(&raw); err != nil {
		return err
	}
	out := make(Matchers, 0, len(raw))
	for _, item := range raw {
		mat, err := ParseMatcherFromMap(item)
		if err != nil {
			return err
		}
		out = append(out, mat)
	}
	*m = out
	return nil
}

// RuleSafety describes destructive potential and execution band.
type RuleSafety struct {
	Mode        SafetyMode `yaml:"mode" json:"mode"`
	Destructive bool       `yaml:"destructive" json:"destructive"`
}

// RuleTarget selects where a rule applies in the request surface.
type RuleTarget struct {
	Methods []string `yaml:"methods" json:"methods"`
	Where   string   `yaml:"where" json:"where"`
}
