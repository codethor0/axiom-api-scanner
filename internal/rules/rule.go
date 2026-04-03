package rules

// SafetyMode classifies how aggressively a rule may mutate or stress the target.
type SafetyMode string

const (
	SafetyPassive SafetyMode = "passive"
	SafetySafe    SafetyMode = "safe"
	SafetyFull    SafetyMode = "full"
)

// Rule is the validated in-memory representation of a YAML rule definition.
type Rule struct {
	ID            string           `yaml:"id"`
	Name          string           `yaml:"name"`
	Category      string           `yaml:"category"`
	Severity      string           `yaml:"severity"`
	Confidence    string           `yaml:"confidence"`
	Safety        RuleSafety       `yaml:"safety"`
	Target        RuleTarget       `yaml:"target"`
	Prerequisites []string         `yaml:"prerequisites"`
	Mutations     []map[string]any `yaml:"mutations"`
	Matchers      []map[string]any `yaml:"matchers"`
	References    []string         `yaml:"references"`
	Tags          []string         `yaml:"tags"`
}

// RuleSafety describes destructive potential and execution band.
type RuleSafety struct {
	Mode        SafetyMode `yaml:"mode"`
	Destructive bool       `yaml:"destructive"`
}

// RuleTarget selects where a rule applies in the request surface.
type RuleTarget struct {
	Methods []string `yaml:"methods"`
	Where   string   `yaml:"where"`
}
