package mutation

import (
	"sort"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
	"github.com/codethor0/axiom-api-scanner/internal/mutate"
	v1plan "github.com/codethor0/axiom-api-scanner/internal/plan/v1"
	"github.com/codethor0/axiom-api-scanner/internal/rules"
)

// WorkItem is one rule mutation candidate applied to one endpoint.
type WorkItem struct {
	Endpoint  engine.ScanEndpoint
	Rule      rules.Rule
	Candidate mutate.Candidate
}

// BuildWorkList expands eligible V1 rules into a deterministic ordered work queue.
func BuildWorkList(eps []engine.ScanEndpoint, ruleSet []rules.Rule) ([]WorkItem, error) {
	byID := make(map[string]rules.Rule, len(ruleSet))
	for _, r := range ruleSet {
		byID[r.ID] = r
	}
	epsSorted := append([]engine.ScanEndpoint(nil), eps...)
	sort.Slice(epsSorted, func(i, j int) bool {
		if epsSorted[i].PathTemplate != epsSorted[j].PathTemplate {
			return epsSorted[i].PathTemplate < epsSorted[j].PathTemplate
		}
		if epsSorted[i].Method != epsSorted[j].Method {
			return epsSorted[i].Method < epsSorted[j].Method
		}
		return epsSorted[i].ID < epsSorted[j].ID
	})
	var out []WorkItem
	for _, ep := range epsSorted {
		for _, d := range v1plan.Plan(ep, ruleSet) {
			if !d.Eligible {
				continue
			}
			ru, ok := byID[d.RuleID]
			if !ok {
				continue
			}
			cands, err := mutate.GenerateForEndpoint(ru, ep)
			if err != nil {
				return nil, err
			}
			for _, c := range cands {
				out = append(out, WorkItem{Endpoint: ep, Rule: ru, Candidate: c})
			}
		}
	}
	return out, nil
}
