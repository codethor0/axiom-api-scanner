package mutate

import (
	"fmt"
	"sort"
	"strings"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
	"github.com/codethor0/axiom-api-scanner/internal/rules"
)

// Candidate is a deterministic mutation step description (no network I/O).
type Candidate struct {
	RuleID          string            `json:"rule_id"`
	MutationIndex   int               `json:"mutation_index"`
	Kind            rules.MutationKind `json:"kind"`
	Detail          string            `json:"detail"`
	EndpointID      string            `json:"endpoint_id,omitempty"`
	PathTemplate    string            `json:"path_template,omitempty"`
}

// GenerateForEndpoint produces ordered candidates for one rule and endpoint.
func GenerateForEndpoint(rule rules.Rule, ep engine.ScanEndpoint) ([]Candidate, error) {
	var out []Candidate
	for i, m := range rule.Mutations {
		c, err := candidateFromMutation(rule.ID, i, m, ep)
		if err != nil {
			return nil, fmt.Errorf("rule %s mutation %d: %w", rule.ID, i, err)
		}
		out = append(out, c...)
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].Kind != out[b].Kind {
			return out[a].Kind < out[b].Kind
		}
		if out[a].MutationIndex != out[b].MutationIndex {
			return out[a].MutationIndex < out[b].MutationIndex
		}
		return out[a].Detail < out[b].Detail
	})
	return out, nil
}

func candidateFromMutation(ruleID string, idx int, m rules.Mutation, ep engine.ScanEndpoint) ([]Candidate, error) {
	base := Candidate{
		RuleID:        ruleID,
		MutationIndex: idx,
		Kind:          m.Kind,
		EndpointID:    ep.ID,
		PathTemplate:  ep.PathTemplate,
	}
	switch m.Kind {
	case rules.MutationReplacePathParam:
		if m.ReplacePathParam == nil {
			return nil, fmt.Errorf("replace_path_param payload missing")
		}
		p := m.ReplacePathParam
		base.Detail = fmt.Sprintf("swap path param %q from %q to %q on %s", p.Param, p.From, p.To, ep.PathTemplate)
		return []Candidate{base}, nil
	case rules.MutationReplaceQueryParam:
		if m.ReplaceQueryParam == nil {
			return nil, fmt.Errorf("replace_query_param payload missing")
		}
		p := m.ReplaceQueryParam
		base.Detail = fmt.Sprintf("swap query param %q from %q to %q", p.Param, p.From, p.To)
		return []Candidate{base}, nil
	case rules.MutationMergeJSONFields:
		if m.MergeJSONFields == nil {
			return nil, fmt.Errorf("merge_json_fields payload missing")
		}
		keys := make([]string, 0, len(m.MergeJSONFields.Fields))
		for k := range m.MergeJSONFields.Fields {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		base.Detail = fmt.Sprintf("merge json fields %s", strings.Join(keys, ","))
		return []Candidate{base}, nil
	case rules.MutationPathNormalizationVariant:
		if m.PathNormalizationVariant == nil {
			return nil, fmt.Errorf("path_normalization_variant payload missing")
		}
		base.Detail = fmt.Sprintf("path variant %q on %s", m.PathNormalizationVariant.Style, ep.PathTemplate)
		return []Candidate{base}, nil
	case rules.MutationRotateRequestHeaders:
		if m.RotateRequestHeaders == nil {
			return nil, fmt.Errorf("rotate_request_headers payload missing")
		}
		names := make([]string, 0, len(m.RotateRequestHeaders.Headers))
		for _, h := range m.RotateRequestHeaders.Headers {
			names = append(names, h.Name)
		}
		sort.Strings(names)
		base.Detail = fmt.Sprintf("rotate headers %s", strings.Join(names, ","))
		return []Candidate{base}, nil
	default:
		return nil, fmt.Errorf("unsupported mutation kind %q", m.Kind)
	}
}
