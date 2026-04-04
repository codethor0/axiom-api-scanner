package v1

import (
	"sort"
	"strings"

	"github.com/chomechomekitchen/axiom-api-scanner/internal/engine"
	"github.com/chomechomekitchen/axiom-api-scanner/internal/rules"
)

// Decision explains planner eligibility for one rule on one endpoint.
type Decision struct {
	RuleID    string   `json:"rule_id"`
	Eligible  bool     `json:"eligible"`
	Reasons   []string `json:"reasons"`
	V1Family  string   `json:"v1_family"`
}

// Plan returns deterministic eligibility decisions for supported V1 families only.
func Plan(ep engine.ScanEndpoint, ruleSet []rules.Rule) []Decision {
	rulesSorted := append([]rules.Rule(nil), ruleSet...)
	sort.Slice(rulesSorted, func(i, j int) bool {
		return rulesSorted[i].ID < rulesSorted[j].ID
	})
	out := make([]Decision, 0, len(rulesSorted))
	for _, r := range rulesSorted {
		fam := familyOf(r)
		if fam == "" {
			continue
		}
		d := Decision{RuleID: r.ID, V1Family: fam}
		d.Reasons, d.Eligible = evaluate(fam, r, ep)
		out = append(out, d)
	}
	return out
}

func familyOf(r rules.Rule) string {
	for _, m := range r.Mutations {
		switch m.Kind {
		case rules.MutationReplacePathParam, rules.MutationReplaceQueryParam:
			return "idor"
		case rules.MutationMergeJSONFields:
			return "mass_assignment"
		case rules.MutationPathNormalizationVariant:
			return "path_normalization"
		case rules.MutationRotateRequestHeaders:
			return "rate_limit_headers"
		}
	}
	return ""
}

func evaluate(fam string, r rules.Rule, ep engine.ScanEndpoint) (reasons []string, ok bool) {
	methodOK := methodAllowed(ep.Method, r.Target.Methods)
	if !methodOK {
		return []string{"method_not_allowed_for_rule"}, false
	}
	where := strings.ToLower(strings.TrimSpace(r.Target.Where))

	switch fam {
	case "idor":
		var needsPath, needsQuery bool
		for _, m := range r.Mutations {
			switch m.Kind {
			case rules.MutationReplacePathParam:
				needsPath = true
			case rules.MutationReplaceQueryParam:
				needsQuery = true
			}
		}
		if !needsPath && !needsQuery {
			return []string{"no_idor_mutation"}, false
		}
		if needsPath {
			if !strings.Contains(ep.PathTemplate, "{") {
				return []string{"path_has_no_template_parameters"}, false
			}
			if !strings.Contains(where, "path") {
				return []string{"target_where_does_not_cover_path_params"}, false
			}
		}
		if needsQuery && !strings.Contains(where, "query") {
			return []string{"target_where_does_not_cover_query"}, false
		}
	case "mass_assignment":
		if ep.Method != "POST" && ep.Method != "PUT" && ep.Method != "PATCH" {
			return []string{"http_method_does_not_support_body_mutation"}, false
		}
		if !ep.RequestBodyJSON {
			return []string{"endpoint_has_no_json_request_body"}, false
		}
		if !strings.Contains(where, "json") && !strings.Contains(where, "body") {
			return []string{"target_where_does_not_cover_json_body"}, false
		}
	case "path_normalization":
		if strings.TrimSpace(ep.PathTemplate) == "" {
			return []string{"empty_path"}, false
		}
	case "rate_limit_headers":
		if ep.Method != "GET" && ep.Method != "POST" {
			return []string{"method_not_supported_for_header_rotation_baseline"}, false
		}
	}

	if needsAuthzPrereq(r) && len(ep.SecuritySchemeHints) == 0 {
		return []string{"authenticated_session_prerequisite_not_met"}, false
	}

	return []string{"eligible_for_v1_family_" + fam}, true
}

func methodAllowed(have string, want []string) bool {
	h := strings.ToUpper(strings.TrimSpace(have))
	for _, m := range want {
		if strings.ToUpper(strings.TrimSpace(m)) == h {
			return true
		}
	}
	return false
}

func needsAuthzPrereq(r rules.Rule) bool {
	for _, p := range r.Prerequisites {
		if strings.EqualFold(strings.TrimSpace(p), "authenticated_session") {
			return true
		}
	}
	return false
}
