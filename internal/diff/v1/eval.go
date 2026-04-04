package v1

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
	"github.com/codethor0/axiom-api-scanner/internal/rules"
)

// Result is the outcome of evaluating all matchers in a rule (AND semantics).
type Result struct {
	Pass       bool     `json:"pass"`
	Incomplete bool     `json:"incomplete"`
	Reasons    []string `json:"reasons"`
}

// MatcherOutcome is one matcher evaluation with a concise human/machine summary line.
type MatcherOutcome struct {
	Index   int    `json:"index"`
	Kind    string `json:"kind"`
	Passed  bool   `json:"passed"`
	Summary string `json:"summary"`
}

// EvalWithOutcomes is Result plus per-matcher rows for evidence summaries.
type EvalWithOutcomes struct {
	Result
	Outcomes []MatcherOutcome `json:"outcomes"`
}

// EvaluateRuleMatchers requires baseline and mutated records for the same scan and endpoint.
func EvaluateRuleMatchers(rule rules.Rule, baseline, mutated engine.ExecutionRecord) Result {
	w := EvaluateRuleMatchersWithOutcomes(rule, baseline, mutated)
	return w.Result
}

// EvaluateRuleMatchersWithOutcomes evaluates matchers and collects MatcherOutcome rows.
func EvaluateRuleMatchersWithOutcomes(rule rules.Rule, baseline, mutated engine.ExecutionRecord) EvalWithOutcomes {
	if baseline.ScanID != mutated.ScanID {
		return EvalWithOutcomes{
			Result: Result{Incomplete: true, Reasons: []string{"scan_id_mismatch"}},
		}
	}
	if baseline.ScanEndpointID != mutated.ScanEndpointID {
		return EvalWithOutcomes{
			Result: Result{Incomplete: true, Reasons: []string{"endpoint_id_mismatch"}},
		}
	}
	var reasons []string
	var outcomes []MatcherOutcome
	for i, m := range rule.Matchers {
		pass, inc, r, note := evalOne(m, baseline, mutated)
		reasons = append(reasons, r...)
		outcomes = append(outcomes, MatcherOutcome{
			Index: i, Kind: string(m.Kind), Passed: pass && !inc, Summary: note,
		})
		if inc {
			return EvalWithOutcomes{
				Result:   Result{Pass: false, Incomplete: true, Reasons: reasons},
				Outcomes: outcomes,
			}
		}
		if !pass {
			reasons = append(reasons, fmt.Sprintf("matcher_%d_failed:%s", i, m.Kind))
			return EvalWithOutcomes{
				Result:   Result{Pass: false, Incomplete: false, Reasons: reasons},
				Outcomes: outcomes,
			}
		}
	}
	return EvalWithOutcomes{
		Result:   Result{Pass: true, Incomplete: false, Reasons: reasons},
		Outcomes: outcomes,
	}
}

func evalOne(m rules.Matcher, b, u engine.ExecutionRecord) (pass bool, incomplete bool, reasons []string, summary string) {
	switch m.Kind {
	case rules.MatcherStatusCodeUnchanged:
		ok := b.ResponseStatus == u.ResponseStatus
		return ok, false, nil, fmt.Sprintf("http_status baseline=%d mutated=%d same=%v", b.ResponseStatus, u.ResponseStatus, ok)
	case rules.MatcherStatusDiffersFromBaseline:
		ok := b.ResponseStatus != u.ResponseStatus
		return ok, false, nil, fmt.Sprintf("http_status baseline=%d mutated=%d differs=%v", b.ResponseStatus, u.ResponseStatus, ok)
	case rules.MatcherStatusIn:
		if m.StatusIn == nil {
			return false, true, []string{"status_in_missing_payload"}, "status_in: missing payload"
		}
		for _, c := range m.StatusIn.Allowed {
			if u.ResponseStatus == c {
				return true, false, nil, fmt.Sprintf("http_status mutated=%d in_allowed=%v", u.ResponseStatus, m.StatusIn.Allowed)
			}
		}
		return false, false, nil, fmt.Sprintf("http_status mutated=%d not_in_allowed=%v", u.ResponseStatus, m.StatusIn.Allowed)
	case rules.MatcherResponseBodySimilarity:
		if m.ResponseBodySimilarity == nil {
			return false, true, []string{"similarity_missing_payload"}, "similarity: missing payload"
		}
		s := diceCoefficient(b.ResponseBody, u.ResponseBody)
		min := m.ResponseBodySimilarity.MinScore
		ok := s >= min
		return ok, false, nil, fmt.Sprintf("body_similarity score=%.4f min=%.4f pass=%v", s, min, ok)
	case rules.MatcherResponseBodySubstring:
		if m.ResponseBodySubstring == nil {
			return false, true, nil, "substring: missing payload"
		}
		ok := strings.Contains(u.ResponseBody, m.ResponseBodySubstring.Substring)
		return ok, false, nil, fmt.Sprintf("body_contains substring=%q pass=%v", m.ResponseBodySubstring.Substring, ok)
	case rules.MatcherJSONPathAbsent:
		if m.JSONPathAbsent == nil {
			return false, true, nil, "json_path_absent: missing payload"
		}
		ok, inc, err := jsonPathAbsent(u.ResponseBody, m.JSONPathAbsent.Path)
		if err != nil {
			return false, true, []string{"json_path_absent_parse_error"}, "json_path_absent: parse error"
		}
		if inc {
			return false, true, nil, fmt.Sprintf("json_path_absent path=%q incomplete=true", m.JSONPathAbsent.Path)
		}
		return ok, false, nil, fmt.Sprintf("json_path_absent path=%q absent=%v", m.JSONPathAbsent.Path, ok)
	case rules.MatcherJSONPathEquals:
		if m.JSONPathEquals == nil {
			return false, true, nil, "json_path_equals: missing payload"
		}
		ok, inc, err := jsonPathEquals(u.ResponseBody, m.JSONPathEquals.Path, m.JSONPathEquals.Value)
		if err != nil {
			return false, true, []string{"json_path_equals_parse_error"}, "json_path_equals: parse error"
		}
		if inc {
			return false, true, nil, fmt.Sprintf("json_path_equals path=%q incomplete=true", m.JSONPathEquals.Path)
		}
		return ok, false, nil, fmt.Sprintf("json_path_equals path=%q equals_value=%v", m.JSONPathEquals.Path, ok)
	case rules.MatcherHeaderPresent:
		if m.HeaderPresent == nil {
			return false, true, nil, "header_present: missing payload"
		}
		name := http.CanonicalHeaderKey(m.HeaderPresent.Name)
		_, ok := u.ResponseHeaders[name]
		return ok, false, nil, fmt.Sprintf("header_present name=%q pass=%v", name, ok)
	case rules.MatcherHeaderAbsent:
		if m.HeaderAbsent == nil {
			return false, true, nil, "header_absent: missing payload"
		}
		name := http.CanonicalHeaderKey(m.HeaderAbsent.Name)
		_, ok := u.ResponseHeaders[name]
		return !ok, false, nil, fmt.Sprintf("header_absent name=%q pass=%v", name, !ok)
	case rules.MatcherResponseHeaderDiffersFromBaseline:
		if m.ResponseHeaderDiffersFromBaseline == nil {
			return false, true, nil, "response_header_differs: missing payload"
		}
		name := http.CanonicalHeaderKey(m.ResponseHeaderDiffersFromBaseline.Name)
		bv := b.ResponseHeaders[name]
		uv := u.ResponseHeaders[name]
		ok := bv != uv
		return ok, false, nil, fmt.Sprintf("header_differs name=%q baseline=%q mutated=%q pass=%v", name, bv, uv, ok)
	default:
		return false, true, []string{"unsupported_matcher_kind:" + string(m.Kind)}, "unsupported matcher"
	}
}

func diceCoefficient(a, b string) float64 {
	if a == "" && b == "" {
		return 1
	}
	if a == "" || b == "" {
		return 0
	}
	if len(a) == 1 && len(b) == 1 {
		if a == b {
			return 1
		}
		return 0
	}
	bgA := bigrams(a)
	bgB := bigrams(b)
	if len(bgA) == 0 || len(bgB) == 0 {
		if a == b {
			return 1
		}
		return 0
	}
	inter := 0
	for s := range bgA {
		if bgB[s] {
			inter++
		}
	}
	return float64(2*inter) / float64(len(bgA)+len(bgB))
}

func bigrams(s string) map[string]bool {
	out := make(map[string]bool)
	r := []rune(s)
	if len(r) < 2 {
		return out
	}
	for i := 0; i < len(r)-1; i++ {
		out[string(r[i:i+2])] = true
	}
	return out
}

func jsonPathTokens(path string) []string {
	path = strings.TrimSpace(path)
	path = strings.TrimPrefix(path, "$.")
	path = strings.TrimPrefix(path, "$")
	path = strings.TrimPrefix(path, ".")
	if path == "" {
		return nil
	}
	parts := strings.Split(path, ".")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func jsonPathAbsent(rawJSON, path string) (absent bool, incomplete bool, err error) {
	toks := jsonPathTokens(path)
	if len(toks) == 0 {
		return false, true, nil
	}
	var root any
	if err := json.Unmarshal([]byte(rawJSON), &root); err != nil {
		return false, true, err
	}
	cur := root
	for i, tok := range toks {
		m, ok := cur.(map[string]any)
		if !ok {
			return true, false, nil
		}
		v, ok := m[tok]
		if !ok {
			return true, false, nil
		}
		if i == len(toks)-1 {
			return false, false, nil
		}
		cur = v
	}
	return false, false, nil
}

func jsonPathEquals(rawJSON, path, want string) (ok bool, incomplete bool, err error) {
	toks := jsonPathTokens(path)
	if len(toks) == 0 {
		return false, true, nil
	}
	var root any
	if err := json.Unmarshal([]byte(rawJSON), &root); err != nil {
		return false, true, err
	}
	cur := root
	for i, tok := range toks {
		m, ok := cur.(map[string]any)
		if !ok {
			return false, false, nil
		}
		v, ok := m[tok]
		if !ok {
			return false, false, nil
		}
		if i == len(toks)-1 {
			return jsonValueMatches(v, want), false, nil
		}
		cur = v
	}
	return false, false, nil
}

func jsonValueMatches(v any, want string) bool {
	b, err := json.Marshal(v)
	if err != nil {
		return false
	}
	got := strings.TrimSpace(string(b))
	want = strings.TrimSpace(want)
	if got == want {
		return true
	}
	if s, ok := v.(string); ok && strings.TrimSpace(s) == want {
		return true
	}
	f, ok := v.(float64)
	if ok && fmt.Sprint(f) == want {
		return true
	}
	return false
}
