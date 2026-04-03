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

// EvaluateRuleMatchers requires baseline and mutated records for the same scan and endpoint.
func EvaluateRuleMatchers(rule rules.Rule, baseline, mutated engine.ExecutionRecord) Result {
	if baseline.ScanID != mutated.ScanID {
		return Result{Incomplete: true, Reasons: []string{"scan_id_mismatch"}}
	}
	if baseline.ScanEndpointID != mutated.ScanEndpointID {
		return Result{Incomplete: true, Reasons: []string{"endpoint_id_mismatch"}}
	}
	var reasons []string
	for i, m := range rule.Matchers {
		pass, inc, r := evalOne(m, baseline, mutated)
		reasons = append(reasons, r...)
		if inc {
			return Result{Pass: false, Incomplete: true, Reasons: reasons}
		}
		if !pass {
			reasons = append(reasons, fmt.Sprintf("matcher_%d_failed:%s", i, m.Kind))
			return Result{Pass: false, Incomplete: false, Reasons: reasons}
		}
	}
	return Result{Pass: true, Incomplete: false, Reasons: reasons}
}

func evalOne(m rules.Matcher, b, u engine.ExecutionRecord) (pass bool, incomplete bool, reasons []string) {
	switch m.Kind {
	case rules.MatcherStatusCodeUnchanged:
		return b.ResponseStatus == u.ResponseStatus, false, nil
	case rules.MatcherStatusDiffersFromBaseline:
		return b.ResponseStatus != u.ResponseStatus, false, nil
	case rules.MatcherStatusIn:
		if m.StatusIn == nil {
			return false, true, []string{"status_in_missing_payload"}
		}
		for _, c := range m.StatusIn.Allowed {
			if u.ResponseStatus == c {
				return true, false, nil
			}
		}
		return false, false, nil
	case rules.MatcherResponseBodySimilarity:
		if m.ResponseBodySimilarity == nil {
			return false, true, []string{"similarity_missing_payload"}
		}
		s := diceCoefficient(b.ResponseBody, u.ResponseBody)
		return s >= m.ResponseBodySimilarity.MinScore, false, nil
	case rules.MatcherResponseBodySubstring:
		if m.ResponseBodySubstring == nil {
			return false, true, nil
		}
		return strings.Contains(u.ResponseBody, m.ResponseBodySubstring.Substring), false, nil
	case rules.MatcherJSONPathAbsent:
		if m.JSONPathAbsent == nil {
			return false, true, nil
		}
		ok, inc, err := jsonPathAbsent(u.ResponseBody, m.JSONPathAbsent.Path)
		if err != nil {
			return false, true, []string{"json_path_absent_parse_error"}
		}
		return ok, inc, nil
	case rules.MatcherJSONPathEquals:
		if m.JSONPathEquals == nil {
			return false, true, nil
		}
		ok, inc, err := jsonPathEquals(u.ResponseBody, m.JSONPathEquals.Path, m.JSONPathEquals.Value)
		if err != nil {
			return false, true, []string{"json_path_equals_parse_error"}
		}
		return ok, inc, nil
	case rules.MatcherHeaderPresent:
		if m.HeaderPresent == nil {
			return false, true, nil
		}
		_, ok := u.ResponseHeaders[http.CanonicalHeaderKey(m.HeaderPresent.Name)]
		return ok, false, nil
	case rules.MatcherHeaderAbsent:
		if m.HeaderAbsent == nil {
			return false, true, nil
		}
		_, ok := u.ResponseHeaders[http.CanonicalHeaderKey(m.HeaderAbsent.Name)]
		return !ok, false, nil
	case rules.MatcherResponseHeaderDiffersFromBaseline:
		if m.ResponseHeaderDiffersFromBaseline == nil {
			return false, true, nil
		}
		name := http.CanonicalHeaderKey(m.ResponseHeaderDiffersFromBaseline.Name)
		bv := b.ResponseHeaders[name]
		uv := u.ResponseHeaders[name]
		if bv == uv {
			return false, false, nil
		}
		return true, false, nil
	default:
		return false, true, []string{"unsupported_matcher_kind:" + string(m.Kind)}
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
