package rules

import (
	"encoding/json"
	"fmt"
	"strings"
)

// MatcherKind identifies a supported response matcher for V1 rules.
type MatcherKind string

const (
	MatcherStatusCodeUnchanged    MatcherKind = "status_code_unchanged"
	MatcherResponseBodySimilarity MatcherKind = "response_body_similarity"
	MatcherJSONPathAbsent         MatcherKind = "json_path_absent"
	MatcherStatusIn               MatcherKind = "status_in"
	MatcherHeaderPresent          MatcherKind = "header_present"
	MatcherHeaderAbsent           MatcherKind = "header_absent"
	MatcherStatusDiffersFromBaseline            MatcherKind = "status_differs_from_baseline"
	MatcherResponseBodySubstring               MatcherKind = "response_body_substring"
	MatcherJSONPathEquals                      MatcherKind = "json_path_equals"
	MatcherResponseHeaderDiffersFromBaseline   MatcherKind = "response_header_differs_from_baseline"
)

// ResponseBodySimilarityMatcher compares normalized bodies with a minimum score.
type ResponseBodySimilarityMatcher struct {
	MinScore float64 `json:"min_score" yaml:"min_score"`
}

// JSONPathAbsentMatcher asserts a JSONPath is absent from the body.
type JSONPathAbsentMatcher struct {
	Path string `json:"path" yaml:"path"`
}

// StatusInMatcher asserts the HTTP status is one of the listed codes.
type StatusInMatcher struct {
	Allowed []int `json:"allowed" yaml:"allowed"`
}

// HeaderPresentMatcher asserts a response header exists.
type HeaderPresentMatcher struct {
	Name string `json:"name" yaml:"name"`
}

// HeaderAbsentMatcher asserts a response header is missing.
type HeaderAbsentMatcher struct {
	Name string `json:"name" yaml:"name"`
}

// ResponseBodySubstringMatcher checks the normalized mutated body for a literal substring.
type ResponseBodySubstringMatcher struct {
	Substring string `json:"substring" yaml:"substring"`
}

// JSONPathEqualsMatcher checks a JSON value at a simple dot path (objects only in V1).
type JSONPathEqualsMatcher struct {
	Path  string `json:"path" yaml:"path"`
	Value string `json:"value" yaml:"value"`
}

// ResponseHeaderDiffersFromBaselineMatcher checks baseline vs mutated header values differ.
type ResponseHeaderDiffersFromBaselineMatcher struct {
	Name string `json:"name" yaml:"name"`
}

// Matcher is a discriminated union validated per kind.
type Matcher struct {
	Kind                   MatcherKind                    `json:"kind" yaml:"kind"`
	ResponseBodySimilarity *ResponseBodySimilarityMatcher `json:"-" yaml:"-"`
	JSONPathAbsent         *JSONPathAbsentMatcher         `json:"-" yaml:"-"`
	StatusIn               *StatusInMatcher               `json:"-" yaml:"-"`
	HeaderPresent          *HeaderPresentMatcher          `json:"-" yaml:"-"`
	HeaderAbsent           *HeaderAbsentMatcher           `json:"-" yaml:"-"`
	ResponseBodySubstring  *ResponseBodySubstringMatcher  `json:"-" yaml:"-"`
	JSONPathEquals         *JSONPathEqualsMatcher         `json:"-" yaml:"-"`
	ResponseHeaderDiffersFromBaseline *ResponseHeaderDiffersFromBaselineMatcher `json:"-" yaml:"-"`
}

// MarshalJSON flattens matcher fields for API output.
func (m Matcher) MarshalJSON() ([]byte, error) {
	out := map[string]any{"kind": string(m.Kind)}
	switch m.Kind {
	case MatcherResponseBodySimilarity:
		if m.ResponseBodySimilarity != nil {
			out["min_score"] = m.ResponseBodySimilarity.MinScore
		}
	case MatcherJSONPathAbsent:
		if m.JSONPathAbsent != nil {
			out["path"] = m.JSONPathAbsent.Path
		}
	case MatcherStatusIn:
		if m.StatusIn != nil {
			out["allowed"] = m.StatusIn.Allowed
		}
	case MatcherHeaderPresent:
		if m.HeaderPresent != nil {
			out["name"] = m.HeaderPresent.Name
		}
	case MatcherHeaderAbsent:
		if m.HeaderAbsent != nil {
			out["name"] = m.HeaderAbsent.Name
		}
	case MatcherResponseBodySubstring:
		if m.ResponseBodySubstring != nil {
			out["substring"] = m.ResponseBodySubstring.Substring
		}
	case MatcherJSONPathEquals:
		if m.JSONPathEquals != nil {
			out["path"] = m.JSONPathEquals.Path
			out["value"] = m.JSONPathEquals.Value
		}
	case MatcherResponseHeaderDiffersFromBaseline:
		if m.ResponseHeaderDiffersFromBaseline != nil {
			out["name"] = m.ResponseHeaderDiffersFromBaseline.Name
		}
	}
	return json.Marshal(out)
}

// ParseMatcherFromMap builds a typed Matcher.
func ParseMatcherFromMap(m map[string]any) (Matcher, error) {
	kindStr, ok := m["kind"].(string)
	if !ok || strings.TrimSpace(kindStr) == "" {
		return Matcher{}, fmt.Errorf("matcher: kind must be a non-empty string")
	}
	kind := MatcherKind(kindStr)
	switch kind {
	case MatcherStatusCodeUnchanged:
		mat := Matcher{Kind: kind}
		return mat, mat.Validate()
	case MatcherResponseBodySimilarity:
		score, err := floatField(m, "min_score")
		if err != nil {
			return Matcher{}, err
		}
		mat := Matcher{Kind: kind, ResponseBodySimilarity: &ResponseBodySimilarityMatcher{MinScore: score}}
		return mat, mat.Validate()
	case MatcherJSONPathAbsent:
		mat := Matcher{Kind: kind, JSONPathAbsent: &JSONPathAbsentMatcher{Path: stringField(m, "path")}}
		return mat, mat.Validate()
	case MatcherStatusIn:
		allowed, err := intSliceField(m, "allowed")
		if err != nil {
			return Matcher{}, err
		}
		mat := Matcher{Kind: kind, StatusIn: &StatusInMatcher{Allowed: allowed}}
		return mat, mat.Validate()
	case MatcherHeaderPresent:
		mat := Matcher{Kind: kind, HeaderPresent: &HeaderPresentMatcher{Name: stringField(m, "name")}}
		return mat, mat.Validate()
	case MatcherHeaderAbsent:
		mat := Matcher{Kind: kind, HeaderAbsent: &HeaderAbsentMatcher{Name: stringField(m, "name")}}
		return mat, mat.Validate()
	case MatcherStatusDiffersFromBaseline:
		mat := Matcher{Kind: kind}
		return mat, mat.Validate()
	case MatcherResponseBodySubstring:
		mat := Matcher{Kind: kind, ResponseBodySubstring: &ResponseBodySubstringMatcher{Substring: stringField(m, "substring")}}
		return mat, mat.Validate()
	case MatcherJSONPathEquals:
		mat := Matcher{Kind: kind, JSONPathEquals: &JSONPathEqualsMatcher{
			Path:  stringField(m, "path"),
			Value: stringField(m, "value"),
		}}
		return mat, mat.Validate()
	case MatcherResponseHeaderDiffersFromBaseline:
		mat := Matcher{Kind: kind, ResponseHeaderDiffersFromBaseline: &ResponseHeaderDiffersFromBaselineMatcher{Name: stringField(m, "name")}}
		return mat, mat.Validate()
	default:
		return Matcher{}, fmt.Errorf("matcher: unknown kind %q", kind)
	}
}

func floatField(m map[string]any, key string) (float64, error) {
	v, ok := m[key]
	if !ok || v == nil {
		return 0, fmt.Errorf("matcher %s: %s is required", m["kind"], key)
	}
	switch t := v.(type) {
	case float64:
		return t, nil
	case int:
		return float64(t), nil
	case int64:
		return float64(t), nil
	default:
		return 0, fmt.Errorf("matcher %s: %s must be numeric", m["kind"], key)
	}
}

func intSliceField(m map[string]any, key string) ([]int, error) {
	v, ok := m[key]
	if !ok || v == nil {
		return nil, fmt.Errorf("matcher status_in: allowed is required")
	}
	list, ok := v.([]any)
	if !ok || len(list) == 0 {
		return nil, fmt.Errorf("matcher status_in: allowed must be a non-empty array")
	}
	out := make([]int, 0, len(list))
	for i, item := range list {
		switch t := item.(type) {
		case int:
			out = append(out, t)
		case int64:
			out = append(out, int(t))
		case float64:
			out = append(out, int(t))
		default:
			return nil, fmt.Errorf("matcher status_in: allowed[%d] must be an integer", i)
		}
	}
	return out, nil
}

// Validate checks matcher payloads.
func (m Matcher) Validate() error {
	switch m.Kind {
	case MatcherStatusCodeUnchanged:
		return nil
	case MatcherResponseBodySimilarity:
		if m.ResponseBodySimilarity == nil {
			return fmt.Errorf("matcher response_body_similarity: payload missing")
		}
		s := m.ResponseBodySimilarity.MinScore
		if s < 0 || s > 1 {
			return fmt.Errorf("matcher response_body_similarity: min_score must be between 0 and 1")
		}
	case MatcherJSONPathAbsent:
		if m.JSONPathAbsent == nil || strings.TrimSpace(m.JSONPathAbsent.Path) == "" {
			return fmt.Errorf("matcher json_path_absent: path is required")
		}
	case MatcherStatusIn:
		if m.StatusIn == nil || len(m.StatusIn.Allowed) == 0 {
			return fmt.Errorf("matcher status_in: allowed must be non-empty")
		}
	case MatcherHeaderPresent:
		if m.HeaderPresent == nil || strings.TrimSpace(m.HeaderPresent.Name) == "" {
			return fmt.Errorf("matcher header_present: name is required")
		}
	case MatcherHeaderAbsent:
		if m.HeaderAbsent == nil || strings.TrimSpace(m.HeaderAbsent.Name) == "" {
			return fmt.Errorf("matcher header_absent: name is required")
		}
	case MatcherStatusDiffersFromBaseline:
		return nil
	case MatcherResponseBodySubstring:
		if m.ResponseBodySubstring == nil || strings.TrimSpace(m.ResponseBodySubstring.Substring) == "" {
			return fmt.Errorf("matcher response_body_substring: substring is required")
		}
	case MatcherJSONPathEquals:
		if m.JSONPathEquals == nil || strings.TrimSpace(m.JSONPathEquals.Path) == "" {
			return fmt.Errorf("matcher json_path_equals: path is required")
		}
	case MatcherResponseHeaderDiffersFromBaseline:
		if m.ResponseHeaderDiffersFromBaseline == nil || strings.TrimSpace(m.ResponseHeaderDiffersFromBaseline.Name) == "" {
			return fmt.Errorf("matcher response_header_differs_from_baseline: name is required")
		}
	default:
		return fmt.Errorf("matcher: unknown kind %q", m.Kind)
	}
	return nil
}
