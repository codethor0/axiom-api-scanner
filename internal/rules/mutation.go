package rules

import (
	"encoding/json"
	"fmt"
	"strings"
)

// MutationKind identifies a supported mutation strategy for V1 rules.
type MutationKind string

const (
	MutationReplacePathParam         MutationKind = "replace_path_param"
	MutationReplaceQueryParam        MutationKind = "replace_query_param"
	MutationMergeJSONFields          MutationKind = "merge_json_fields"
	MutationPathNormalizationVariant MutationKind = "path_normalization_variant"
	MutationRotateRequestHeaders     MutationKind = "rotate_request_headers"
)

// ReplacePathParamMutation swaps a path parameter value (IDOR-style probes).
type ReplacePathParamMutation struct {
	Param string `json:"param" yaml:"param"`
	From  string `json:"from" yaml:"from"`
	To    string `json:"to" yaml:"to"`
}

// ReplaceQueryParamMutation swaps a query parameter value.
type ReplaceQueryParamMutation struct {
	Param string `json:"param" yaml:"param"`
	From  string `json:"from" yaml:"from"`
	To    string `json:"to" yaml:"to"`
}

// PathNormalizationMutation rewrites the path to probe normalization bypasses.
type PathNormalizationMutation struct {
	Style string `json:"style" yaml:"style"`
}

// MergeJSONFieldsMutation merges privileged fields into a JSON body (mass assignment probes).
type MergeJSONFieldsMutation struct {
	Fields map[string]any `json:"fields" yaml:"fields"`
}

// RotateRequestHeadersMutation replaces or adds headers (rate-limit rotation probes).
type RotateRequestHeadersMutation struct {
	Headers []HeaderPair `json:"headers" yaml:"headers"`
}

// HeaderPair is a single header replacement entry.
type HeaderPair struct {
	Name  string `json:"name" yaml:"name"`
	Value string `json:"value" yaml:"value"`
}

// Mutation is a discriminated union validated per kind.
type Mutation struct {
	Kind                     MutationKind                  `json:"kind" yaml:"kind"`
	ReplacePathParam         *ReplacePathParamMutation     `json:"-" yaml:"-"`
	ReplaceQueryParam        *ReplaceQueryParamMutation    `json:"-" yaml:"-"`
	MergeJSONFields          *MergeJSONFieldsMutation      `json:"-" yaml:"-"`
	PathNormalizationVariant *PathNormalizationMutation    `json:"-" yaml:"-"`
	RotateRequestHeaders     *RotateRequestHeadersMutation `json:"-" yaml:"-"`
}

// MarshalJSON flattens kind-specific fields for stable API output.
func (m Mutation) MarshalJSON() ([]byte, error) {
	out := map[string]any{"kind": string(m.Kind)}
	switch m.Kind {
	case MutationReplacePathParam:
		if m.ReplacePathParam != nil {
			out["param"] = m.ReplacePathParam.Param
			out["from"] = m.ReplacePathParam.From
			out["to"] = m.ReplacePathParam.To
		}
	case MutationReplaceQueryParam:
		if m.ReplaceQueryParam != nil {
			out["param"] = m.ReplaceQueryParam.Param
			out["from"] = m.ReplaceQueryParam.From
			out["to"] = m.ReplaceQueryParam.To
		}
	case MutationPathNormalizationVariant:
		if m.PathNormalizationVariant != nil {
			out["style"] = m.PathNormalizationVariant.Style
		}
	case MutationMergeJSONFields:
		if m.MergeJSONFields != nil {
			out["fields"] = m.MergeJSONFields.Fields
		}
	case MutationRotateRequestHeaders:
		if m.RotateRequestHeaders != nil {
			b, err := json.Marshal(m.RotateRequestHeaders.Headers)
			if err != nil {
				return nil, err
			}
			var hdrs any
			if err := json.Unmarshal(b, &hdrs); err != nil {
				return nil, err
			}
			out["headers"] = hdrs
		}
	}
	return json.Marshal(out)
}

// ParseMutationFromMap builds a typed Mutation from a raw YAML/JSON map.
func ParseMutationFromMap(m map[string]any) (Mutation, error) {
	kindStr, ok := m["kind"].(string)
	if !ok || strings.TrimSpace(kindStr) == "" {
		return Mutation{}, fmt.Errorf("mutation: kind must be a non-empty string")
	}
	kind := MutationKind(kindStr)
	switch kind {
	case MutationReplacePathParam:
		p := replacePathFromMap(m)
		mu := Mutation{Kind: kind, ReplacePathParam: &p}
		return mu, mu.Validate()
	case MutationReplaceQueryParam:
		p := replaceQueryFromMap(m)
		mu := Mutation{Kind: kind, ReplaceQueryParam: &p}
		return mu, mu.Validate()
	case MutationMergeJSONFields:
		fields, err := fieldsFromMap(m)
		if err != nil {
			return Mutation{}, err
		}
		mu := Mutation{Kind: kind, MergeJSONFields: &MergeJSONFieldsMutation{Fields: fields}}
		return mu, mu.Validate()
	case MutationPathNormalizationVariant:
		style, _ := m["style"].(string)
		mu := Mutation{Kind: kind, PathNormalizationVariant: &PathNormalizationMutation{Style: strings.TrimSpace(style)}}
		return mu, mu.Validate()
	case MutationRotateRequestHeaders:
		headers, err := headersFromMap(m)
		if err != nil {
			return Mutation{}, err
		}
		mu := Mutation{Kind: kind, RotateRequestHeaders: &RotateRequestHeadersMutation{Headers: headers}}
		return mu, mu.Validate()
	default:
		return Mutation{}, fmt.Errorf("mutation: unknown kind %q (see supported kinds in docs/rule-authoring.md#v1-mutation-kinds)", kind)
	}
}

func replacePathFromMap(m map[string]any) ReplacePathParamMutation {
	return ReplacePathParamMutation{
		Param: stringField(m, "param"),
		From:  stringField(m, "from"),
		To:    stringField(m, "to"),
	}
}

func replaceQueryFromMap(m map[string]any) ReplaceQueryParamMutation {
	return ReplaceQueryParamMutation{
		Param: stringField(m, "param"),
		From:  stringField(m, "from"),
		To:    stringField(m, "to"),
	}
}

func stringField(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	default:
		return strings.TrimSpace(fmt.Sprint(t))
	}
}

func fieldsFromMap(m map[string]any) (map[string]any, error) {
	raw, ok := m["fields"]
	if !ok || raw == nil {
		return nil, fmt.Errorf("mutation merge_json_fields: fields is required")
	}
	fields, ok := raw.(map[string]any)
	if !ok || len(fields) == 0 {
		return nil, fmt.Errorf("mutation merge_json_fields: fields must be a non-empty object")
	}
	return fields, nil
}

func headersFromMap(m map[string]any) ([]HeaderPair, error) {
	raw, ok := m["headers"]
	if !ok || raw == nil {
		return nil, fmt.Errorf("mutation rotate_request_headers: headers is required")
	}
	list, ok := raw.([]any)
	if !ok || len(list) == 0 {
		return nil, fmt.Errorf("mutation rotate_request_headers: headers must be a non-empty array")
	}
	out := make([]HeaderPair, 0, len(list))
	for i, item := range list {
		row, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("mutation rotate_request_headers: headers[%d] must be an object", i)
		}
		name := stringField(row, "name")
		if name == "" {
			return nil, fmt.Errorf("mutation rotate_request_headers: headers[%d].name is required", i)
		}
		out = append(out, HeaderPair{Name: name, Value: stringField(row, "value")})
	}
	return out, nil
}

// Validate enforces required fields for the mutation kind.
func (m Mutation) Validate() error {
	switch m.Kind {
	case MutationReplacePathParam:
		if m.ReplacePathParam == nil {
			return fmt.Errorf("mutation replace_path_param: payload missing")
		}
		p := m.ReplacePathParam
		if strings.TrimSpace(p.Param) == "" || strings.TrimSpace(p.From) == "" || strings.TrimSpace(p.To) == "" {
			return fmt.Errorf("mutation replace_path_param: param, from, and to are required")
		}
	case MutationReplaceQueryParam:
		if m.ReplaceQueryParam == nil {
			return fmt.Errorf("mutation replace_query_param: payload missing")
		}
		p := m.ReplaceQueryParam
		if strings.TrimSpace(p.Param) == "" || strings.TrimSpace(p.From) == "" || strings.TrimSpace(p.To) == "" {
			return fmt.Errorf("mutation replace_query_param: param, from, and to are required")
		}
	case MutationMergeJSONFields:
		if m.MergeJSONFields == nil || len(m.MergeJSONFields.Fields) == 0 {
			return fmt.Errorf("mutation merge_json_fields: fields must be non-empty")
		}
	case MutationPathNormalizationVariant:
		if m.PathNormalizationVariant == nil {
			return fmt.Errorf("mutation path_normalization_variant: payload missing")
		}
		st := strings.TrimSpace(m.PathNormalizationVariant.Style)
		switch st {
		case "trailing_slash", "double_slash", "dot_segment", "case_variant", "encoded_slash":
			return nil
		default:
			return fmt.Errorf("mutation path_normalization_variant: unsupported style %q", st)
		}
	case MutationRotateRequestHeaders:
		if m.RotateRequestHeaders == nil || len(m.RotateRequestHeaders.Headers) == 0 {
			return fmt.Errorf("mutation rotate_request_headers: headers required")
		}
	default:
		return fmt.Errorf("mutation: unknown kind %q", m.Kind)
	}
	return nil
}
