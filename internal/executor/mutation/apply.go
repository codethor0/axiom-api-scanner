package mutation

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
	"github.com/codethor0/axiom-api-scanner/internal/executil"
	"github.com/codethor0/axiom-api-scanner/internal/mutate"
	"github.com/codethor0/axiom-api-scanner/internal/pathutil"
	"github.com/codethor0/axiom-api-scanner/internal/rules"
)

// BuiltRequest is an HTTP request description without side effects.
type BuiltRequest struct {
	Method      string
	URL         string
	Body        string
	ExtraHeader map[string]string
}

// BuildRequest materializes one mutated request from a candidate and rule mutation payload.
func BuildRequest(baseStr string, ep engine.ScanEndpoint, rule rules.Rule, cand mutate.Candidate) (BuiltRequest, error) {
	if cand.MutationIndex < 0 || cand.MutationIndex >= len(rule.Mutations) {
		return BuiltRequest{}, fmt.Errorf("mutation_index out of range")
	}
	m := rule.Mutations[cand.MutationIndex]
	path := pathutil.FillPathTemplate(ep.PathTemplate)
	extra := map[string]string{}

	switch m.Kind {
	case rules.MutationReplacePathParam:
		p := m.ReplacePathParam
		needle := pathutil.PlaceholderForParam(p.Param)
		if !strings.Contains(path, needle) {
			return BuiltRequest{}, fmt.Errorf("path has no placeholder for param %q", p.Param)
		}
		path = strings.Replace(path, needle, url.PathEscape(p.To), 1)
	case rules.MutationReplaceQueryParam:
		p := m.ReplaceQueryParam
		// Path only here; query applied after join.
		_ = p
	case rules.MutationMergeJSONFields:
		if ep.Method != "POST" && ep.Method != "PUT" && ep.Method != "PATCH" {
			return BuiltRequest{}, fmt.Errorf("merge_json_fields requires POST/PUT/PATCH")
		}
	case rules.MutationPathNormalizationVariant:
		path = applyPathNormalization(m.PathNormalizationVariant.Style, path)
	case rules.MutationRotateRequestHeaders:
		for _, h := range m.RotateRequestHeaders.Headers {
			extra[h.Name] = h.Value
		}
	default:
		return BuiltRequest{}, fmt.Errorf("unsupported mutation kind %q", m.Kind)
	}

	joined := executil.JoinRawBaseURLToPath(baseStr, path)
	var full string
	if m.Kind == rules.MutationReplaceQueryParam {
		u, err := url.Parse(joined)
		if err != nil {
			return BuiltRequest{}, err
		}
		p := m.ReplaceQueryParam
		q := u.Query()
		q.Set(p.Param, p.To)
		u.RawQuery = q.Encode()
		full = u.String()
	} else {
		full = joined
	}

	method := strings.ToUpper(strings.TrimSpace(ep.Method))
	body := ""
	if method == "POST" {
		body = "{}"
		if m.Kind == rules.MutationMergeJSONFields {
			var obj map[string]any
			_ = json.Unmarshal([]byte(body), &obj)
			for k, v := range m.MergeJSONFields.Fields {
				obj[k] = v
			}
			buf, err := json.Marshal(obj)
			if err != nil {
				return BuiltRequest{}, err
			}
			body = string(buf)
		}
	}

	return BuiltRequest{Method: method, URL: full, Body: body, ExtraHeader: extra}, nil
}

func applyPathNormalization(style, path string) string {
	path = "/" + strings.TrimPrefix(path, "/")
	switch style {
	case "trailing_slash":
		if !strings.HasSuffix(path, "/") {
			return path + "/"
		}
		return path
	case "double_slash":
		if len(path) > 1 {
			i := strings.Index(path[1:], "/")
			if i >= 0 {
				at := i + 1
				return path[:at] + "/" + path[at:]
			}
		}
		return path + "//"
	case "dot_segment":
		if len(path) > 1 {
			return path[:1] + "./" + path[1:]
		}
		return "/./"
	case "case_variant":
		r := []rune(path)
		for i, ch := range r {
			if ch >= 'a' && ch <= 'z' {
				r[i] = ch - ('a' - 'A')
				break
			}
			if ch >= 'A' && ch <= 'Z' {
				r[i] = ch + ('a' - 'A')
				break
			}
		}
		return string(r)
	case "encoded_slash":
		return strings.ReplaceAll(path, "/", "%2F")
	default:
		return path
	}
}
