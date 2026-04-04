package api

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/codethor0/axiom-api-scanner/internal/findings"
	"github.com/codethor0/axiom-api-scanner/internal/storage"
	"github.com/google/uuid"
)

type parsedEndpointListParams struct {
	storageFilter    storage.EndpointListFilter
	includeSummary bool
}

func parseEndpointListParams(r *http.Request) (parsedEndpointListParams, *apiRequestError) {
	var out parsedEndpointListParams
	out.includeSummary = true
	if v := strings.TrimSpace(r.URL.Query().Get("include_summary")); v != "" {
		switch strings.ToLower(v) {
		case "true", "1", "yes":
			out.includeSummary = true
		case "false", "0", "no":
			out.includeSummary = false
		default:
			return parsedEndpointListParams{}, &apiRequestError{code: "invalid_query", message: "include_summary must be true or false"}
		}
	}
	if v := strings.TrimSpace(r.URL.Query().Get("method")); v != "" {
		out.storageFilter.Method = v
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("declares_security")); raw != "" {
		switch strings.ToLower(raw) {
		case "true":
			t := true
			out.storageFilter.DeclaresSecurity = &t
		case "false":
			f := false
			out.storageFilter.DeclaresSecurity = &f
		default:
			return parsedEndpointListParams{}, &apiRequestError{code: "invalid_query", message: "declares_security must be true or false"}
		}
	}
	return out, nil
}

func parseEndpointListPageParams(r *http.Request) (storage.EndpointListPageOptions, *apiRequestError) {
	q := r.URL.Query()
	if _, ok := q["offset"]; ok {
		return storage.EndpointListPageOptions{}, &apiRequestError{code: "unsupported_query_parameter", message: "offset is not supported; use cursor-based pagination"}
	}
	opts := storage.EndpointListPageOptions{
		SortField: storage.EndpointListSortPath,
		SortOrder: storage.ListSortAsc,
		Cursor:    strings.TrimSpace(q.Get("cursor")),
	}
	if v := strings.TrimSpace(q.Get("sort")); v != "" {
		switch v {
		case storage.EndpointListSortPath, storage.EndpointListSortMethod, storage.EndpointListSortCreatedAt:
			opts.SortField = v
		default:
			return storage.EndpointListPageOptions{}, &apiRequestError{code: "invalid_sort", message: "sort must be path, method, or created_at for endpoints"}
		}
	}
	if v := strings.TrimSpace(q.Get("order")); v != "" {
		switch strings.ToLower(v) {
		case storage.ListSortAsc, storage.ListSortDesc:
			opts.SortOrder = strings.ToLower(v)
		default:
			return storage.EndpointListPageOptions{}, &apiRequestError{code: "invalid_order", message: "order must be asc or desc"}
		}
	}
	ls := strings.TrimSpace(q.Get("limit"))
	if ls == "" {
		opts.Limit = storage.DefaultListLimit
	} else {
		n, err := strconv.Atoi(ls)
		if err != nil || n < 1 || n > storage.MaxListLimit {
			return storage.EndpointListPageOptions{}, &apiRequestError{code: "invalid_limit", message: "limit must be between 1 and 200"}
		}
		opts.Limit = n
	}
	return opts, nil
}

// parseFindingListFilters validates optional exact-match filters for the findings list.
func parseFindingListFilters(r *http.Request) (storage.FindingListFilter, *apiRequestError) {
	q := r.URL.Query()
	f := storage.FindingListFilter{
		AssessmentTier:         strings.TrimSpace(q.Get("assessment_tier")),
		Severity:               strings.TrimSpace(q.Get("severity")),
		RuleDeclaredConfidence: strings.TrimSpace(q.Get("rule_declared_confidence")),
		RuleID:                 strings.TrimSpace(q.Get("rule_id")),
	}
	if f.AssessmentTier != "" {
		switch f.AssessmentTier {
		case "confirmed", "tentative", "incomplete":
		default:
			return storage.FindingListFilter{}, &apiRequestError{code: "invalid_filter", message: "assessment_tier must be confirmed, tentative, or incomplete"}
		}
	}
	if f.Severity != "" {
		switch findings.Severity(f.Severity) {
		case findings.SeverityInfo, findings.SeverityLow, findings.SeverityMedium, findings.SeverityHigh, findings.SeverityCritical:
		default:
			return storage.FindingListFilter{}, &apiRequestError{code: "invalid_filter", message: "severity must be info, low, medium, high, or critical"}
		}
	}
	if f.RuleDeclaredConfidence != "" {
		switch f.RuleDeclaredConfidence {
		case "high", "medium", "low":
		default:
			return storage.FindingListFilter{}, &apiRequestError{code: "invalid_filter", message: "rule_declared_confidence must be high, medium, or low"}
		}
	}
	return f, nil
}

// parseExecutionListFilters validates list filters including phase, UUIDs, and response_status.
func parseExecutionListFilters(r *http.Request) (storage.ExecutionListFilter, *apiRequestError) {
	q := r.URL.Query()
	phase := strings.TrimSpace(q.Get("phase"))
	ek := strings.TrimSpace(q.Get("execution_kind"))
	if phase != "" && ek != "" && phase != ek {
		return storage.ExecutionListFilter{}, &apiRequestError{code: "invalid_filter", message: "phase and execution_kind must match when both are set"}
	}
	if phase == "" {
		phase = ek
	}
	if phase != "" && phase != "baseline" && phase != "mutated" {
		return storage.ExecutionListFilter{}, &apiRequestError{code: "invalid_filter", message: "phase must be baseline or mutated"}
	}
	filter := storage.ExecutionListFilter{
		Phase:          phase,
		ScanEndpointID: strings.TrimSpace(q.Get("scan_endpoint_id")),
		RuleID:         strings.TrimSpace(q.Get("rule_id")),
	}
	if filter.ScanEndpointID != "" {
		if _, err := uuid.Parse(filter.ScanEndpointID); err != nil {
			return storage.ExecutionListFilter{}, &apiRequestError{code: "invalid_filter", message: "scan_endpoint_id must be a UUID"}
		}
	}
	if _, present := q["response_status"]; present {
		rs := strings.TrimSpace(q.Get("response_status"))
		if rs == "" {
			return storage.ExecutionListFilter{}, &apiRequestError{code: "invalid_filter", message: "response_status must be an integer between 100 and 599"}
		}
		code, err := strconv.Atoi(rs)
		if err != nil || code < 100 || code > 599 {
			return storage.ExecutionListFilter{}, &apiRequestError{code: "invalid_filter", message: "response_status must be an integer between 100 and 599"}
		}
		filter.ResponseStatus = code
	}
	return filter, nil
}

func parseExecutionListPageParams(r *http.Request) (storage.ExecutionListPageOptions, *apiRequestError) {
	q := r.URL.Query()
	if _, ok := q["offset"]; ok {
		return storage.ExecutionListPageOptions{}, &apiRequestError{code: "unsupported_query_parameter", message: "offset is not supported; use cursor-based pagination"}
	}
	opts := storage.ExecutionListPageOptions{
		SortField: storage.ExecListSortCreatedAt,
		SortOrder: storage.ListSortAsc,
		Cursor:    strings.TrimSpace(q.Get("cursor")),
	}
	if v := strings.TrimSpace(q.Get("sort")); v != "" {
		switch v {
		case storage.ExecListSortCreatedAt, storage.ExecListSortPhase:
			opts.SortField = v
		default:
			return storage.ExecutionListPageOptions{}, &apiRequestError{code: "invalid_sort", message: "sort must be created_at or phase for executions"}
		}
	}
	if v := strings.TrimSpace(q.Get("order")); v != "" {
		switch strings.ToLower(v) {
		case storage.ListSortAsc, storage.ListSortDesc:
			opts.SortOrder = strings.ToLower(v)
		default:
			return storage.ExecutionListPageOptions{}, &apiRequestError{code: "invalid_order", message: "order must be asc or desc"}
		}
	}
	ls := strings.TrimSpace(q.Get("limit"))
	if ls == "" {
		opts.Limit = storage.DefaultListLimit
	} else {
		n, err := strconv.Atoi(ls)
		if err != nil || n < 1 || n > storage.MaxListLimit {
			return storage.ExecutionListPageOptions{}, &apiRequestError{code: "invalid_limit", message: "limit must be between 1 and 200"}
		}
		opts.Limit = n
	}
	return opts, nil
}

func parseFindingListPageParams(r *http.Request) (storage.FindingListPageOptions, *apiRequestError) {
	q := r.URL.Query()
	if _, ok := q["offset"]; ok {
		return storage.FindingListPageOptions{}, &apiRequestError{code: "unsupported_query_parameter", message: "offset is not supported; use cursor-based pagination"}
	}
	opts := storage.FindingListPageOptions{
		SortField: storage.FindingListSortCreatedAt,
		SortOrder: storage.ListSortAsc,
		Cursor:    strings.TrimSpace(q.Get("cursor")),
	}
	if v := strings.TrimSpace(q.Get("sort")); v != "" {
		switch v {
		case storage.FindingListSortCreatedAt, storage.FindingListSortSeverity:
			opts.SortField = v
		default:
			return storage.FindingListPageOptions{}, &apiRequestError{code: "invalid_sort", message: "sort must be created_at or severity for findings"}
		}
	}
	if v := strings.TrimSpace(q.Get("order")); v != "" {
		switch strings.ToLower(v) {
		case storage.ListSortAsc, storage.ListSortDesc:
			opts.SortOrder = strings.ToLower(v)
		default:
			return storage.FindingListPageOptions{}, &apiRequestError{code: "invalid_order", message: "order must be asc or desc"}
		}
	}
	ls := strings.TrimSpace(q.Get("limit"))
	if ls == "" {
		opts.Limit = storage.DefaultListLimit
	} else {
		n, err := strconv.Atoi(ls)
		if err != nil || n < 1 || n > storage.MaxListLimit {
			return storage.FindingListPageOptions{}, &apiRequestError{code: "invalid_limit", message: "limit must be between 1 and 200"}
		}
		opts.Limit = n
	}
	return opts, nil
}
