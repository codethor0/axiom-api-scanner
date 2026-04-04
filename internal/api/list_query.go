package api

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/codethor0/axiom-api-scanner/internal/storage"
)

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
