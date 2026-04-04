package storage

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
	"github.com/codethor0/axiom-api-scanner/internal/findings"
)

// ErrInvalidListCursor is returned when an opaque cursor cannot be decoded or fails validation.
var ErrInvalidListCursor = errors.New("invalid list cursor")

type listCursorV1 struct {
	V  int    `json:"v"`
	SF string `json:"sf"`
	O  string `json:"o"`
	T  string `json:"t"`
	ID string `json:"id"`
	P  *int   `json:"p,omitempty"`
	S  *int   `json:"s,omitempty"`
}

// EncodeListCursor builds a URL-safe opaque cursor tied to sort field and order.
func EncodeListCursor(sortField, order string, ts time.Time, id string, phaseOrd, sevOrd *int) (string, error) {
	sortField = strings.TrimSpace(sortField)
	order = strings.TrimSpace(order)
	id = strings.TrimSpace(id)
	if sortField == "" || order == "" || id == "" {
		return "", ErrInvalidListCursor
	}
	p := listCursorV1{
		V:  1,
		SF: sortField,
		O:  order,
		T:  ts.UTC().Format(time.RFC3339Nano),
		ID: id,
		P:  phaseOrd,
		S:  sevOrd,
	}
	b, err := json.Marshal(p)
	if err != nil {
		return "", ErrInvalidListCursor
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// DecodeListCursor validates the cursor matches expected sort field and order, then returns decoded fields.
func DecodeListCursor(enc, wantSort, wantOrder string) (ts time.Time, id string, phaseOrd, sevOrd *int, err error) {
	wantSort = strings.TrimSpace(wantSort)
	wantOrder = strings.TrimSpace(wantOrder)
	if enc == "" {
		return time.Time{}, "", nil, nil, ErrInvalidListCursor
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(enc))
	if err != nil {
		return time.Time{}, "", nil, nil, ErrInvalidListCursor
	}
	var p listCursorV1
	if uerr := json.Unmarshal(raw, &p); uerr != nil || p.V != 1 {
		return time.Time{}, "", nil, nil, ErrInvalidListCursor
	}
	if !strings.EqualFold(strings.TrimSpace(p.SF), wantSort) || !strings.EqualFold(strings.TrimSpace(p.O), wantOrder) {
		return time.Time{}, "", nil, nil, ErrInvalidListCursor
	}
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(p.T))
	if err != nil {
		return time.Time{}, "", nil, nil, ErrInvalidListCursor
	}
	id = strings.TrimSpace(p.ID)
	if id == "" {
		return time.Time{}, "", nil, nil, ErrInvalidListCursor
	}
	switch wantSort {
	case ExecListSortPhase:
		if p.P == nil {
			return time.Time{}, "", nil, nil, ErrInvalidListCursor
		}
		phaseOrd = p.P
	case FindingListSortSeverity:
		if p.S == nil {
			return time.Time{}, "", nil, nil, ErrInvalidListCursor
		}
		sevOrd = p.S
	case ExecListSortCreatedAt:
		if p.P != nil || p.S != nil {
			return time.Time{}, "", nil, nil, ErrInvalidListCursor
		}
	default:
		return time.Time{}, "", nil, nil, ErrInvalidListCursor
	}
	return t, id, phaseOrd, sevOrd, nil
}

// EncodeExecutionPageCursor builds a continuation cursor from the last row on the current page.
func EncodeExecutionPageCursor(rec engine.ExecutionRecord, sf, o string) (string, error) {
	sf = strings.TrimSpace(sf)
	o = strings.TrimSpace(o)
	var p *int
	if sf == ExecListSortPhase {
		v := executionPhaseRank(rec)
		p = &v
	}
	return EncodeListCursor(sf, o, rec.CreatedAt, rec.ID, p, nil)
}

// EncodeFindingPageCursor builds a continuation cursor from the last finding on the current page.
func EncodeFindingPageCursor(f findings.Finding, sf, o string) (string, error) {
	sf = strings.TrimSpace(sf)
	o = strings.TrimSpace(o)
	var s *int
	if sf == FindingListSortSeverity {
		v := findingSeverityRank(f)
		s = &v
	}
	return EncodeListCursor(sf, o, f.CreatedAt, f.ID, nil, s)
}

