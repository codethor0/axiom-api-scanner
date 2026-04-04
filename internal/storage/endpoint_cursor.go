package storage

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

type endpointCursorV1 struct {
	V  int    `json:"v"`
	SF string `json:"sf"`
	O  string `json:"o"`
	PT string `json:"pt"`
	M  string `json:"m"`
	ID string `json:"id"`
	CA string `json:"ca"`
}

// EncodeEndpointPageCursor builds an opaque cursor valid for the given sort field and order.
func EncodeEndpointPageCursor(sortField, sortOrder string, ep EndpointInventoryEntry) (string, error) {
	sf := strings.TrimSpace(sortField)
	o := strings.TrimSpace(sortOrder)
	id := strings.TrimSpace(ep.Endpoint.ID)
	if sf == "" || o == "" || id == "" {
		return "", ErrInvalidListCursor
	}
	switch sf {
	case EndpointListSortPath, EndpointListSortMethod, EndpointListSortCreatedAt:
	default:
		return "", ErrInvalidListCursor
	}
	p := endpointCursorV1{
		V:  1,
		SF: sf,
		O:  o,
		PT: ep.Endpoint.PathTemplate,
		M:  strings.TrimSpace(ep.Endpoint.Method),
		ID: id,
		CA: ep.Endpoint.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
	b, err := json.Marshal(p)
	if err != nil {
		return "", ErrInvalidListCursor
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// DecodeEndpointCursor validates the cursor against expected sort field and order, returning tuple parts for keyset SQL.
func DecodeEndpointCursor(enc, wantSort, wantOrder string) (pathTemplate, method, id string, createdAt time.Time, err error) {
	wantSort = strings.TrimSpace(wantSort)
	wantOrder = strings.TrimSpace(wantOrder)
	if enc == "" {
		return "", "", "", time.Time{}, ErrInvalidListCursor
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(enc))
	if err != nil {
		return "", "", "", time.Time{}, ErrInvalidListCursor
	}
	var p endpointCursorV1
	if uerr := json.Unmarshal(raw, &p); uerr != nil || p.V != 1 {
		return "", "", "", time.Time{}, ErrInvalidListCursor
	}
	if !strings.EqualFold(strings.TrimSpace(p.SF), wantSort) || !strings.EqualFold(strings.TrimSpace(p.O), wantOrder) {
		return "", "", "", time.Time{}, ErrInvalidListCursor
	}
	id = strings.TrimSpace(p.ID)
	if id == "" {
		return "", "", "", time.Time{}, ErrInvalidListCursor
	}
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(p.CA))
	if err != nil {
		return "", "", "", time.Time{}, ErrInvalidListCursor
	}
	return strings.TrimSpace(p.PT), strings.TrimSpace(p.M), id, t, nil
}
