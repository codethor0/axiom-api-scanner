package engine

import "time"

// ScanEndpoint is a persisted OpenAPI operation row scoped to one scan.
type ScanEndpoint struct {
	ID                   string    `json:"id"`
	ScanID               string    `json:"scan_id"`
	Method               string    `json:"method"`
	PathTemplate         string    `json:"path_template"`
	OperationID          string    `json:"operation_id,omitempty"`
	SecuritySchemeHints  []string  `json:"security_scheme_hints,omitempty"`
	RequestContentTypes  []string  `json:"request_content_types,omitempty"`
	ResponseContentTypes []string  `json:"response_content_types,omitempty"`
	RequestBodyJSON      bool      `json:"request_body_json"`
	CreatedAt            time.Time `json:"created_at"`
}

// EndpointSpec is an import-time view without database identifiers.
type EndpointSpec struct {
	Method               string   `json:"method"`
	Path                 string   `json:"path"`
	OperationID          string   `json:"operation_id,omitempty"`
	Summary              string   `json:"summary,omitempty"`
	SecuritySchemeHints  []string `json:"security_scheme_hints,omitempty"`
	RequestContentTypes  []string `json:"request_content_types,omitempty"`
	ResponseContentTypes []string `json:"response_content_types,omitempty"`
	RequestBodyJSON      bool     `json:"request_body_json"`
}
