package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/codethor0/axiom-api-scanner/internal/findings"
	"github.com/codethor0/axiom-api-scanner/internal/rules"
	"github.com/codethor0/axiom-api-scanner/internal/spec/openapi"
	"github.com/codethor0/axiom-api-scanner/internal/storage"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
)

const (
	safetyPassive = "passive"
	safetySafe    = "safe"
	safetyFull    = "full"
)

// Handler bundles HTTP dependencies for the control plane.
type Handler struct {
	RulesDir string

	Scans    storage.ScanRepository
	Findings storage.FindingRepository
	Evidence storage.EvidenceMetadataRepository
}

func (h *Handler) Routes() chi.Router {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Post("/v1/scans", h.createScan)
	r.Get("/v1/scans/{scanID}", h.getScan)
	r.Post("/v1/scans/{scanID}/control", h.controlScan)
	r.Get("/v1/scans/{scanID}/findings", h.listFindings)
	r.Get("/v1/findings/{findingID}", h.getFinding)
	r.Get("/v1/findings/{findingID}/evidence", h.getFindingEvidence)
	r.Get("/v1/rules", h.listRules)
	r.Post("/v1/specs/openapi/validate", h.validateOpenAPI)
	r.Post("/v1/specs/openapi/import", h.importOpenAPI)
	return r
}

func (h *Handler) createScan(w http.ResponseWriter, r *http.Request) {
	if h.Scans == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "service_unavailable", "scan persistence is not configured")
		return
	}
	var req CreateScanRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_json", "request body must be JSON")
		return
	}
	if err := validateCreateScanRequest(req); err != nil {
		var ae *apiRequestError
		if errors.As(err, &ae) {
			writeAPIError(w, http.StatusBadRequest, ae.code, ae.message)
			return
		}
		writeAPIError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	in := storage.CreateScanInput{
		TargetLabel:        strings.TrimSpace(req.TargetLabel),
		SafetyMode:         strings.TrimSpace(req.SafetyMode),
		AllowFullExecution: req.AllowFullExecution,
	}
	scan, err := h.Scans.CreateScan(r.Context(), in)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "could not persist scan")
		return
	}
	writeJSON(w, http.StatusCreated, scan)
}

func (h *Handler) getScan(w http.ResponseWriter, r *http.Request) {
	if h.Scans == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "service_unavailable", "scan persistence is not configured")
		return
	}
	id, err := parseUUIDParam(chi.URLParam(r, "scanID"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_scan_id", "scan id must be a UUID")
		return
	}
	scan, err := h.Scans.GetScan(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeAPIError(w, http.StatusNotFound, "not_found", "scan not found")
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "could not load scan")
		return
	}
	writeJSON(w, http.StatusOK, scan)
}

func (h *Handler) controlScan(w http.ResponseWriter, r *http.Request) {
	if h.Scans == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "service_unavailable", "scan persistence is not configured")
		return
	}
	id, err := parseUUIDParam(chi.URLParam(r, "scanID"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_scan_id", "scan id must be a UUID")
		return
	}
	var req ScanControlRequest
	if err = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_json", "request body must be JSON")
		return
	}
	action, err := parseControlAction(req.Action)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_control_action", err.Error())
		return
	}
	scan, err := h.Scans.ApplyControl(r.Context(), id, action)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeAPIError(w, http.StatusNotFound, "not_found", "scan not found")
			return
		}
		if errors.Is(err, storage.ErrInvalidTransition) {
			writeAPIError(w, http.StatusConflict, "invalid_state_transition", "control action is not valid for the current scan status")
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "could not update scan")
		return
	}
	writeJSON(w, http.StatusOK, scan)
}

func (h *Handler) listFindings(w http.ResponseWriter, r *http.Request) {
	if h.Findings == nil || h.Scans == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "service_unavailable", "persistence is not configured")
		return
	}
	id, err := parseUUIDParam(chi.URLParam(r, "scanID"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_scan_id", "scan id must be a UUID")
		return
	}
	_, getErr := h.Scans.GetScan(r.Context(), id)
	if getErr != nil {
		if errors.Is(getErr, storage.ErrNotFound) {
			writeAPIError(w, http.StatusNotFound, "not_found", "scan not found")
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "could not load scan")
		return
	}
	list, err := h.Findings.ListByScanID(r.Context(), id)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "could not list findings")
		return
	}
	if list == nil {
		list = []findings.Finding{}
	}
	writeJSON(w, http.StatusOK, list)
}

func (h *Handler) getFinding(w http.ResponseWriter, r *http.Request) {
	if h.Findings == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "service_unavailable", "finding persistence is not configured")
		return
	}
	id, err := parseUUIDParam(chi.URLParam(r, "findingID"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_finding_id", "finding id must be a UUID")
		return
	}
	f, err := h.Findings.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeAPIError(w, http.StatusNotFound, "not_found", "finding not found")
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "could not load finding")
		return
	}
	writeJSON(w, http.StatusOK, f)
}

func (h *Handler) getFindingEvidence(w http.ResponseWriter, r *http.Request) {
	if h.Evidence == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "service_unavailable", "evidence persistence is not configured")
		return
	}
	id, err := parseUUIDParam(chi.URLParam(r, "findingID"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_finding_id", "finding id must be a UUID")
		return
	}
	ev, err := h.Evidence.GetArtifactByFindingID(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeAPIError(w, http.StatusNotFound, "not_found", "evidence not found")
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "could not load evidence")
		return
	}
	writeJSON(w, http.StatusOK, ev)
}

func (h *Handler) listRules(w http.ResponseWriter, r *http.Request) {
	if h.RulesDir == "" {
		writeJSON(w, http.StatusOK, []rules.Rule{})
		return
	}
	loader := rules.Loader{}
	list, err := loader.LoadDir(h.RulesDir)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "rule_load_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (h *Handler) validateOpenAPI(w http.ResponseWriter, r *http.Request) {
	data, err := readBody(r)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	_, err = openapi.ExtractEndpoints(r.Context(), data)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_openapi", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, OpenAPIValidateResponse{Status: "valid"})
}

func (h *Handler) importOpenAPI(w http.ResponseWriter, r *http.Request) {
	data, err := readBody(r)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	endpoints, err := openapi.ExtractEndpoints(r.Context(), data)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_openapi", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, OpenAPIImportResponse{Endpoints: endpoints, Count: len(endpoints)})
}

func readBody(r *http.Request) ([]byte, error) {
	defer func() { _ = r.Body.Close() }()
	const maxBody = 10 << 20
	limited := io.LimitReader(r.Body, maxBody+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(data) > maxBody {
		return nil, errors.New("request body exceeds limit")
	}
	if len(data) == 0 {
		return nil, errors.New("request body is empty")
	}
	return data, nil
}

func parseUUIDParam(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("empty id")
	}
	parsed, err := uuid.Parse(raw)
	if err != nil {
		return "", err
	}
	return parsed.String(), nil
}

func parseControlAction(s string) (storage.ScanControlAction, error) {
	switch strings.TrimSpace(strings.ToLower(s)) {
	case "start":
		return storage.ScanControlStart, nil
	case "pause":
		return storage.ScanControlPause, nil
	case "cancel":
		return storage.ScanControlCancel, nil
	case "":
		return "", errors.New("action is required")
	default:
		return "", errors.New("action must be one of start, pause, cancel")
	}
}

type apiRequestError struct {
	code    string
	message string
}

func (e *apiRequestError) Error() string { return e.message }

func validateCreateScanRequest(req CreateScanRequest) error {
	label := strings.TrimSpace(req.TargetLabel)
	if label == "" || len(label) > 256 {
		return &apiRequestError{code: "invalid_target_label", message: "target_label is required and must be at most 256 characters"}
	}
	mode := strings.TrimSpace(strings.ToLower(req.SafetyMode))
	if mode != safetyPassive && mode != safetySafe && mode != safetyFull {
		return &apiRequestError{code: "invalid_safety_mode", message: "safety_mode must be one of passive, safe, full"}
	}
	if mode == safetyFull && !req.AllowFullExecution {
		return &apiRequestError{code: "full_mode_requires_opt_in", message: "safety_mode full requires allow_full_execution true"}
	}
	return nil
}
