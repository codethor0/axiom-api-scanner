package api

import (
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
	"github.com/codethor0/axiom-api-scanner/internal/findings"
	"github.com/codethor0/axiom-api-scanner/internal/rules"
	"github.com/codethor0/axiom-api-scanner/internal/spec/openapi"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// Handler bundles HTTP dependencies for the control plane (stubs until storage is wired).
type Handler struct {
	RulesDir string
}

func (h *Handler) Routes() chi.Router {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Post("/v1/scans", h.createScan)
	r.Get("/v1/scans/{scanID}", h.getScan)
	r.Post("/v1/scans/{scanID}/start", h.startScan)
	r.Post("/v1/scans/{scanID}/pause", h.pauseScan)
	r.Post("/v1/scans/{scanID}/cancel", h.cancelScan)
	r.Get("/v1/scans/{scanID}/findings", h.listFindings)
	r.Get("/v1/findings/{findingID}", h.getFinding)
	r.Get("/v1/findings/{findingID}/evidence", h.getFindingEvidence)
	r.Get("/v1/rules", h.listRules)
	r.Post("/v1/specs/openapi/validate", h.validateOpenAPI)
	r.Post("/v1/specs/openapi/import", h.importOpenAPI)
	return r
}

func (h *Handler) createScan(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusCreated, engine.Scan{
		ID:          "scan-placeholder",
		Status:      engine.ScanQueued,
		TargetLabel: "unspecified",
		SafetyMode:  "safe",
		CreatedAt:   time.Now().UTC().Truncate(time.Second),
		UpdatedAt:   time.Now().UTC().Truncate(time.Second),
	})
}

func (h *Handler) getScan(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "scanID")
	writeJSON(w, http.StatusOK, engine.Scan{
		ID:          id,
		Status:      engine.ScanQueued,
		TargetLabel: "unspecified",
		SafetyMode:  "safe",
		CreatedAt:   time.Now().UTC().Truncate(time.Second),
		UpdatedAt:   time.Now().UTC().Truncate(time.Second),
	})
}

func (h *Handler) startScan(w http.ResponseWriter, r *http.Request) {
	h.transitionScan(w, r, engine.ScanRunning)
}

func (h *Handler) pauseScan(w http.ResponseWriter, r *http.Request) {
	h.transitionScan(w, r, engine.ScanPaused)
}

func (h *Handler) cancelScan(w http.ResponseWriter, r *http.Request) {
	h.transitionScan(w, r, engine.ScanCanceled)
}

func (h *Handler) transitionScan(w http.ResponseWriter, r *http.Request, st engine.ScanStatus) {
	id := chi.URLParam(r, "scanID")
	writeJSON(w, http.StatusOK, engine.Scan{
		ID:          id,
		Status:      st,
		TargetLabel: "unspecified",
		SafetyMode:  "safe",
		CreatedAt:   time.Now().UTC().Truncate(time.Second),
		UpdatedAt:   time.Now().UTC().Truncate(time.Second),
	})
}

func (h *Handler) listFindings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, []findings.Finding{})
}

func (h *Handler) getFinding(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "findingID")
	writeJSON(w, http.StatusOK, findings.Finding{
		ID:        id,
		ScanID:    "scan-placeholder",
		RuleID:    "placeholder.rule",
		Category:  "placeholder",
		Severity:  findings.SeverityInfo,
		Summary:   "stub",
		CreatedAt: time.Now().UTC().Truncate(time.Second),
	})
}

func (h *Handler) getFindingEvidence(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, findings.EvidenceArtifact{
		ID:              "evidence-placeholder",
		FindingID:       chi.URLParam(r, "findingID"),
		BaselineRequest: "",
		MutatedRequest:  "",
		DiffSummary:     "stub",
		CreatedAt:       time.Now().UTC().Truncate(time.Second),
	})
}

func (h *Handler) listRules(w http.ResponseWriter, r *http.Request) {
	if h.RulesDir == "" {
		writeJSON(w, http.StatusOK, []rules.Rule{})
		return
	}
	loader := rules.Loader{}
	list, err := loader.LoadDir(h.RulesDir)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (h *Handler) validateOpenAPI(w http.ResponseWriter, r *http.Request) {
	data, err := readBody(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	_, err = openapi.ExtractEndpoints(r.Context(), data)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "valid"})
}

func (h *Handler) importOpenAPI(w http.ResponseWriter, r *http.Request) {
	data, err := readBody(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	endpoints, err := openapi.ExtractEndpoints(r.Context(), data)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"endpoints": endpoints,
		"count":     len(endpoints),
	})
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
