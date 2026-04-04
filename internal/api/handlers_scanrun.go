package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
	"github.com/codethor0/axiom-api-scanner/internal/orchestrator"
	"github.com/codethor0/axiom-api-scanner/internal/storage"
	"github.com/go-chi/chi/v5"
)

// scanRunStatus returns operator-facing scan run phase and counters.
func (h *Handler) scanRunStatus(w http.ResponseWriter, r *http.Request) {
	if h.Scans == nil || h.Endpoints == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "service_unavailable", "persistence is not configured")
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
	endpoints, err := h.Endpoints.ListScanEndpoints(r.Context(), id)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "could not list endpoints")
		return
	}
	secEndpoints := 0
	for _, ep := range endpoints {
		if len(ep.SecuritySchemeHints) > 0 {
			secEndpoints++
		}
	}
	authConfigured := len(scan.AuthHeaders) > 0
	cov := ScanRunCoverage{
		AuthHeadersConfigured:      authConfigured,
		EndpointsDeclaringSecurity: secEndpoints,
	}
	if secEndpoints > 0 && !authConfigured {
		cov.Hints = append(cov.Hints, "imported operations include OpenAPI-declared security ("+strconv.Itoa(secEndpoints)+" operation(s)); scan has no auth_headers, so protected routes may return 401/403 and V1 eligible work may be reduced")
	}
	if authConfigured && secEndpoints > 0 {
		cov.Hints = append(cov.Hints, "auth_headers are present; outbound baseline and mutation requests will include them (sensitive values are never returned by this API)")
	}
	if secEndpoints == 0 && !authConfigured && len(endpoints) > 0 {
		cov.Hints = append(cov.Hints, "no operations in the imported spec declare security schemes; auth may still be required by the target for routes not reflected in OpenAPI")
	}
	out := ScanRunStatusResponse{
		ScanID:     scan.ID,
		Phase:      string(scan.RunPhase),
		ScanStatus: string(scan.Status),
		Progress: ScanRunProgress{
			EndpointsDiscovered:         len(endpoints),
			BaselineExecutionsCompleted: scan.BaselineEndpointsDone,
			MutationExecutionsCompleted: scan.MutationCandidatesDone,
			FindingsCreated:             scan.FindingsCount,
		},
		Coverage:  cov,
		LastError: lastRunError(scan),
	}
	writeJSON(w, http.StatusOK, out)
}

func lastRunError(scan engine.Scan) string {
	if scan.RunPhase == engine.PhaseFailed && strings.TrimSpace(scan.RunError) != "" {
		return strings.TrimSpace(scan.RunError)
	}
	if strings.TrimSpace(scan.BaselineRunError) != "" && (scan.BaselineRunStatus == "failed" || scan.RunPhase == engine.PhaseFailed) {
		return strings.TrimSpace(scan.BaselineRunError)
	}
	if strings.TrimSpace(scan.MutationRunError) != "" && (scan.MutationRunStatus == "failed" || scan.RunPhase == engine.PhaseFailed) {
		return strings.TrimSpace(scan.MutationRunError)
	}
	return strings.TrimSpace(scan.RunError)
}

// scanRunControl starts, resumes, or cancels orchestrated execution (synchronous).
func (h *Handler) scanRunControl(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUIDParam(chi.URLParam(r, "scanID"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_scan_id", "scan id must be a UUID")
		return
	}
	var req ScanRunControlRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_json", "request body must be JSON")
		return
	}
	action := strings.TrimSpace(strings.ToLower(req.Action))
	switch action {
	case "start", "resume":
		if h.Orchestrator == nil {
			writeAPIError(w, http.StatusServiceUnavailable, "service_unavailable", "scan orchestration is not configured")
			return
		}
		if action == "start" {
			err = h.Orchestrator.Run(r.Context(), id, orchestrator.Options{
				ResumeRetry:        false,
				ForceRerunBaseline: req.ForceRerunBaseline,
			})
		} else {
			err = h.Orchestrator.Run(r.Context(), id, orchestrator.Options{
				ResumeRetry:        true,
				ForceRerunBaseline: req.ForceRerunBaseline,
			})
		}
	case "cancel":
		err = h.cancelOrchestratedScan(r.Context(), id)
	default:
		writeAPIError(w, http.StatusBadRequest, "invalid_scan_run_action", "action must be one of start, resume, cancel")
		return
	}
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeAPIError(w, http.StatusNotFound, "not_found", "scan not found")
			return
		}
		if errors.Is(err, engine.ErrInvalidScanRunPhase) {
			writeAPIError(w, http.StatusConflict, "invalid_run_phase", err.Error())
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "scan_run_failed", err.Error())
		return
	}
	h.scanRunStatus(w, r)
}

func (h *Handler) cancelOrchestratedScan(ctx context.Context, scanID string) error {
	if h.Scans == nil || h.ScanRun == nil {
		return errors.New("persistence not configured")
	}
	if _, err := h.Scans.ApplyControl(ctx, scanID, storage.ScanControlCancel); err != nil && !errors.Is(err, storage.ErrInvalidTransition) {
		return err
	}
	return h.ScanRun.PatchScanRunPhase(ctx, scanID, engine.PhaseCanceled, "")
}
