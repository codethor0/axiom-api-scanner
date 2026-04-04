package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
	"github.com/codethor0/axiom-api-scanner/internal/executor/baseline"
	"github.com/codethor0/axiom-api-scanner/internal/executor/mutation"
	"github.com/codethor0/axiom-api-scanner/internal/mutate"
	"github.com/codethor0/axiom-api-scanner/internal/orchestrator"
	v1plan "github.com/codethor0/axiom-api-scanner/internal/plan/v1"
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

const maxMutationPreview = 40

// Handler bundles HTTP dependencies for the control plane.
type Handler struct {
	RulesDir string

	Scans       storage.ScanRepository
	ScanTargets storage.ScanTargetRepository
	ScanRun     storage.ScanRunRepository
	Endpoints   storage.EndpointRepository
	Executions  storage.ExecutionRepository
	Findings    storage.FindingRepository
	Evidence    storage.EvidenceMetadataRepository

	Baseline     *baseline.Runner
	Mutations    *mutation.Runner
	Orchestrator *orchestrator.Service
}

func (h *Handler) Routes() chi.Router {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Post("/v1/scans", h.createScan)
	r.Patch("/v1/scans/{scanID}", h.patchScan)
	r.Get("/v1/scans/{scanID}", h.getScan)
	r.Get("/v1/scans/{scanID}/run/status", h.scanRunStatus)
	r.Post("/v1/scans/{scanID}/run", h.scanRunControl)
	r.Post("/v1/scans/{scanID}/control", h.controlScan)
	r.Post("/v1/scans/{scanID}/specs/openapi", h.importOpenAPIScan)
	r.Get("/v1/scans/{scanID}/endpoints", h.listScanEndpoints)
	r.Get("/v1/scans/{scanID}/endpoints/{endpointID}", h.getScanEndpoint)
	r.Post("/v1/scans/{scanID}/executions/baseline", h.runBaseline)
	r.Post("/v1/scans/{scanID}/executions/mutations", h.runMutations)
	r.Get("/v1/scans/{scanID}/executions", h.listExecutions)
	r.Get("/v1/scans/{scanID}/executions/{executionID}", h.getExecution)
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
	auth := req.AuthHeaders
	if auth == nil {
		auth = map[string]string{}
	}
	in := storage.CreateScanInput{
		TargetLabel:        strings.TrimSpace(req.TargetLabel),
		SafetyMode:         strings.TrimSpace(req.SafetyMode),
		AllowFullExecution: req.AllowFullExecution,
		BaseURL:            strings.TrimSpace(req.BaseURL),
		AuthHeaders:        auth,
	}
	scan, err := h.Scans.CreateScan(r.Context(), in)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "could not persist scan")
		return
	}
	writeJSON(w, http.StatusCreated, scan)
}

func (h *Handler) patchScan(w http.ResponseWriter, r *http.Request) {
	if h.ScanTargets == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "service_unavailable", "scan persistence is not configured")
		return
	}
	id, err := parseUUIDParam(chi.URLParam(r, "scanID"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_scan_id", "scan id must be a UUID")
		return
	}
	var req PatchScanRequest
	if err = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_json", "request body must be JSON")
		return
	}
	if req.BaseURL != nil && strings.TrimSpace(*req.BaseURL) != "" {
		if _, perr := url.Parse(strings.TrimSpace(*req.BaseURL)); perr != nil {
			writeAPIError(w, http.StatusBadRequest, "invalid_base_url", "base_url must be a valid URL")
			return
		}
	}
	in := storage.PatchScanTargetInput{
		BaseURL:     req.BaseURL,
		AuthHeaders: req.AuthHeaders,
		ReplaceAuth: req.ReplaceAuthHeaders,
	}
	scan, err := h.ScanTargets.PatchScanTarget(r.Context(), id, in)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeAPIError(w, http.StatusNotFound, "not_found", "scan not found")
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "could not update scan")
		return
	}
	writeJSON(w, http.StatusOK, scan)
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

func (h *Handler) importOpenAPIScan(w http.ResponseWriter, r *http.Request) {
	if h.Endpoints == nil || h.Scans == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "service_unavailable", "persistence is not configured")
		return
	}
	id, err := parseUUIDParam(chi.URLParam(r, "scanID"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_scan_id", "scan id must be a UUID")
		return
	}
	if _, gerr := h.Scans.GetScan(r.Context(), id); gerr != nil {
		if errors.Is(gerr, storage.ErrNotFound) {
			writeAPIError(w, http.StatusNotFound, "not_found", "scan not found")
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "could not load scan")
		return
	}
	data, err := readBody(r)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	specs, err := openapi.ExtractEndpointSpecs(r.Context(), data)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_openapi", err.Error())
		return
	}
	if err := h.Endpoints.ReplaceScanEndpoints(r.Context(), id, specs); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "could not persist endpoints")
		return
	}
	writeJSON(w, http.StatusOK, ScanOpenAPIImportResponse{ScanID: id, Endpoints: specs, Count: len(specs)})
}

func (h *Handler) listScanEndpoints(w http.ResponseWriter, r *http.Request) {
	if h.Endpoints == nil || h.Scans == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "service_unavailable", "persistence is not configured")
		return
	}
	id, err := parseUUIDParam(chi.URLParam(r, "scanID"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_scan_id", "scan id must be a UUID")
		return
	}
	if _, gerr := h.Scans.GetScan(r.Context(), id); gerr != nil {
		if errors.Is(gerr, storage.ErrNotFound) {
			writeAPIError(w, http.StatusNotFound, "not_found", "scan not found")
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "could not load scan")
		return
	}
	listFilter, reqErr := parseEndpointListParams(r)
	if reqErr != nil {
		writeAPIError(w, http.StatusBadRequest, reqErr.code, reqErr.message)
		return
	}
	pageOpts, perr := parseEndpointListPageParams(r)
	if perr != nil {
		writeAPIError(w, http.StatusBadRequest, perr.code, perr.message)
		return
	}
	page, err := h.Endpoints.ListEndpointInventoryPage(r.Context(), id, listFilter.storageFilter, storage.EndpointInventoryOptions{IncludeSummary: listFilter.includeSummary}, pageOpts)
	if err != nil {
		if errors.Is(err, storage.ErrInvalidListCursor) {
			writeAPIError(w, http.StatusBadRequest, "invalid_cursor", "cursor is invalid or does not match sort and order")
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "could not list endpoints")
		return
	}
	out := EndpointListResponse{
		Items: make([]EndpointRead, 0, len(page.Records)),
		Meta: ListPageMeta{
			Limit:      pageOpts.Limit,
			Sort:       pageOpts.SortField,
			Order:      pageOpts.SortOrder,
			NextCursor: page.NextCursor,
			HasMore:    page.HasMore,
		},
	}
	for _, ent := range page.Records {
		out.Items = append(out.Items, endpointReadFromInventory(ent, listFilter.includeSummary))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) getScanEndpoint(w http.ResponseWriter, r *http.Request) {
	if h.Endpoints == nil || h.Scans == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "service_unavailable", "persistence is not configured")
		return
	}
	scanID, err := parseUUIDParam(chi.URLParam(r, "scanID"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_scan_id", "scan id must be a UUID")
		return
	}
	endpointID, err := parseUUIDParam(chi.URLParam(r, "endpointID"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_endpoint_id", "endpoint id must be a UUID")
		return
	}
	if _, gerr := h.Scans.GetScan(r.Context(), scanID); gerr != nil {
		if errors.Is(gerr, storage.ErrNotFound) {
			writeAPIError(w, http.StatusNotFound, "not_found", "scan not found")
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "could not load scan")
		return
	}
	ent, err := h.Endpoints.GetEndpointInventory(r.Context(), scanID, endpointID, storage.EndpointInventoryOptions{IncludeSummary: true})
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeAPIError(w, http.StatusNotFound, "not_found", "endpoint not found")
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "could not load endpoint")
		return
	}
	writeJSON(w, http.StatusOK, endpointDetailFromInventory(ent))
}

func (h *Handler) runBaseline(w http.ResponseWriter, r *http.Request) {
	if h.Baseline == nil || h.Scans == nil || h.Endpoints == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "service_unavailable", "baseline execution is not configured")
		return
	}
	id, err := parseUUIDParam(chi.URLParam(r, "scanID"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_scan_id", "scan id must be a UUID")
		return
	}
	if _, gerr := h.Scans.GetScan(r.Context(), id); gerr != nil {
		if errors.Is(gerr, storage.ErrNotFound) {
			writeAPIError(w, http.StatusNotFound, "not_found", "scan not found")
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "could not load scan")
		return
	}

	res, err := h.Baseline.Run(r.Context(), id)
	if err != nil && res.Status == "" {
		writeAPIError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	ruleSet, _ := h.loadRules()
	endpoints, _ := h.Endpoints.ListScanEndpoints(r.Context(), id, storage.EndpointListFilter{})
	resp := BaselineRunAPIResponse{
		Result:             res,
		PlanByEndpoint:     buildPlanSummaries(endpoints, ruleSet),
		MutationCandidates: buildMutationPreview(endpoints, ruleSet),
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) runMutations(w http.ResponseWriter, r *http.Request) {
	if h.Mutations == nil || h.Scans == nil || h.Endpoints == nil || h.Executions == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "service_unavailable", "mutation execution is not configured")
		return
	}
	id, err := parseUUIDParam(chi.URLParam(r, "scanID"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_scan_id", "scan id must be a UUID")
		return
	}
	if _, gerr := h.Scans.GetScan(r.Context(), id); gerr != nil {
		if errors.Is(gerr, storage.ErrNotFound) {
			writeAPIError(w, http.StatusNotFound, "not_found", "scan not found")
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "could not load scan")
		return
	}
	ruleSet, err := h.loadRules()
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "rule_load_failed", err.Error())
		return
	}
	endpoints, err := h.Endpoints.ListScanEndpoints(r.Context(), id, storage.EndpointListFilter{})
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "could not list endpoints")
		return
	}
	work, werr := mutation.BuildWorkList(endpoints, ruleSet)
	if werr != nil {
		writeAPIError(w, http.StatusBadRequest, "mutation_worklist_failed", werr.Error())
		return
	}
	res, rerr := h.Mutations.Run(r.Context(), id, work)
	if rerr != nil && res.Status == "" {
		writeAPIError(w, http.StatusInternalServerError, "internal_error", rerr.Error())
		return
	}
	writeJSON(w, http.StatusOK, MutationRunAPIResponse{Result: res})
}

func (h *Handler) listExecutions(w http.ResponseWriter, r *http.Request) {
	if h.Executions == nil || h.Scans == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "service_unavailable", "execution persistence is not configured")
		return
	}
	id, err := parseUUIDParam(chi.URLParam(r, "scanID"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_scan_id", "scan id must be a UUID")
		return
	}
	if _, gerr := h.Scans.GetScan(r.Context(), id); gerr != nil {
		if errors.Is(gerr, storage.ErrNotFound) {
			writeAPIError(w, http.StatusNotFound, "not_found", "scan not found")
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "could not load scan")
		return
	}
	filter, ferr := parseExecutionListFilters(r)
	if ferr != nil {
		writeAPIError(w, http.StatusBadRequest, ferr.code, ferr.message)
		return
	}
	pageOpts, perr := parseExecutionListPageParams(r)
	if perr != nil {
		writeAPIError(w, http.StatusBadRequest, perr.code, perr.message)
		return
	}
	page, err := h.Executions.ListExecutionsPage(r.Context(), id, filter, pageOpts)
	if err != nil {
		if errors.Is(err, storage.ErrInvalidListCursor) {
			writeAPIError(w, http.StatusBadRequest, "invalid_cursor", "cursor is invalid or does not match sort and order")
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "could not list executions")
		return
	}
	items := make([]ExecutionListItem, len(page.Records))
	for i := range page.Records {
		items[i] = NewExecutionListItem(page.Records[i])
	}
	writeJSON(w, http.StatusOK, ExecutionListResponse{
		Items: items,
		Meta: ListPageMeta{
			Limit:      pageOpts.Limit,
			Sort:       pageOpts.SortField,
			Order:      pageOpts.SortOrder,
			NextCursor: page.NextCursor,
			HasMore:    page.HasMore,
		},
	})
}

func (h *Handler) getExecution(w http.ResponseWriter, r *http.Request) {
	if h.Executions == nil || h.Scans == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "service_unavailable", "execution persistence is not configured")
		return
	}
	scanID, err := parseUUIDParam(chi.URLParam(r, "scanID"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_scan_id", "scan id must be a UUID")
		return
	}
	execID, err := parseUUIDParam(chi.URLParam(r, "executionID"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_execution_id", "execution id must be a UUID")
		return
	}
	if _, gerr := h.Scans.GetScan(r.Context(), scanID); gerr != nil {
		if errors.Is(gerr, storage.ErrNotFound) {
			writeAPIError(w, http.StatusNotFound, "not_found", "scan not found")
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "could not load scan")
		return
	}
	rec, err := h.Executions.GetExecution(r.Context(), scanID, execID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeAPIError(w, http.StatusNotFound, "not_found", "execution not found")
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "could not load execution")
		return
	}
	writeJSON(w, http.StatusOK, NewExecutionRead(rec))
}

func (h *Handler) loadRules() ([]rules.Rule, error) {
	if h.RulesDir == "" {
		return nil, nil
	}
	return (rules.Loader{}).LoadDir(h.RulesDir)
}

func buildPlanSummaries(endpoints []engine.ScanEndpoint, ruleSet []rules.Rule) []EndpointPlanSummary {
	out := make([]EndpointPlanSummary, 0, len(endpoints))
	for _, ep := range endpoints {
		out = append(out, EndpointPlanSummary{
			EndpointID:   ep.ID,
			PathTemplate: ep.PathTemplate,
			Method:       ep.Method,
			Decisions:    v1plan.Plan(ep, ruleSet),
		})
	}
	return out
}

func buildMutationPreview(endpoints []engine.ScanEndpoint, ruleSet []rules.Rule) []mutate.Candidate {
	byID := make(map[string]rules.Rule, len(ruleSet))
	for _, ru := range ruleSet {
		byID[ru.ID] = ru
	}
	var cands []mutate.Candidate
outer:
	for _, ep := range endpoints {
		for _, d := range v1plan.Plan(ep, ruleSet) {
			if !d.Eligible {
				continue
			}
			ru, ok := byID[d.RuleID]
			if !ok {
				continue
			}
			mc, err := mutate.GenerateForEndpoint(ru, ep)
			if err != nil {
				continue
			}
			cands = append(cands, mc...)
			if len(cands) >= maxMutationPreview {
				break outer
			}
		}
	}
	return cands
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
	filter, ferr := parseFindingListFilters(r)
	if ferr != nil {
		writeAPIError(w, http.StatusBadRequest, ferr.code, ferr.message)
		return
	}
	pageOpts, perr := parseFindingListPageParams(r)
	if perr != nil {
		writeAPIError(w, http.StatusBadRequest, perr.code, perr.message)
		return
	}
	page, err := h.Findings.ListFindingsPage(r.Context(), id, filter, pageOpts)
	if err != nil {
		if errors.Is(err, storage.ErrInvalidListCursor) {
			writeAPIError(w, http.StatusBadRequest, "invalid_cursor", "cursor is invalid or does not match sort and order")
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "could not list findings")
		return
	}
	out := make([]FindingListItem, len(page.Records))
	for i := range page.Records {
		out[i] = NewFindingListItem(page.Records[i])
	}
	writeJSON(w, http.StatusOK, FindingListResponse{
		Items: out,
		Meta: ListPageMeta{
			Limit:      pageOpts.Limit,
			Sort:       pageOpts.SortField,
			Order:      pageOpts.SortOrder,
			NextCursor: page.NextCursor,
			HasMore:    page.HasMore,
		},
	})
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
	writeJSON(w, http.StatusOK, NewFindingRead(f))
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
	_, err = openapi.ExtractEndpointSpecs(r.Context(), data)
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
	specs, err := openapi.ExtractEndpointSpecs(r.Context(), data)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_openapi", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, OpenAPIImportResponse{Endpoints: specs, Count: len(specs)})
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
	if bu := strings.TrimSpace(req.BaseURL); bu != "" {
		u, err := url.Parse(bu)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return &apiRequestError{code: "invalid_base_url", message: "base_url must be an absolute URL when provided"}
		}
	}
	return nil
}
