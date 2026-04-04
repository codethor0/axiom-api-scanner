package baseline

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
	"github.com/codethor0/axiom-api-scanner/internal/executil"
	"github.com/codethor0/axiom-api-scanner/internal/pathutil"
	"github.com/codethor0/axiom-api-scanner/internal/storage"
)

// Store is the persistence surface required for baseline runs.
type Store interface {
	GetScan(ctx context.Context, id string) (engine.Scan, error)
	ListScanEndpoints(ctx context.Context, scanID string) ([]engine.ScanEndpoint, error)
	InsertExecutionRecord(ctx context.Context, rec engine.ExecutionRecord) (string, error)
	UpdateBaselineState(ctx context.Context, scanID string, st storage.BaselineState) error
}

// Runner executes sequential GET and JSON POST baselines against imported endpoints.
type Runner struct {
	HTTP    *http.Client
	Store   Store
	MaxBody int64
}

// NewRunner returns a runner with conservative defaults.
func NewRunner(s Store) *Runner {
	c := &http.Client{
		Timeout: 45 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("stopped after 5 redirects")
			}
			if via[0].URL.Scheme != req.URL.Scheme || via[0].URL.Host != req.URL.Host {
				return fmt.Errorf("cross-origin redirect rejected")
			}
			return nil
		},
	}
	return &Runner{HTTP: c, Store: s, MaxBody: 2 << 20}
}

// SkipDetail records a non-executed endpoint.
type SkipDetail struct {
	EndpointID string `json:"endpoint_id,omitempty"`
	Path       string `json:"path,omitempty"`
	Method     string `json:"method,omitempty"`
	Reason     string `json:"reason"`
}

// Result is the machine-readable outcome of a baseline pass.
type Result struct {
	Status             string       `json:"status"`
	Error              string       `json:"error,omitempty"`
	EndpointsTotal     int          `json:"endpoints_total"`
	EndpointsExecuted  int          `json:"endpoints_executed"`
	EndpointsSkipped   int          `json:"endpoints_skipped"`
	ExecutionRecordIDs []string     `json:"execution_record_ids"`
	SkippedDetail      []SkipDetail `json:"skipped_detail,omitempty"`
	Warnings           []string     `json:"warnings,omitempty"`
}

// Run performs one sequential baseline pass for all eligible endpoints.
func (r *Runner) Run(ctx context.Context, scanID string) (Result, error) {
	if r.MaxBody <= 0 {
		r.MaxBody = 2 << 20
	}
	scan, err := r.Store.GetScan(ctx, scanID)
	if err != nil {
		return Result{}, err
	}
	baseStr := strings.TrimSpace(scan.BaseURL)
	if baseStr == "" {
		out := Result{Status: "failed", Error: "base_url_required"}
		return out, errors.New("base_url_required")
	}
	base, err := url.Parse(baseStr)
	if err != nil || base.Scheme == "" || base.Host == "" {
		out := Result{Status: "failed", Error: "invalid_base_url"}
		return out, fmt.Errorf("invalid_base_url: %w", err)
	}

	endpoints, err := r.Store.ListScanEndpoints(ctx, scanID)
	if err != nil {
		return Result{}, err
	}
	if len(endpoints) == 0 {
		out := Result{Status: "failed", Error: "no_imported_endpoints", EndpointsSkipped: 0}
		_ = r.Store.UpdateBaselineState(ctx, scanID, storage.BaselineState{
			Status: "failed", Error: "no_imported_endpoints", Total: 0, Done: 0,
		})
		return out, errors.New("no_imported_endpoints")
	}

	var toRun []engine.ScanEndpoint
	var skips []SkipDetail
	for _, ep := range endpoints {
		m := strings.ToUpper(strings.TrimSpace(ep.Method))
		switch m {
		case http.MethodGet:
			toRun = append(toRun, ep)
		case http.MethodPost:
			if ep.RequestBodyJSON {
				toRun = append(toRun, ep)
			} else {
				skips = append(skips, SkipDetail{EndpointID: ep.ID, Path: ep.PathTemplate, Method: m, Reason: "post_requires_json_request_body"})
			}
		default:
			skips = append(skips, SkipDetail{EndpointID: ep.ID, Path: ep.PathTemplate, Method: m, Reason: "method_not_supported_for_baseline"})
		}
	}

	total := len(toRun)
	_ = r.Store.UpdateBaselineState(ctx, scanID, storage.BaselineState{
		Status: "in_progress", Total: total, Done: 0,
	})

	var ids []string
	warnings := make([]string, 0)
	executed := 0

	for _, ep := range toRun {
		select {
		case <-ctx.Done():
			_ = r.Store.UpdateBaselineState(ctx, scanID, storage.BaselineState{
				Status: "failed", Error: ctx.Err().Error(), Total: total, Done: executed,
			})
			return Result{
				Status:             "failed",
				Error:              ctx.Err().Error(),
				EndpointsTotal:     total,
				EndpointsExecuted:  executed,
				EndpointsSkipped:   len(skips),
				ExecutionRecordIDs: ids,
				SkippedDetail:      skips,
				Warnings:           warnings,
			}, ctx.Err()
		default:
		}

		resolvedPath := pathutil.FillPathTemplate(ep.PathTemplate)
		targetURL, uerr := executil.JoinScanURL(baseStr, resolvedPath)
		if uerr != nil {
			skips = append(skips, SkipDetail{EndpointID: ep.ID, Path: ep.PathTemplate, Method: ep.Method, Reason: "url_build_failed"})
			warnings = append(warnings, fmt.Sprintf("url_build_failed:%s", ep.ID))
			continue
		}
		if !executil.HasPrefixURL(baseStr, targetURL) {
			skips = append(skips, SkipDetail{EndpointID: ep.ID, Path: ep.PathTemplate, Method: ep.Method, Reason: "url_out_of_scope"})
			continue
		}

		bodyStr := ""
		var bodyReader io.Reader
		if strings.ToUpper(ep.Method) == http.MethodPost {
			bodyStr = "{}"
			bodyReader = strings.NewReader(bodyStr)
		}

		req, rerr := http.NewRequestWithContext(ctx, strings.ToUpper(ep.Method), targetURL, bodyReader)
		if rerr != nil {
			skips = append(skips, SkipDetail{EndpointID: ep.ID, Reason: "request_build_failed"})
			continue
		}
		for k, v := range scan.AuthHeaders {
			req.Header.Set(k, v)
		}
		req.Header.Set("User-Agent", "Axiom-Baseline/1")
		if bodyStr != "" {
			req.Header.Set("Content-Type", "application/json")
		}

		start := time.Now()
		resp, err := r.HTTP.Do(req)
		dur := time.Since(start).Milliseconds()
		status := 0
		respHeaders := map[string]string{}
		respBody := ""
		respCT := ""

		if err != nil {
			warnings = append(warnings, fmt.Sprintf("http_error:%s:%v", ep.ID, err))
		} else {
			func() {
				defer func() { _ = resp.Body.Close() }()
				status = resp.StatusCode
				respCT = resp.Header.Get("Content-Type")
				respHeaders = executil.RedactSensitiveHeaders(executil.FilterHeaders(resp.Header))
				lim := io.LimitReader(resp.Body, r.MaxBody)
				b, _ := io.ReadAll(lim)
				respBody = executil.NormalizeResponseBody(respCT, b)
			}()
		}

		recID, ierr := r.Store.InsertExecutionRecord(ctx, engine.ExecutionRecord{
			ScanID:              scanID,
			ScanEndpointID:      ep.ID,
			Phase:               engine.PhaseBaseline,
			RequestMethod:       ep.Method,
			RequestURL:          targetURL,
			RequestHeaders:      executil.RedactSensitiveHeaders(executil.FilterHeaders(req.Header)),
			RequestBody:         bodyStr,
			ResponseStatus:      status,
			ResponseHeaders:     respHeaders,
			ResponseBody:        respBody,
			ResponseContentType: respCT,
			DurationMs:          dur,
		})
		if ierr != nil {
			_ = r.Store.UpdateBaselineState(ctx, scanID, storage.BaselineState{
				Status: "failed", Error: ierr.Error(), Total: total, Done: executed,
			})
			return Result{
				Status:             "failed",
				Error:              ierr.Error(),
				EndpointsTotal:     total,
				EndpointsExecuted:  executed,
				EndpointsSkipped:   len(skips),
				ExecutionRecordIDs: ids,
				SkippedDetail:      skips,
				Warnings:           warnings,
			}, ierr
		}
		ids = append(ids, recID)
		executed++
		_ = r.Store.UpdateBaselineState(ctx, scanID, storage.BaselineState{
			Status: "in_progress", Total: total, Done: executed,
		})
	}

	finalStatus := "succeeded"
	finalErr := ""
	if total == 0 {
		finalStatus = "failed"
		finalErr = "no_eligible_endpoints"
	} else if executed == 0 {
		finalStatus = "failed"
		finalErr = "all_endpoint_attempts_skipped_or_failed"
	}
	_ = r.Store.UpdateBaselineState(ctx, scanID, storage.BaselineState{
		Status: finalStatus, Error: finalErr, Total: total, Done: executed,
	})

	return Result{
		Status:             finalStatus,
		Error:              finalErr,
		EndpointsTotal:     total,
		EndpointsExecuted:  executed,
		EndpointsSkipped:   len(skips),
		ExecutionRecordIDs: ids,
		SkippedDetail:      skips,
		Warnings:           warnings,
	}, nil
}
