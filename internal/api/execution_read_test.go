package api

import (
	"strings"
	"testing"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
)

func TestShortenExecutionURL(t *testing.T) {
	t.Parallel()
	short := "https://ex/a"
	if got := shortenExecutionURL(short, 120); got != short {
		t.Fatalf("got %q", got)
	}
	long := "https://example.com/" + strings.Repeat("segment/", 40)
	got := shortenExecutionURL(long, 80)
	if len(got) > 80 {
		t.Fatalf("len %d: %q", len(got), got)
	}
	if !strings.HasSuffix(got, "...") {
		t.Fatalf("want ellipsis suffix: %q", got)
	}
}

func TestNewExecutionRead_summariesAndKind(t *testing.T) {
	t.Parallel()
	rec := engine.ExecutionRecord{
		ID:                  "e1",
		ScanID:              "s1",
		ScanEndpointID:      "ep1",
		Phase:               engine.PhaseMutated,
		RuleID:              "rule.a",
		CandidateKey:        "ck-1",
		RequestMethod:       "GET",
		RequestURL:          "https://api.example/v1/items/1",
		RequestHeaders:      map[string]string{"X-A": "1"},
		RequestBody:         "body",
		ResponseStatus:      200,
		ResponseHeaders:     map[string]string{"X-B": "2"},
		ResponseBody:        "ok",
		ResponseContentType: "text/plain",
		DurationMs:          10,
	}
	r := NewExecutionRead(rec)
	if r.ExecutionKind != "mutated" || r.Phase != "mutated" {
		t.Fatalf("phase/kind %+v", r)
	}
	if r.MutationRuleID != "rule.a" || r.CandidateKey != "ck-1" {
		t.Fatalf("mutation fields %+v", r)
	}
	if r.RequestSummary.Method != "GET" || r.RequestSummary.HeaderCount != 1 || r.RequestSummary.BodyByteLength != 4 {
		t.Fatalf("request summary %+v", r.RequestSummary)
	}
	if r.ResponseSummary.StatusCode != 200 || r.ResponseSummary.HeaderCount != 1 || r.ResponseSummary.BodyByteLength != 2 {
		t.Fatalf("response summary %+v", r.ResponseSummary)
	}
	if r.ResponseSummary.ContentType != "text/plain" {
		t.Fatalf("content type %+v", r.ResponseSummary)
	}
}
