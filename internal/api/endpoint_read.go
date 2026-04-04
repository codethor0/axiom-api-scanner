package api

import (
	"fmt"

	"github.com/codethor0/axiom-api-scanner/internal/storage"
)

func endpointReadFromInventory(ent storage.EndpointInventoryEntry, includeSummary bool) EndpointRead {
	ep := ent.Endpoint
	r := EndpointRead{
		ID:                      ep.ID,
		ScanID:                  ep.ScanID,
		Method:                  ep.Method,
		PathTemplate:            ep.PathTemplate,
		OperationID:             ep.OperationID,
		SecuritySchemeHints:     ep.SecuritySchemeHints,
		RequestContentTypes:     ep.RequestContentTypes,
		ResponseContentTypes:    ep.ResponseContentTypes,
		RequestBodyJSON:         ep.RequestBodyJSON,
		CreatedAt:               ep.CreatedAt,
		DeclaresOpenAPISecurity: len(ep.SecuritySchemeHints) > 0,
	}
	if includeSummary {
		r.Summary = &EndpointInventorySummaryRead{
			BaselineExecutionsRecorded: ent.Summary.BaselineExecutionsRecorded,
			MutationExecutionsRecorded: ent.Summary.MutationExecutionsRecorded,
			FindingsRecorded:           ent.Summary.FindingsRecorded,
		}
	}
	return r
}

func endpointInvestigationReadFromInventory(ent storage.EndpointInventoryEntry) EndpointInvestigationRead {
	out := EndpointInvestigationRead{}
	if ent.Investigation == nil {
		return out
	}
	inv := ent.Investigation
	if ent.Summary.BaselineExecutionsRecorded > 0 && inv.LatestBaselineResponseStatus != nil {
		out.Baseline = &EndpointPhaseInvestigationRead{LatestResponseStatus: *inv.LatestBaselineResponseStatus}
	}
	if ent.Summary.MutationExecutionsRecorded > 0 && inv.LatestMutatedResponseStatus != nil {
		out.Mutation = &EndpointPhaseInvestigationRead{LatestResponseStatus: *inv.LatestMutatedResponseStatus}
	}
	if ent.Summary.FindingsRecorded > 0 {
		fr := &EndpointFindingsInvestigationRead{}
		if len(inv.FindingsByAssessmentTier) > 0 {
			cp := make(map[string]int, len(inv.FindingsByAssessmentTier))
			for k, v := range inv.FindingsByAssessmentTier {
				cp[k] = v
			}
			fr.ByAssessmentTier = cp
		}
		out.Findings = fr
	}
	return out
}

func endpointDetailFromInventory(ent storage.EndpointInventoryEntry) EndpointDetailResponse {
	r := endpointReadFromInventory(ent, true)
	id := ent.Endpoint.ID
	sid := ent.Endpoint.ScanID
	q := fmt.Sprintf("scan_endpoint_id=%s", id)
	return EndpointDetailResponse{
		EndpointRead:  r,
		Investigation: endpointInvestigationReadFromInventory(ent),
		Drilldown:     endpointDrilldownHints(sid, id, q, q),
	}
}
