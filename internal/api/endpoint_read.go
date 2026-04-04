package api

import "github.com/codethor0/axiom-api-scanner/internal/storage"

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
