package platformapi

import (
	"encoding/csv"
	"net/http"
	"time"

	"github.com/ClatTribe/tsengine/internal/exporter"
	"github.com/ClatTribe/tsengine/internal/report"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// handleFindingsExport renders the tenant's findings as a portable artifact for an
// auditor / pipeline / another tool: SARIF (default — GitHub code-scanning ingestible) or
// CSV (`?format=csv`). It reuses the engine's report→SARIF path so platform exports match
// the engine's exactly.
func (d Deps) handleFindingsExport(w http.ResponseWriter, r *http.Request, tenantID string) {
	findings, err := d.Store.ListFindings(r.Context(), tenantID, store.FindingFilter{})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	rep := report.FromScan(types.Scan{
		ScanID:           "export-" + tenantID,
		Asset:            types.Asset{Target: tenantID},
		FindingsEnriched: findings,
	}, time.Now())

	switch r.URL.Query().Get("format") {
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="findings.csv"`)
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"id", "severity", "status", "tool", "title", "endpoint"})
		for _, f := range rep.Findings {
			_ = cw.Write([]string{f.ID, f.Severity, f.Status, f.Tool, f.Title, f.Endpoint})
		}
		cw.Flush()
	default: // sarif
		b, serr := exporter.ToSARIF(rep)
		if serr != nil {
			writeJSON(w, http.StatusInternalServerError, errBody(serr.Error()))
			return
		}
		w.Header().Set("Content-Type", "application/sarif+json")
		w.Header().Set("Content-Disposition", `attachment; filename="findings.sarif"`)
		_, _ = w.Write(b)
	}
}
