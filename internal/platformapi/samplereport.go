package platformapi

import (
	"io"
	"net/http"
	"time"

	"github.com/ClatTribe/tsengine/internal/grc"
	"github.com/ClatTribe/tsengine/internal/samplereport"
)

// handleSampleReport serves the PUBLIC sample VAPT report — the asset a prospect reads
// before they have an account, and the highest-leverage thing on the marketing site.
//
// PUBLIC AND UNGATED, deliberately. An email wall in front of a sample report buys a lead
// list and costs the reader who was going to become a customer: the whole argument for this
// product is that its reports are generated from grounded posture rather than written, and a
// reader cannot check that claim through a form. The lead capture already exists one step
// along, at /scan, which assesses the prospect's OWN domain — a far better magnet than a
// document about a fictional one.
//
// It is generated on every request by the SAME grc renderer a paying customer's report goes
// through (see internal/samplereport for why that is structural rather than stylistic), so
// it cannot drift from the product the way an uploaded PDF does.
//
//	GET /v1/sample-report                → Markdown (default)
//	GET /v1/sample-report?format=html    → the print-ready deliverable (Save as PDF)
//	GET /v1/sample-report?format=json    → the raw report object
//	&download=1                          → Content-Disposition: attachment
//
// No rate limiting: unlike /v1/assess this performs no probe, reaches no network, touches no
// store and reads no tenant data — it renders a fixed in-memory dataset. There is nothing
// here for a limiter to protect.
func (d Deps) handleSampleReport(w http.ResponseWriter, r *http.Request) {
	rep := samplereport.Report(time.Now().UTC())
	// Reassess is what turns the declared coverage gaps into the report's closing verdict. The
	// tenant path calls it for exactly this reason: without it a report can list unscanned scope
	// at the top and still close by calling the estate clean. The sample must carry the same
	// verdict logic or it advertises an honesty the product would not actually deliver.
	grc.Reassess(rep)

	filename := "tensorshield-sample-vapt-report"
	download := r.URL.Query().Get("download") != ""

	switch r.URL.Query().Get("format") {
	case "json":
		if download {
			w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`.json"`)
		}
		writeJSON(w, http.StatusOK, rep)
	case "html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if download {
			w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`.html"`)
		}
		_, _ = io.WriteString(w, grc.RenderVAPTHTML(rep))
	default:
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		if download {
			w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`.md"`)
		}
		_, _ = io.WriteString(w, grc.RenderVAPTMarkdown(rep))
	}
}
