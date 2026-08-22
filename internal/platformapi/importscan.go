package platformapi

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/importers"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// importscan.go accepts a customer's EXISTING scanner backlog — Snyk, Dependabot, or any SARIF.
//
// This is the cheapest path to value in the product and the only one that needs no OAuth, no
// sandbox and no model: a team that already runs Snyk has thousands of findings they cannot clear,
// and the question they actually have is not "what else is wrong" but "which of these 4,000 things
// can an attacker reach". Answering that requires their list, so we take it.
//
// The parsers already existed (internal/importers) and were reachable only from the CLI. A customer
// using the product could not import anything, which made the whole capability invisible — the same
// built-but-unreachable pattern that has produced several bugs here.
//
// # Sized against measurements, not guesses
//
// A real Snyk export was generated at three sizes and run through the full pipeline:
//
//	 4,000 findings ·  2.4 MB · parse 19ms · store 204ms · enrich  6ms
//	20,000 findings · 11.1 MB · parse 64ms · store 829ms · enrich 30ms
//	50,000 findings · 27.8 MB · parse 151ms · store 2.05s · enrich 71ms
//
// Two things follow. The 1MB body cap most handlers use would have rejected a 4,000-finding export
// outright, so the cap here is 64MB — comfortably past the 50,000 measurement. And the work is real
// enough (seconds, not milliseconds) that it runs OFF the request path as a job, because a customer
// uploading their backlog should get an immediate answer about whether the file was accepted, not a
// connection held open while we write fifty thousand rows.
//
// The store write path scales fine one-at-a-time (2s for 50,000), so this deliberately does NOT add
// a batch-write API. That would be an optimisation of the part that already works; the cost that
// actually mattered was on the read side and is addressed by findings_summary.go.

// maxImportBytes bounds the upload. 64MB is ~115,000 findings at the measured density — larger than
// any export this ICP produces, and small enough that a malicious upload cannot exhaust memory.
const maxImportBytes = 64 << 20

type importResponse struct {
	JobID    string `json:"job_id,omitempty"`
	Format   string `json:"format"`
	Findings int    `json:"findings"`
	Stored   int    `json:"stored"`
	Detail   string `json:"detail"`
}

// handleImportScan ingests a third-party scanner export.
//
//	?format=  snyk | dependabot | sarif | auto (default)
//	?target=  what the report is about (repo name / URL), used as the finding endpoint when the
//	          report does not carry one.
func (d Deps) handleImportScan(w http.ResponseWriter, r *http.Request, tenantID string) {
	format := strings.TrimSpace(r.URL.Query().Get("format"))
	if format == "" {
		format = string(importers.FormatAuto)
	}
	target := strings.TrimSpace(r.URL.Query().Get("target"))

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxImportBytes))
	if err != nil {
		// Say which limit was hit and what it means. "Request entity too large" sends someone
		// hunting through docs; a number they can compare their file against does not.
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{
			"error": fmt.Sprintf("that export is larger than the %dMB we accept in one upload — "+
				"split it by project and import each part", maxImportBytes>>20),
			"reason": "import_too_large",
		})
		return
	}
	if len(body) == 0 {
		writeJSON(w, http.StatusBadRequest, errBody("the upload was empty"))
		return
	}

	// Parse BEFORE queueing. A malformed file must fail while the customer is still looking at the
	// screen — queueing it would turn a typo into a job that fails somewhere they never look.
	scan, perr := importers.Import(body, importers.Format(format), target, time.Now().UTC())
	if perr != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":  "could not read that export: " + perr.Error(),
			"reason": "unparseable",
		})
		return
	}
	found := scan.FindingsRaw
	if len(found) == 0 {
		// An export with no findings is a real answer — a clean Snyk run — and must not read as a
		// failed import.
		writeJSON(w, http.StatusOK, importResponse{
			Format: format, Detail: "That export contains no findings. Nothing to import.",
		})
		return
	}

	// Small imports finish inline so the customer sees the result immediately; large ones go to the
	// job pool. The threshold is where the measurements say the work stops being instant.
	if d.Jobs == nil || len(found) <= inlineImportLimit {
		stored := d.storeImported(r.Context(), tenantID, found)
		writeJSON(w, http.StatusOK, importResponse{
			Format: format, Findings: len(found), Stored: stored,
			Detail: plural(stored, "finding is", "findings are") + " now in your issues, ready to be " +
				"triaged and tested for exploitability.",
		})
		return
	}

	job, jerr := d.Jobs.Enqueue("import", tenantID, func(ctx context.Context) (any, error) {
		return d.storeImported(ctx, tenantID, found), nil
	})
	if jerr != nil {
		writeJSON(w, http.StatusTooManyRequests, errBody("too many imports running — try again shortly"))
		return
	}
	writeJSON(w, http.StatusAccepted, importResponse{
		JobID: job.ID, Format: format, Findings: len(found),
		Detail: plural(len(found), "finding is", "findings are") + " importing in the background. " +
			"They appear in your issues as they land.",
	})
}

// inlineImportLimit is where an import stops being instant. Below this the measured cost is well
// under a second end to end, so holding the request is kinder than making the customer poll.
const inlineImportLimit = 2000

// storeImported enriches and stores, reporting how many actually landed.
//
// It runs the SAME L1.5 chain as every other ingest door (enrichFindings), so an imported Snyk
// finding gains KEV/EPSS, exploitability and compliance mapping exactly like one we found ourselves.
// That is the point: the customer's existing backlog becomes first-class evidence rather than a
// second-class list we merely display.
func (d Deps) storeImported(ctx context.Context, tenantID string, fs []types.Finding) int {
	stored := 0
	for _, f := range enrichFindings(fs) {
		if err := d.Store.PutFinding(ctx, tenantID, f); err != nil {
			continue
		}
		d.foldIntoPosture(ctx, tenantID, []types.Finding{f})
		stored++
	}
	// Deliberately NOT proposing a fix for every imported finding. An import of 20,000 findings would
	// queue 20,000 proposals, which is not a worklist — it is the same backlog with our name on it.
	// The customer asks for fixes per practice or per issue, once they have decided what matters.
	if d.Recorder != nil && stored > 0 {
		d.Recorder.Record("scanner export imported", "import",
			map[string]any{"tenant_id": tenantID, "findings": stored}, "third-party scanner import")
	}
	return stored
}
