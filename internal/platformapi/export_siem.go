package platformapi

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// export_siem.go emits findings as newline-delimited JSON — the shape every log platform ingests.
//
// The existing export already offers SARIF, CSV and a JSON document, and its comment claims JSON
// serves "a SIEM ingest". It does not, quite. Splunk HEC, Datadog's log intake, Panther and the
// Elastic bulk API all consume ONE EVENT PER LINE; handed a wrapped array they either reject it or
// swallow the whole thing as a single enormous event, which is worse because it looks like it worked.
//
// The second reason is size. A workspace that imported its scanner backlog has tens of thousands of
// findings — a measured 27MB for 50,000 — and a document format forces the consumer to hold all of it
// in memory before the first record is usable. NDJSON streams: the reader handles line one before
// line two exists.
//
// # This is an export, not a SIEM
//
// We do not aggregate, correlate across sources, or alert on their logs. Their SIEM does that, and
// competing with it would be a worse product than being the tool that talks to it. This is findings
// out, in the shape the receiving end already parses.
//
// # The event shape is FLAT, deliberately
//
// Nested objects are where SIEM field extraction goes wrong: a search for severity has to know
// whether it is `severity` or `finding.severity` or `enrichment.exploitability.severity`. Flat keys
// with a stable prefix survive a schema change on our side and stay searchable on theirs.

// siemEvent is one finding as a log platform wants it: flat, stable keys, no nesting.
type siemEvent struct {
	Time     string `json:"time"` // RFC3339 — every platform parses it
	Tenant   string `json:"tenant"`
	ID       string `json:"finding_id"`
	RuleID   string `json:"rule_id"`
	Tool     string `json:"tool"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Endpoint string `json:"endpoint,omitempty"`
	CWE      string `json:"cwe,omitempty"` // comma-joined: a list field breaks naive extraction
	CVE      string `json:"cve,omitempty"`
	Verified string `json:"verification_status,omitempty"`
	// KEV and EPSS ride along because they are the two fields an on-call engineer actually filters
	// on, and re-deriving them on the SIEM side would need the whole threat-intel corpus.
	KEV  bool    `json:"kev,omitempty"`
	EPSS float64 `json:"epss,omitempty"`
	// Source names us, so a rule on their side can scope to our events without matching on shape.
	Source string `json:"source"`
}

// handleFindingsSIEMExport streams findings as NDJSON.
func (d Deps) handleFindingsSIEMExport(w http.ResponseWriter, r *http.Request, tenantID string) {
	limit, offset := pageParams(r)
	findings, err := d.Store.ListFindings(r.Context(), tenantID, store.FindingFilter{
		Severity: severityParam(r), Status: r.URL.Query().Get("status"),
		Limit: limit, Offset: offset,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", `attachment; filename="findings.ndjson"`)
	enc := json.NewEncoder(w)
	// Written one at a time rather than built into a slice first: the point of NDJSON is that neither
	// side has to hold the whole set, and buffering it here would give up half of that.
	for _, f := range findings {
		if err := enc.Encode(siemEventFor(tenantID, f)); err != nil {
			// The client hung up mid-stream. Nothing useful to say to a closed connection, and a
			// partial export is not a server fault.
			return
		}
	}
	// An empty result writes NOTHING, which is correct for NDJSON — zero events is an empty body, not
	// an empty array. A consumer counting lines gets zero, which is the true answer.
}

func siemEventFor(tenantID string, f types.Finding) siemEvent {
	e := siemEvent{
		Time:     f.DiscoveredAt.UTC().Format(time.RFC3339),
		Tenant:   tenantID,
		ID:       f.ID,
		RuleID:   f.RuleID,
		Tool:     f.Tool,
		Severity: string(f.Severity),
		Title:    f.Title,
		Endpoint: f.Endpoint,
		CWE:      strings.Join(f.CWE, ","),
		Verified: string(f.VerificationStatus),
		Source:   "tensorshield",
	}
	if f.DiscoveredAt.IsZero() {
		// A zero time serializes as year 1, which a log platform will either reject or file in 0001.
		// Neither is useful; the export time is honest about being an export time.
		e.Time = time.Now().UTC().Format(time.RFC3339)
	}
	// The CVE is not a field — it lives in the rule id or title, and the enrichment chain finds it the
	// same way (hooks.hasCVE). Matching that here keeps the export agreeing with the enrichment rather
	// than inventing a second notion of "has a CVE".
	e.CVE = firstCVE(f.RuleID, f.Title)
	if ti := f.ThreatIntel; ti != nil {
		if ti.KEV != nil {
			e.KEV = ti.KEV.Listed
		}
		if ti.EPSS != nil {
			e.EPSS = ti.EPSS.Score
		}
	}
	return e
}

// cveRe matches a CVE id wherever it appears. Mirrors the enrichment chain's own matcher.
var cveRe = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)

// firstCVE returns the first CVE found across the given strings, or "" — an empty CVE field is
// omitted from the event rather than exported as a blank a SIEM rule might match on.
func firstCVE(in ...string) string {
	for _, s := range in {
		if m := cveRe.FindString(s); m != "" {
			return m
		}
	}
	return ""
}
