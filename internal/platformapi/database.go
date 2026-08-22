package platformapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/ClatTribe/tsengine/internal/connector/pgcollect"
	"github.com/ClatTribe/tsengine/internal/dataplatform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// database.go connects a customer's Postgres — the Series A integration that needs no OAuth.
//
// Supabase and Neon are both Postgres, so this one endpoint covers the database layer for most of the
// segment, and it covers the layer that matters most: every attack path in the product is pointed at
// the customer's data, and this is what lets us name the TABLE rather than stop at "your database".
//
// A connection string is something the customer already has. That is the whole point — every other
// integration begins with an OAuth dance and ships as a "posted snapshot" they have no way to produce.
//
// # The credential is never stored
//
// A production database DSN is the most dangerous secret a customer can hand us: it is not scoped, not
// revocable per-use, and it opens the data itself rather than a description of it. So this endpoint
// uses it for one collection and drops it. We do not seal it, we do not persist it, and there is no
// code path that could later re-read it — because the safest place for a credential of that power is
// nowhere. A customer who wants continuous monitoring re-posts it, or connects a scoped read-only role
// (which is what the response tells them to do).
//
// # Metadata only unless they say otherwise
//
// pgcollect reads the catalog and never a customer row. Value sampling — which would upgrade
// classifications from "suspected" to "confirmed" — is an explicit opt-in on the request, because
// reading their actual SSNs is a different act from reading their schema.

type dbConnectRequest struct {
	// DSN is the Postgres connection string (postgres://…). Used once, never stored.
	DSN string `json:"dsn"`
	// Schemas optionally limits the scan. Empty → every non-system schema.
	Schemas []string `json:"schemas,omitempty"`
	// SampleValues opts in to reading a bounded sample of column values so data classification is
	// value-proven rather than name-based. Off unless the customer sets it.
	SampleValues bool `json:"sample_values,omitempty"`
}

// handleDatabaseScan collects a Postgres database's access posture and stores the findings.
func (d Deps) handleDatabaseScan(w http.ResponseWriter, r *http.Request, tenantID string) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	var req dbConnectRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid body: "+err.Error()))
		return
	}
	if strings.TrimSpace(req.DSN) == "" {
		writeJSON(w, http.StatusBadRequest, errBody(
			"dsn is required — paste the Postgres connection string from Supabase, Neon, RDS or your own host"))
		return
	}

	opts := pgcollect.Options{Schemas: req.Schemas}
	if req.SampleValues {
		opts.SampleRows = 5
	}
	res, cerr := pgcollect.Collect(r.Context(), req.DSN, opts)
	if cerr != nil {
		// The error is the customer's to act on (bad host, wrong password, no network route), so it is
		// returned rather than swallowed — but never with the DSN echoed back into a response or a log.
		writeJSON(w, http.StatusBadGateway, errBody("could not read the database: "+redactDSN(cerr.Error())))
		return
	}

	// Discover sensitivity from the collected columns before assessing, so the severity of a public
	// grant reflects what the table actually holds.
	est, discoveries := dataplatform.Classify(res.Estate)
	findings := dataplatform.Assess(est, dataplatform.Options{})
	findings = enrichFindings(findings) // L1.5 parity (§11)

	stored := 0
	saved := make([]types.Finding, 0, len(findings))
	for i, f := range findings {
		f.ID = d.newID("db") + "-" + strconv.Itoa(i)
		if err := d.Store.PutFinding(r.Context(), tenantID, f); err != nil {
			continue
		}
		d.foldIntoPosture(r.Context(), tenantID, []types.Finding{f})
		saved = append(saved, f)
		stored++
	}
	if d.IncidentOpener != nil && stored > 0 {
		_, _ = d.IncidentOpener.OpenFor(r.Context(), tenantID, saved, nil)
	}
	if d.Recorder != nil {
		// Ledger-recorded WITHOUT the DSN: that a database was scanned is worth an audit trail; the
		// credential is not.
		d.Recorder.Record("database scanned", "data_platform",
			map[string]any{"tenant_id": tenantID, "tables": len(est.Objects), "findings": stored,
				"sampled": res.Sampled}, "postgres access-posture collection")
	}

	tables := len(est.Objects)
	grants := 0
	for _, o := range est.Objects {
		grants += len(o.Grants)
	}
	if findings == nil {
		findings = []types.Finding{}
	}
	resp := map[string]any{
		"tables": tables, "grants": grants, "issues_detected": stored,
		"schemas_scanned": res.SchemasScanned, "findings": findings,
		"note": res.Note,
		// Say plainly that we did not keep it. A customer pasting a production DSN deserves to be told
		// what happened to it rather than left to assume.
		"credential_retained": false,
		"credential_note": "This connection string was used for this scan and not stored. Re-run the scan " +
			"to refresh, or connect a scoped read-only role for continuous monitoring.",
	}
	if len(discoveries) > 0 {
		resp["discovered_sensitive"] = discoveries
	}
	if !res.Sampled {
		resp["deeper_scan_available"] = "Set sample_values to let us read a few values per column and " +
			"CONFIRM which tables hold personal data. Without it we classify from column names, which is a " +
			"strong hint rather than proof."
	}
	writeJSON(w, http.StatusOK, resp)
}

// redactDSN strips anything password-shaped out of a driver error before it reaches a response or a
// log. Driver errors quote the connection string surprisingly often, and a leaked production password
// in an error body would be a breach we caused while looking for breaches.
func redactDSN(msg string) string {
	out := msg
	for _, scheme := range []string{"postgres://", "postgresql://"} {
		out = redactFrom(out, scheme, scheme+"[redacted]")
	}
	// Bare password= form (key/value DSNs). Case-insensitive because drivers are inconsistent.
	for _, key := range []string{"password=", "PASSWORD=", "Password="} {
		out = redactFrom(out, key, key+"[redacted]")
	}
	return out
}

// redactFrom replaces every credential run that starts with marker, scanning from an ADVANCING offset.
//
// The offset is the whole point: the replacement text still CONTAINS the marker (we keep "postgres://"
// so the error stays readable), so restarting the search from zero would find the same marker forever.
// The first version of this function did exactly that and hung a request handler — a self-inflicted
// denial of service in the code meant to protect the customer's password.
func redactFrom(s, marker, replacement string) string {
	from := 0
	for {
		rel := strings.Index(s[from:], marker)
		if rel < 0 {
			return s
		}
		i := from + rel
		end := i + len(marker)
		for end < len(s) && !isDSNTerminator(s[end]) {
			end++
		}
		s = s[:i] + replacement + s[end:]
		from = i + len(replacement) // past what we just wrote, so the marker inside it is not re-found
	}
}

func isDSNTerminator(c byte) bool {
	return c == ' ' || c == '"' || c == '\'' || c == ',' || c == ')' || c == '\n' || c == '\t'
}
