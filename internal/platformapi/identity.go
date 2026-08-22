package platformapi

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/ClatTribe/tsengine/internal/identitythreat"
	"github.com/ClatTribe/tsengine/internal/tracer/hooks"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// handleIngestIdentityEvents is the real-time identity-threat (ITDR) ingest (ADR 0010 Phase 5
// wiring). An IdP connector (or the customer) POSTs identity audit events (Okta System Log /
// Google Admin / M365 audit); the deterministic detector (impossible_travel, privileged_grant,
// mfa_removed, password_spray) runs over them and emits findings into the SAME store the rest of
// the platform reads — so identity threats flow through issues / incidents / grc / hitl like any
// other finding. Mirrors the runtime-events ingest. Tenant-scoped (body tenant ignored for
// isolation). LLM-free + grounded (§10).
func (d Deps) handleIngestIdentityEvents(w http.ResponseWriter, r *http.Request, tenantID string) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	// Accept a single event or an array.
	var events []identitythreat.Event
	if err := json.Unmarshal(raw, &events); err != nil {
		var one identitythreat.Event
		if err2 := json.Unmarshal(raw, &one); err2 != nil {
			writeJSON(w, http.StatusBadRequest, errBody("body must be an identity event or an array of them"))
			return
		}
		events = []identitythreat.Event{one}
	}

	threats := identitythreat.Detect(events, identitythreat.Config{})
	findings := identitythreat.Findings(threats)
	findings = enrichFindings(findings) // L1.5 parity (§11) — threat-intel/exploitability/confidence + the CWE→control map below stays as the L15-disabled fallback
	// Map each identity threat to the compliance controls it affects (§8) — these are access-control /
	// authentication issues, so an MFA-removed or privileged-grant IS a SOC 2 CC6.x / NIST IA-2 gap.
	// Without this they'd carry no control mapping and never surface in the founder's compliance posture.
	comp := hooks.NewCompliance()
	stored := 0
	saved := make([]types.Finding, 0, len(findings))
	for _, f := range findings {
		f.ID = d.newID("idt")
		if c, ok := comp.Lookup(f.CWE); ok {
			f.Compliance = c
		}
		if perr := d.Store.PutFinding(r.Context(), tenantID, f); perr != nil {
			respond(w, nil, perr)
			return
		}
		// Fold the finding into the compliance posture so the identity threat shows up as a real
		// control gap (SOC 2 CC6.x / NIST IA-2 …) in the founder's posture — not just a raw finding.
		d.foldIntoPosture(r.Context(), tenantID, []types.Finding{f})
		saved = append(saved, f)
		stored++
	}
	// Open an incident for any high-severity threat right now — the scan-pass reconcile never sees
	// these ingested findings, so without this a new MFA-removed / privileged-grant would never raise
	// a "new since last scan" incident. Open-only (no resolve sweep). Best-effort.
	if d.IncidentOpener != nil && stored > 0 {
		_, _ = d.IncidentOpener.OpenFor(r.Context(), tenantID, saved, nil)
	}
	if d.Recorder != nil && stored > 0 {
		d.Recorder.Record("identity threats detected", "identity_threat",
			map[string]any{"tenant_id": tenantID, "events": len(events), "threats": stored}, "ITDR ingest")
	}
	// WHAT THIS BATCH COULD NOT LOOK FOR. Detection is correlation-based and runs over the batch it
	// is given: impossible travel needs two sign-ins in different countries, spray needs a run of
	// failures, MFA fatigue needs repeated challenges. Post a single login and none of the nine rules
	// can fire — yet "threats_detected: 0" reads as "identity is clean". It matters most for a
	// customer streaming IdP events one per request, who would get zero forever while it looked like
	// it was working. The device-posture ingest already reports checks_not_run for exactly this
	// reason; the field name is shared so the two read the same way.
	resp := map[string]any{
		"events_ingested":  len(events),
		"threats_detected": stored,
		"threats":          threats,
	}
	if notRun := identitythreat.Unevaluated(events); len(notRun) > 0 {
		resp["checks_not_run"] = notRun
	}
	writeJSON(w, http.StatusOK, resp)
}
