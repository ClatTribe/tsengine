package platformapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"github.com/ClatTribe/tsengine/internal/dataplatform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// handleDataPlatformIngest is the DATA-WAREHOUSE ACCESS-POSTURE ingest — who can read which table.
//
// The engine already reaches warehouses as cloud RESOURCES (cloudgraph classifies BigQuery, Redshift and
// friends as data stores), so an attack path can say "this leads to data". It could not say who holds
// the keys INSIDE: a warehouse runs its own grant system beneath cloud IAM, and Snowflake is not a cloud
// resource at all, so it never appeared in an inventory. This closes that step — the table, and the
// grant that exposes it.
//
// A connector (or the customer) POSTs the grant snapshot; dataplatform.Assess surfaces grounded findings
// into the same store, flowing through issues/incidents/grc/hitl like any other. Grounded + LLM-free: a
// well-governed warehouse yields zero. Live collectors (Snowflake ACCOUNT_USAGE, BigQuery getIamPolicy,
// Postgres information_schema) are the credential-gated half; the posted-snapshot path works today,
// mirroring the OSINT / SaaS-posture / tprm / device ingests.
func (d Deps) handleDataPlatformIngest(w http.ResponseWriter, r *http.Request, tenantID string) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	var est dataplatform.Estate
	if err := json.Unmarshal(raw, &est); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid data-platform snapshot: "+err.Error()))
		return
	}

	findings := dataplatform.Assess(est, dataplatform.Options{})
	findings = enrichFindings(findings) // L1.5 parity (§11)
	stored := 0
	saved := make([]types.Finding, 0, len(findings))
	for i, f := range findings {
		f.ID = d.newID("dp") + "-" + strconv.Itoa(i)
		if err := d.Store.PutFinding(r.Context(), tenantID, f); err != nil {
			continue
		}
		if d.GRC != nil {
			_ = d.GRC.Apply(r.Context(), tenantID, f)
		}
		saved = append(saved, f)
		stored++
	}
	if d.IncidentOpener != nil && stored > 0 {
		_, _ = d.IncidentOpener.OpenFor(r.Context(), tenantID, saved, nil)
	}
	if d.Recorder != nil && stored > 0 {
		d.Recorder.Record("data-platform access assessed", "data_platform",
			map[string]any{"tenant_id": tenantID, "objects": len(est.Objects), "findings": stored},
			"data-platform grant-snapshot ingest")
	}

	grants := 0
	for _, o := range est.Objects {
		grants += len(o.Grants)
	}
	if findings == nil {
		findings = []types.Finding{}
	}
	resp := map[string]any{
		"objects": len(est.Objects), "grants": grants, "issues_detected": stored, "findings": findings,
	}
	// Say which checks did NOT run, rather than letting a clean result read as a clean warehouse. Both
	// gaps are silent by design (§10 — we will not guess who is internal, and unknown is not unused), so
	// silence about the gap is the one thing that would make the refusal dishonest.
	var limits []string
	if len(est.OrgDomains) == 0 {
		limits = append(limits, "No org_domains were supplied, so external-grantee checks did not run — "+
			"we cannot tell a contractor from an employee without being told which domains are yours.")
	}
	if !anyLastUsed(est) {
		limits = append(limits, "No grant carried a last_used timestamp, so stale-access checks did not "+
			"run. An unrecorded grant is unknown, not unused.")
	}
	if !anySensitive(est) {
		limits = append(limits, "No object is declared sensitive, so regulated-data checks did not run. "+
			"Sensitivity is a declared fact here — we do not infer it from table names.")
	}
	if len(limits) > 0 {
		resp["checks_not_run"] = limits
	}
	writeJSON(w, http.StatusOK, resp)
}

func anyLastUsed(est dataplatform.Estate) bool {
	for _, o := range est.Objects {
		for _, g := range o.Grants {
			if g.LastUsed != "" {
				return true
			}
		}
	}
	return false
}

func anySensitive(est dataplatform.Estate) bool {
	for _, o := range est.Objects {
		if o.Sensitive {
			return true
		}
	}
	return false
}
