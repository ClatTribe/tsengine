package platformapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/ClatTribe/tsengine/internal/grc"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/ledger"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

func auditDeps(t *testing.T) (Deps, *ledger.Recorder) {
	t.Helper()
	st := store.NewMemory()
	ctx := context.Background()
	if err := st.PutTenant(ctx, platform.Tenant{ID: "ten-1"}); err != nil {
		t.Fatal(err)
	}
	// two SOC2 controls in posture → the engagement seeds two pending attestations
	_ = st.UpsertControlState(ctx, platform.ControlState{TenantID: "ten-1", Framework: "soc2", ControlID: "CC6.1", State: platform.ControlMet})
	_ = st.UpsertControlState(ctx, platform.ControlState{TenantID: "ten-1", Framework: "soc2", ControlID: "CC7.1", State: platform.ControlGap})
	n := 0
	rec := ledger.NewRecorder()
	return Deps{Store: st, Recorder: rec, NewID: func() string { n++; return fmt.Sprintf("a%d", n) }}, rec
}

func TestAudits_CreateAttestIssue(t *testing.T) {
	d, rec := auditDeps(t)

	// 1) create → seeds the two posture controls as pending; status planning
	crec := call(d, d.handleCreateAudit, http.MethodPost, "/v1/audits",
		`{"framework":"soc2","audit_type":"type_i","auditor_name":"Pat Lee, CPA","auditor_firm":"Lee Assurance"}`, "")
	if crec.Code != http.StatusOK {
		t.Fatalf("create: %d %s", crec.Code, crec.Body.String())
	}
	var av struct {
		platform.AuditEngagement
		Summary grc.AuditSummary `json:"summary"`
	}
	_ = json.Unmarshal(crec.Body.Bytes(), &av)
	if av.Summary.Total != 2 || av.Summary.Pending != 2 || av.Status != platform.AuditPlanning {
		t.Fatalf("create should seed 2 pending controls in planning, got %+v / %+v", av.AuditEngagement, av.Summary)
	}
	id := av.ID

	// 2) attest requires a named auditor + a valid verdict
	if r := call(d, d.handleAttestControl, http.MethodPost, "/x", `{"control_id":"CC6.1","verdict":"passed"}`, id); r.Code != http.StatusBadRequest {
		t.Errorf("attest without attested_by must be 400, got %d", r.Code)
	}
	if r := call(d, d.handleAttestControl, http.MethodPost, "/x", `{"control_id":"CC6.1","verdict":"maybe","attested_by":"Pat"}`, id); r.Code != http.StatusBadRequest {
		t.Errorf("invalid verdict must be 400, got %d", r.Code)
	}

	// 3) the auditor attests both controls → fieldwork, ledger-recorded
	a1 := call(d, d.handleAttestControl, http.MethodPost, "/x", `{"control_id":"CC6.1","verdict":"passed","attested_by":"Pat Lee, CPA"}`, id)
	if a1.Code != http.StatusOK {
		t.Fatalf("attest CC6.1: %d %s", a1.Code, a1.Body.String())
	}
	var afterFirst struct {
		platform.AuditEngagement
	}
	_ = json.Unmarshal(a1.Body.Bytes(), &afterFirst)
	if afterFirst.Status != platform.AuditFieldwork {
		t.Errorf("first attestation should move engagement to fieldwork, got %q", afterFirst.Status)
	}
	// issue before all attested → 400
	if r := call(d, d.handleIssueAudit, http.MethodPost, "/x", "", id); r.Code != http.StatusBadRequest {
		t.Errorf("issue with a pending control must be 400, got %d", r.Code)
	}
	call(d, d.handleAttestControl, http.MethodPost, "/x", `{"control_id":"CC7.1","verdict":"exception","note":"remediation in flight","attested_by":"Pat Lee, CPA"}`, id)

	// 4) issue → issued + ledger ref; the named auditor is the signer
	irec := call(d, d.handleIssueAudit, http.MethodPost, "/x", "", id)
	if irec.Code != http.StatusOK {
		t.Fatalf("issue: %d %s", irec.Code, irec.Body.String())
	}
	var issued struct {
		platform.AuditEngagement
	}
	_ = json.Unmarshal(irec.Body.Bytes(), &issued)
	if issued.Status != platform.AuditIssued || issued.LedgerRef == "" || issued.IssuedAt.IsZero() {
		t.Fatalf("issued engagement missing status/ledger/timestamp: %+v", issued.AuditEngagement)
	}
	if len(rec.Steps()) < 3 { // 2 attestations + 1 issue
		t.Errorf("each auditor action must be recorded into the ledger, got %d steps", len(rec.Steps()))
	}
}
