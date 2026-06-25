package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/ClatTribe/tsengine/internal/pentest"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/ledger"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// A risk decided by a practitioner-of-record records their capacity + firm; an unknown actor defaults
// to internal — so the artifact is honest about who accepted the risk and in what capacity.
func TestRiskDecision_RecordsPractitionerCapacity(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	_ = st.PutTenant(ctx, platform.Tenant{
		ID: "ten-1",
		Practitioners: []platform.Practitioner{
			{ID: "p1", Name: "Jordan Lee", Firm: "AcmeMSP", Capacity: platform.CapacityMSP},
		},
	})
	_ = st.PutFinding(ctx, "ten-1", types.Finding{ID: "f1", Tool: "sqlmap", Severity: types.SeverityHigh, CWE: []string{"CWE-89"}})
	d := Deps{Store: st, Recorder: ledger.NewRecorder()}
	_ = call(d, d.handleSeedRisks, http.MethodPost, "/v1/risks/seed", "", "")

	// decided by the MSP practitioner → capacity msp + firm AcmeMSP
	drec := call(d, d.handleDecideRisk, http.MethodPost, "/x", `{"treatment":"mitigate","owner":"Jordan Lee"}`, "risk-injection")
	var decided platform.Risk
	_ = json.Unmarshal(drec.Body.Bytes(), &decided)
	if decided.Capacity != platform.CapacityMSP || decided.Firm != "AcmeMSP" {
		t.Fatalf("expected msp/AcmeMSP capacity, got %q/%q", decided.Capacity, decided.Firm)
	}

	// re-decided by an unknown actor → internal, no firm
	d2 := call(d, d.handleDecideRisk, http.MethodPost, "/x", `{"treatment":"accept","owner":"Some Founder"}`, "risk-injection")
	var decided2 platform.Risk
	_ = json.Unmarshal(d2.Body.Bytes(), &decided2)
	if decided2.Capacity != platform.CapacityInternal || decided2.Firm != "" {
		t.Fatalf("unknown actor must default to internal, got %q/%q", decided2.Capacity, decided2.Firm)
	}
}

// A pentest sign-off by a managed (our) practitioner records the managed capacity + firm — the named
// accountability is honest that our delivery expert signed.
func TestPentestSignoff_RecordsCapacity(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	_ = st.PutTenant(ctx, platform.Tenant{
		ID: "ten-1",
		Practitioners: []platform.Practitioner{
			{ID: "p1", Name: "Dana Reed", Email: "dana@ts.io", Firm: "TensorShield Managed", Capacity: platform.CapacityManaged},
		},
	})
	_ = st.PutPentest(ctx, pentest.Engagement{ID: "pt-1", TenantID: "ten-1", Name: "Q3"})
	d := Deps{Store: st, Recorder: ledger.NewRecorder()}

	rec := call(d, d.handleSignoffPentest, http.MethodPost, "/x", `{"signer":"dana@ts.io","role":"Lead Pentester"}`, "pt-1")
	var eng pentest.Engagement
	_ = json.Unmarshal(rec.Body.Bytes(), &eng)
	if eng.Signoff == nil || eng.Signoff.Capacity != platform.CapacityManaged || eng.Signoff.Firm != "TensorShield Managed" {
		t.Fatalf("expected managed capacity on the sign-off, got %+v", eng.Signoff)
	}
}
