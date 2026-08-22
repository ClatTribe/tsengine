package runner

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/detect"
	"github.com/ClatTribe/tsengine/internal/grc"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// A control gap flipping to MET is the false-compliant failure mode — the one the whole coverage
// layer exists to prevent — and it lands in the Markdown report a customer hands an auditor.
//
// grc.Reconcile clears a gap when its citing findings stop appearing, which is the same
// absence-derived reasoning as detect.Reconcile and retest.Verify. Those two are guarded by
// firstErr == nil and by the degraded flag. This one was guarded only by scanned > 0, while its own
// comment said "Guarded by scanned>0 like the detector".
func TestRescanTenant_APartialPassDoesNotClearAComplianceGap(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})

	// The asset whose finding opened the gap, behind a REVOKED connection → skipped this pass.
	_ = st.PutConnection(ctx, platform.Connection{
		ID: "c-dead", TenantID: "t1", Kind: platform.ConnGitHub, Status: platform.ConnRevoked,
	})
	_ = st.PutAsset(ctx, platform.Asset{
		ID: "a-skipped", TenantID: "t1", Type: "workspace", Target: "acme", ConnectionID: "c-dead",
	})
	// A second asset that scans fine, so the pass looks complete (scanned > 0, no error).
	_ = st.PutAsset(ctx, platform.Asset{ID: "a-ok", TenantID: "t1", Type: "workspace", Target: "other"})

	// An open SOC 2 gap, evidenced by a finding from the asset that is about to be skipped.
	_ = st.UpsertControlState(ctx, platform.ControlState{
		TenantID: "t1", Framework: "soc2", ControlID: "CC6.1",
		State: platform.ControlGap, EvidenceRefs: []string{"f-1"},
	})

	n := 0
	svc := &Service{
		Store: st, Connectors: connector.NewRegistry(), Tokens: fakeTokens{},
		Scanner: cleanScanner{}, NewID: func() string { n++; return itoa(n) },
		Detector: &detect.Detector{Store: st, NewID: func() string { n++; return itoa(n) }},
		GRC:      &grc.GRC{Store: st},
	}
	if _, err := svc.RescanTenant(ctx, "t1"); err != nil {
		t.Fatalf("the pass should succeed — that is the point, it LOOKS complete: %v", err)
	}

	states, err := st.Posture(ctx, "t1", "soc2")
	if err != nil {
		t.Fatal(err)
	}
	for _, cs := range states {
		if cs.ControlID == "CC6.1" && cs.State == platform.ControlMet {
			t.Fatal("a SOC 2 control gap was marked MET because the asset evidencing it was never " +
				"scanned. That is the false-compliant failure mode, and it reaches the auditor in " +
				"the compliance report.")
		}
	}
}

// The control, and it matters as much as the case above: on a pass that DID see the whole estate, a
// gap whose finding is genuinely gone must still clear. Refusing to clear anything would replace the
// false-compliant failure with a permanent false NON-compliant one — the mirror the Reconcile comment
// already names, and just as wrong in a document an auditor reads.
func TestRescanTenant_ACompletePassStillClearsARemediatedGap(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	_ = st.PutAsset(ctx, platform.Asset{ID: "a-ok", TenantID: "t1", Type: "workspace", Target: "acme"})
	_ = st.UpsertControlState(ctx, platform.ControlState{
		TenantID: "t1", Framework: "soc2", ControlID: "CC6.1",
		State: platform.ControlGap, EvidenceRefs: []string{"f-1"},
	})

	n := 0
	svc := &Service{
		Store: st, Connectors: connector.NewRegistry(), Tokens: fakeTokens{},
		Scanner: cleanScanner{}, NewID: func() string { n++; return itoa(n) },
		Detector: &detect.Detector{Store: st, NewID: func() string { n++; return itoa(n) }},
		GRC:      &grc.GRC{Store: st},
	}
	if _, err := svc.RescanTenant(ctx, "t1"); err != nil {
		t.Fatalf("clean pass: %v", err)
	}

	states, _ := st.Posture(ctx, "t1", "soc2")
	var cleared bool
	for _, cs := range states {
		if cs.ControlID == "CC6.1" && cs.State == platform.ControlMet {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("every asset was scanned and the evidencing finding is gone — that gap is genuinely " +
			"remediated. Leaving it open forever is the false NON-compliant mirror of the bug above.")
	}
}
