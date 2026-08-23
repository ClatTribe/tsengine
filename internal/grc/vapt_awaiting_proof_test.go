package grc

import (
	"context"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// A fix the re-scan found gone but which is NOT counted as confirmed (ADR 0025 F1) must be reported
// as its own thing. Folded into confirmed it overstates; folded into still-present it claims the fix
// failed; omitted entirely it silently shrinks the totals and the reader sees a smaller report with
// no reason why — which is the failure mode this project keeps finding.
func TestVAPTRenderers_AwaitingProofIsReportedAndNotFolded(t *testing.T) {
	var r VAPTReport
	r.Summary.RetestConfirmed = 2
	r.Summary.RetestStillPresent = 1
	r.Summary.RetestAwaitingProof = 3

	md := RenderVAPTMarkdown(&r)
	html := RenderVAPTHTML(&r)

	for name, out := range map[string]string{"markdown": md, "html": html} {
		if !strings.Contains(out, "3") {
			t.Errorf("%s: the awaiting-proof count is missing entirely", name)
		}
		if !strings.Contains(strings.ToLower(out), "re-attack") {
			t.Errorf("%s: must say what the fix is awaiting, got no mention of a re-attack", name)
		}
		// The confirmed count must stay 2 — not 5.
		if strings.Contains(out, "5 applied fix") {
			t.Errorf("%s: awaiting-proof was folded into confirmed", name)
		}
	}
}

// The retest section must appear at all when the ONLY signal is awaiting-proof — otherwise a report
// where every fix is unconfirmed renders as a report with no fix verification at all.
func TestVAPTHTML_RetestSectionShowsWhenOnlySignalIsAwaitingProof(t *testing.T) {
	var r VAPTReport
	r.Summary.RetestAwaitingProof = 1
	if !strings.Contains(strings.ToLower(RenderVAPTHTML(&r)), "re-attack") {
		t.Fatal("a report whose only retest signal is awaiting-proof must still render the section")
	}
}

// The RENDERER tests above prove the number is shown; this proves it is COUNTED as its own thing.
// Both halves are needed: a mutation folding the count into RetestConfirmed passed every renderer
// test, because a renderer test constructs the summary directly and never exercises the tally.
func TestVAPTReport_AwaitingProofIsTalliedSeparatelyFromConfirmed(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", Name: "Acme Inc"})
	_ = st.PutAsset(ctx, platform.Asset{ID: "a1", TenantID: "t1", Type: "web_application", Target: "https://acme.example"})
	mk := func(id, status string) platform.Action {
		return platform.Action{ID: id, TenantID: "t1", FindingID: id, Kind: platform.ActOpenPR,
			Status: platform.ActApplied, Verification: &platform.FixVerification{Status: status}}
	}
	_ = st.PutAction(ctx, mk("act-1", platform.FixStatusFixed))
	_ = st.PutAction(ctx, mk("act-2", platform.FixStatusRescanUnconfirmed))
	_ = st.PutAction(ctx, mk("act-3", platform.FixStatusRescanUnconfirmed))

	g := &GRC{Store: st}
	rep, err := g.VAPTReport(ctx, "t1")
	if err != nil {
		t.Fatalf("VAPTReport: %v", err)
	}
	if rep.Summary.RetestConfirmed != 1 {
		t.Errorf("only the genuinely confirmed fix may be counted as confirmed, got %d", rep.Summary.RetestConfirmed)
	}
	if rep.Summary.RetestAwaitingProof != 2 {
		t.Errorf("want 2 awaiting proof, got %d", rep.Summary.RetestAwaitingProof)
	}
	if rep.Summary.RetestStillPresent != 0 {
		t.Errorf("a withheld confirmation must not be reported as a failed fix, got %d", rep.Summary.RetestStillPresent)
	}
}
