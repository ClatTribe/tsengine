package grc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func fixedClock() time.Time { return time.Unix(1700000000, 0).UTC() }

func reportFixture(t *testing.T) *GRC {
	t.Helper()
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", Name: "Acme Inc"})
	crit := types.Finding{
		ID: "f-001", Title: "SQL injection", Severity: types.SeverityCritical,
		Compliance: &types.Compliance{SOC2: []string{"CC6.1"}},
	}
	_ = st.PutFinding(ctx, "t1", crit)
	g := &GRC{Store: st, Now: fixedClock}
	if err := g.Apply(ctx, "t1", crit); err != nil { // marks CC6.1 a gap, cites f-001
		t.Fatal(err)
	}
	// a met control recorded directly (no finding cites it)
	_ = st.UpsertControlState(ctx, platform.ControlState{
		TenantID: "t1", Framework: "soc2", ControlID: "CC7.1", State: platform.ControlMet, UpdatedAt: fixedClock(),
	})
	return g
}

func TestReport_ResolvesEvidence(t *testing.T) {
	g := reportFixture(t)
	r, err := g.Report(context.Background(), "t1", "soc2")
	if err != nil {
		t.Fatal(err)
	}
	if r.TenantName != "Acme Inc" {
		t.Errorf("want tenant name resolved, got %q", r.TenantName)
	}
	if r.Title != "SOC 2" {
		t.Errorf("want display title SOC 2, got %q", r.Title)
	}
	if r.GapCount != 1 || r.MetCount != 1 {
		t.Fatalf("want 1 gap + 1 met, got gap=%d met=%d", r.GapCount, r.MetCount)
	}
	var found bool
	for _, row := range r.Rows {
		if row.ControlID == "CC6.1" {
			if !row.Gap || len(row.Evidence) != 1 ||
				row.Evidence[0].Title != "SQL injection" || row.Evidence[0].Severity != types.SeverityCritical {
				t.Fatalf("CC6.1 evidence not resolved: %+v", row)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("CC6.1 gap row missing")
	}
}

func TestRenderMarkdown_ShowsGapsAndEvidence(t *testing.T) {
	g := reportFixture(t)
	r, _ := g.Report(context.Background(), "t1", "soc2")
	md := RenderMarkdown(r)
	for _, want := range []string{
		"# SOC 2 Compliance Report — Acme Inc",
		"## Gaps (1)",
		"### CC6.1 — GAP",
		"`f-001` — SQL injection (critical)",
		"## Met (1)",
		"- CC7.1",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q\n---\n%s", want, md)
		}
	}
}

func TestRenderMarkdown_CleanFramework(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", Name: "Quiet Co"})
	_ = st.UpsertControlState(ctx, platform.ControlState{
		TenantID: "t1", Framework: "soc2", ControlID: "CC6.1", State: platform.ControlMet, UpdatedAt: fixedClock(),
	})
	g := &GRC{Store: st, Now: fixedClock}
	r, _ := g.Report(ctx, "t1", "soc2")
	md := RenderMarkdown(r)
	if !strings.Contains(md, "No open gaps") {
		t.Errorf("a clean framework should say so:\n%s", md)
	}
}

func TestSignedReport_CarriesAttestation(t *testing.T) {
	g := reportFixture(t)
	ctx := context.Background()
	pack, err := g.EvidencePack(ctx, "t1", "soc2")
	if err != nil {
		t.Fatal(err)
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	if err := Sign(pack, "tsengine-prod-key-v1", priv, fixedClock()); err != nil {
		t.Fatal(err)
	}
	r, err := g.SignedReport(ctx, "t1", "soc2", pack)
	if err != nil {
		t.Fatal(err)
	}
	if r.Signer != "tsengine-prod-key-v1" || r.SHA256 == "" {
		t.Fatalf("signed report should carry attestation, got signer=%q sha=%q", r.Signer, r.SHA256)
	}
	if !strings.Contains(RenderMarkdown(r), "Signed:") {
		t.Error("markdown should render the signature line when signed")
	}
}
