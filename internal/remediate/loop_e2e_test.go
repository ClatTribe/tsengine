package remediate_test

// This is the assembled non-tech loop, end to end, with the REAL components — the proof
// that #91/#92/#93 compose: a workspace posture finding → runner.Service →
// remediate.Propose (the identity runbook) → grc (compliance gap) → grc.Report. It lives
// in remediate_test because remediate imports runner (so runner's own tests can't import
// remediate); an external test package can import both.

import (
	"context"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/grc"
	"github.com/ClatTribe/tsengine/internal/hitl"
	"github.com/ClatTribe/tsengine/internal/operate"
	"github.com/ClatTribe/tsengine/internal/remediate"
	"github.com/ClatTribe/tsengine/internal/runner"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// workspaceScanner runs the REAL operate posture engine over a deliberately weak
// workspace (an admin with no MFA + a domain with no DMARC) — exactly what a live
// Okta/Workspace fetch would surface.
type workspaceScanner struct{}

func (workspaceScanner) Scan(_ context.Context, _ platform.Asset) ([]types.Finding, error) {
	ws := operate.Workspace{
		Provider: "okta",
		Users:    []operate.User{{Email: "ceo@acme.com", SuperAdmin: true, MFA: false}},
		Domains:  []operate.DomainConfig{{Name: "acme.com", DMARC: "", SPF: false, DKIM: false}},
	}
	return operate.Assess(ws, operate.Options{}), nil
}

// capApplier captures every delivered action (tier-1 identity tickets auto-apply).
type capApplier struct{ got []platform.Action }

func (c *capApplier) Apply(_ context.Context, a platform.Action) error {
	c.got = append(c.got, a)
	return nil
}

type noTokens struct{}

func (noTokens) Resolve(context.Context, platform.Connection) (string, error) { return "", nil }

func TestNonTechLoop_PostureToRunbookToCompliance(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	g := &grc.GRC{Store: st}
	app := &capApplier{}
	desk := &hitl.Desk{Store: st, Apply: app}

	n := 0
	svc := &runner.Service{
		Store: st, Connectors: connector.NewRegistry(), Tokens: noTokens{},
		Scanner: workspaceScanner{},
		NewID:   func() string { n++; return string(rune('a' + n)) },
		GRC:     g, Desk: desk,
		Propose: func(f types.Finding, a platform.Asset) (platform.Action, bool) {
			return remediate.Propose(f, a, func() string { n++; return string(rune('a' + n)) })
		},
	}

	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", Name: "Acme Inc"})
	_ = st.PutAsset(ctx, platform.Asset{ID: "w1", TenantID: "t1", ConnectionID: "okta-1", Type: "workspace", Target: "acme-okta"})
	if _, err := svc.OnTrigger(ctx, connector.Trigger{TenantID: "t1", AssetTarget: "acme-okta", Kind: platform.TriggerManual}); err != nil {
		t.Fatal(err)
	}

	// 1) the REAL remediate.Propose produced identity RUNBOOKS (not generic tickets):
	//    the DMARC fix must carry the exact record; the admin fix must name the admin.
	var dmarc, adminMFA bool
	for _, a := range app.got {
		switch a.Payload["remediation_type"] {
		case "dmarc_publish":
			if s, _ := a.Payload["summary"].(string); strings.Contains(s, "_dmarc.acme.com") && strings.Contains(s, "p=reject") {
				dmarc = true
			}
		case "mfa_enforce":
			if strings.Contains(a.Title, "ceo@acme.com") {
				adminMFA = true
			}
		}
	}
	if !dmarc {
		t.Errorf("the DMARC finding should deliver a runbook with the exact record; got %+v", app.got)
	}
	if !adminMFA {
		t.Errorf("the admin-without-MFA finding should deliver an MFA runbook naming the admin; got %+v", app.got)
	}

	// 2) the same findings folded into the compliance system-of-record as gaps
	soc2, _ := g.Posture(ctx, "t1", grc.FrameworkSOC2) // admin-without-mfa → CC6.1
	if len(soc2) == 0 || soc2[0].State != platform.ControlGap {
		t.Errorf("admin-without-MFA should open a SOC2 gap, got %+v", soc2)
	}

	// 3) the compliance REPORT renders the gap, citing the finding that drove it
	rep, err := g.Report(ctx, "t1", grc.FrameworkSOC2)
	if err != nil {
		t.Fatal(err)
	}
	if rep.GapCount == 0 {
		t.Fatal("the SOC2 report should show at least one gap")
	}
	var citesFinding bool
	for _, row := range rep.Rows {
		if row.Gap && len(row.Evidence) > 0 {
			citesFinding = true
		}
	}
	if !citesFinding {
		t.Error("a reported gap must cite the finding that grounds it (grounding holds end to end)")
	}
}
