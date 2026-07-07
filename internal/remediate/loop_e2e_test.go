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
	"github.com/ClatTribe/tsengine/internal/detect"
	"github.com/ClatTribe/tsengine/internal/grc"
	"github.com/ClatTribe/tsengine/internal/hitl"
	"github.com/ClatTribe/tsengine/internal/operate"
	"github.com/ClatTribe/tsengine/internal/remediate"
	"github.com/ClatTribe/tsengine/internal/runner"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/ledger"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// criticalScanner surfaces one CRITICAL finding (what would open a critical incident).
type criticalScanner struct{}

func (criticalScanner) Scan(context.Context, platform.Asset) ([]types.Finding, error) {
	return []types.Finding{{
		ID: "f-rce", RuleID: "nuclei::rce", Tool: "nuclei", Severity: types.SeverityCritical,
		Title: "Remote code execution on /api/exec", Endpoint: "https://acme.example/api/exec",
	}}, nil
}

// The full A-RSP "respond" loop: a critical finding → detect opens a critical incident →
// the agent drafts a T3 breach disclosure that QUEUES for a human signature (never
// auto-applies, per the T3 invariant) → a named human signs → it is delivered.
func TestARSP_CriticalIncidentDraftsBreachDisclosureForSignature(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", Name: "Acme"})
	_ = st.PutAsset(ctx, platform.Asset{ID: "w1", TenantID: "t1", Type: "repository", Target: "acme-repo"})

	app := &capApplier{}
	desk := &hitl.Desk{Store: st, Apply: app}
	n := 0
	gen := func() string { n++; return string(rune('a' + n)) }
	svc := &runner.Service{
		Store: st, Connectors: connector.NewRegistry(), Tokens: noTokens{},
		Scanner: criticalScanner{}, NewID: gen, Desk: desk,
		Detector: &detect.Detector{Store: st, Recorder: ledger.NewRecorder(), NewID: gen},
		ProposeIncidentResponse: func(inc platform.Incident) ([]platform.Action, bool) {
			return remediate.ProposeIncidentResponse(inc, gen)
		},
	}

	if _, err := svc.RescanTenant(ctx, "t1"); err != nil {
		t.Fatal(err)
	}

	// 1) a T3 breach-disclosure draft QUEUED for a human — it did NOT auto-apply
	pending, _ := desk.Pending(ctx, "t1")
	var draft *platform.Action
	for i := range pending {
		if pending[i].Kind == platform.ActDraftNotification {
			draft = &pending[i]
		}
	}
	if draft == nil {
		t.Fatalf("a critical incident must queue a T3 breach-disclosure draft; pending=%+v", pending)
	}
	if draft.Tier != platform.TierIrreversible || !draft.NeedsHumanSignature() {
		t.Errorf("the draft must be tier-3 / needs-signature, got tier %d", draft.Tier)
	}
	for _, a := range app.got {
		if a.Kind == platform.ActDraftNotification {
			t.Fatal("a T3 breach draft must NEVER auto-apply")
		}
	}

	// 2) a named human signs it → it is delivered
	if _, err := desk.Decide(ctx, "t1", draft.ID, hitl.Verdict{Approver: "ciso@acme.com", Approve: true}); err != nil {
		t.Fatal(err)
	}
	delivered := false
	for _, a := range app.got {
		if a.Kind == platform.ActDraftNotification {
			delivered = true
		}
	}
	if !delivered {
		t.Error("after a named human signs, the disclosure draft must be delivered")
	}
}

// The full A-RSP "respond" loop, containment half: a critical incident → the agent proposes
// a tier-2 GATED containment action that QUEUES (never auto-applies) → a human approves →
// it is delivered, and the runbook names the affected entity from the incident key.
func TestARSP_CriticalIncidentProposesGatedContainment(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", Name: "Acme"})
	_ = st.PutAsset(ctx, platform.Asset{ID: "w1", TenantID: "t1", Type: "repository", Target: "acme-repo"})

	app := &capApplier{}
	desk := &hitl.Desk{Store: st, Apply: app}
	n := 0
	gen := func() string { n++; return string(rune('a' + n)) }
	svc := &runner.Service{
		Store: st, Connectors: connector.NewRegistry(), Tokens: noTokens{},
		Scanner: criticalScanner{}, NewID: gen, Desk: desk,
		Detector: &detect.Detector{Store: st, Recorder: ledger.NewRecorder(), NewID: gen},
		ProposeIncidentResponse: func(inc platform.Incident) ([]platform.Action, bool) {
			return remediate.ProposeIncidentResponse(inc, gen)
		},
	}
	if _, err := svc.RescanTenant(ctx, "t1"); err != nil {
		t.Fatal(err)
	}

	// 1) a tier-2 containment action QUEUED — it did NOT auto-apply
	pending, _ := desk.Pending(ctx, "t1")
	var con *platform.Action
	for i := range pending {
		if pending[i].Payload["remediation_type"] == "containment" {
			con = &pending[i]
		}
	}
	if con == nil {
		t.Fatalf("a critical incident must queue a gated containment action; pending=%+v", pending)
	}
	if con.Tier != platform.GateTier || !con.NeedsApproval() {
		t.Errorf("containment must be tier-2 human-gated, got tier %d", con.Tier)
	}
	for _, a := range app.got {
		if a.Payload["remediation_type"] == "containment" {
			t.Fatal("containment must NEVER auto-apply — it is human-gated")
		}
	}

	// 2) a human approves → it is delivered, runbook names the endpoint from the incident key
	if _, err := desk.Decide(ctx, "t1", con.ID, hitl.Verdict{Approver: "ops@acme.com", Approve: true}); err != nil {
		t.Fatal(err)
	}
	delivered := false
	for _, a := range app.got {
		if a.Payload["remediation_type"] == "containment" {
			delivered = true
			if rb, _ := a.Payload["runbook"].(string); !strings.Contains(rb, "acme.example/api/exec") {
				t.Errorf("delivered containment runbook should name the affected endpoint: %s", rb)
			}
		}
	}
	if !delivered {
		t.Error("after a human approves, the containment action must be delivered")
	}
}

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

// oktaApplier is a fake Okta connector that records the action it was asked to apply (it
// stands in for connector.Okta.Apply's live suspend — the routing, not the HTTP call, is
// what this loop test exercises).
type oktaApplier struct{ applied *platform.Action }

func (oktaApplier) Kind() string                   { return platform.ConnOkta }
func (oktaApplier) OAuthURL(string, string) string { return "" }
func (oktaApplier) Exchange(context.Context, string, string) (platform.Connection, error) {
	return platform.Connection{}, nil
}
func (oktaApplier) Discover(context.Context, platform.Connection, string) ([]platform.Asset, error) {
	return nil, nil
}
func (oktaApplier) Watch(context.Context, platform.Connection, []byte) ([]connector.Trigger, error) {
	return nil, nil
}
func (o oktaApplier) Apply(_ context.Context, _ platform.Connection, _ string, a platform.Action) error {
	*o.applied = a
	return nil
}

// staleOktaScanner surfaces exactly one stale Okta account (MFA on, no domains → no other
// posture issues), isolating the gated-suspend path.
type staleOktaScanner struct{}

func (staleOktaScanner) Scan(context.Context, platform.Asset) ([]types.Finding, error) {
	ws := operate.Workspace{
		Provider: "okta",
		Users:    []operate.User{{Email: "bob@acme.com", MFA: true, LastLoginDays: 200}},
	}
	return operate.Assess(ws, operate.Options{}), nil
}

// The full non-tech autonomous-with-approval loop (GAP-1, end to end through the REAL
// runner + hitl + deliverer): a stale Okta account → a tier-2 gated suspend that QUEUES
// (does NOT auto-apply) → a human approves → the Okta connector suspends the account.
func TestNonTechLoop_StaleAccountGatedThenApprovedSuspends(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", Name: "Acme"})
	_ = st.PutConnection(ctx, platform.Connection{ID: "conn-okta", TenantID: "t1", Kind: platform.ConnOkta, Status: platform.ConnActive})
	_ = st.PutAsset(ctx, platform.Asset{ID: "w1", TenantID: "t1", ConnectionID: "conn-okta", Type: "workspace",
		Target: "acme-okta", Meta: map[string]string{"provider": platform.ConnOkta}})

	var applied platform.Action
	reg := connector.NewRegistry(oktaApplier{applied: &applied})
	deliverer := &remediate.Deliverer{Store: st, Connectors: reg, Tokens: noTokens{}}
	desk := &hitl.Desk{Store: st, Apply: deliverer}

	n := 0
	svc := &runner.Service{
		Store: st, Connectors: reg, Tokens: noTokens{},
		Scanner: staleOktaScanner{},
		NewID:   func() string { n++; return string(rune('a' + n)) },
		Desk:    desk,
		Propose: func(f types.Finding, a platform.Asset) (platform.Action, bool) {
			return remediate.Propose(f, a, func() string { n++; return string(rune('a' + n)) })
		},
	}

	if _, err := svc.OnTrigger(ctx, connector.Trigger{TenantID: "t1", AssetTarget: "acme-okta", Kind: platform.TriggerManual}); err != nil {
		t.Fatal(err)
	}

	// 1) the suspend QUEUED for a human — it did NOT auto-apply
	pending, _ := desk.Pending(ctx, "t1")
	if len(pending) != 1 {
		t.Fatalf("the stale-account suspend should queue exactly one approval, got %d", len(pending))
	}
	if pending[0].Kind != platform.ActApplyConfig {
		t.Errorf("queued action should be the gated config-mutation, got %s", pending[0].Kind)
	}
	if applied.ID != "" {
		t.Fatal("a tier-2 suspend must NOT auto-apply before a human approves it")
	}

	// 2) a human approves → the Okta connector suspends the named account
	if _, err := desk.Decide(ctx, "t1", pending[0].ID, hitl.Verdict{Approver: "founder@acme.com", Approve: true}); err != nil {
		t.Fatal(err)
	}
	if applied.Payload["remediation_type"] != "account_suspend" || applied.Payload["target"] != "bob@acme.com" {
		t.Errorf("after approval the Okta connector must suspend bob@acme.com, got %+v", applied)
	}
}

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

// TestRespondBreadth_E2E: a common cloud misconfig (an open security group) flows the REAL Respond
// path — remediate.Propose → hitl.Desk gate — and lands as a tier-2 pending-approval action carrying a
// CLASS-CORRECT, specific runbook (the exact revoke-security-group-ingress cut), not a generic "review
// this" ticket. This is the Respond breadth win end to end: the human desk sees the fix, not a vague
// lead. (Before the breadth catalog, a non-storage cloud finding carried no remediation_type + only the
// generic body.)
func TestRespondBreadth_E2E(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	desk := &hitl.Desk{Store: st}

	asset := platform.Asset{
		ID: "a-cloud", TenantID: "t1", ConnectionID: "c-aws", Type: "cloud_account",
		Target: "aws:111122223333", Meta: map[string]string{"provider": "aws"},
	}
	f := types.Finding{
		ID: "f-sg", Severity: types.SeverityHigh, Tool: "prowler",
		Title:  "Security group sg-0abc allows 0.0.0.0/0 ingress on port 22 (SSH open to the internet)",
		RuleID: "prowler::ec2_securitygroup_default_open", Endpoint: "sg-0abc",
	}

	act, ok := remediate.Propose(f, asset, func() string { return "1" })
	if !ok {
		t.Fatal("a cloud finding must produce a remediation action")
	}
	if act.Payload["remediation_type"] != "sg_restrict_ingress" {
		t.Fatalf("an open-SG finding must carry the class-correct sg_restrict_ingress type, got %v", act.Payload["remediation_type"])
	}
	if act.Payload["target"] != "sg-0abc" {
		t.Errorf("the runbook must target the finding's own security group, got %v", act.Payload["target"])
	}
	run, _ := act.Payload["remediation"].(string)
	if !strings.Contains(run, "revoke-security-group-ingress") {
		t.Errorf("the runbook must be class-correct (the exact revoke cut), got:\n%s", run)
	}

	// Through the gate: a tier-2 cloud config action queues for a human (never auto-applies).
	got, err := desk.Submit(ctx, act)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if got.Status != platform.ActPendingApproval {
		t.Fatalf("a tier-2 cloud remediation must queue for approval, got status %s", got.Status)
	}
	pending, _ := desk.Pending(ctx, "t1")
	if len(pending) != 1 || !strings.Contains(pending[0].Payload["remediation"].(string), "revoke-security-group-ingress") {
		t.Fatal("the human desk must see the specific class-correct runbook on the queued action")
	}
}
