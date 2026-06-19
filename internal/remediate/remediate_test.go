package remediate

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestPropose_RepoFindingOpensPR(t *testing.T) {
	a := platform.Asset{TenantID: "t", Type: "repository", Target: "https://github.com/acme/web", Meta: map[string]string{"full_name": "acme/web"}}
	f := types.Finding{ID: "f1", Title: "SQL Injection", Severity: types.SeverityHigh, Tool: "semgrep"}

	act, ok := Propose(f, a, func() string { return "1" })
	if !ok {
		t.Fatal("repo finding should yield an action")
	}
	if act.Kind != platform.ActOpenPR || act.Tier != tierOpenPR {
		t.Errorf("want open_pr tier-1, got %s tier %d", act.Kind, act.Tier)
	}
	if act.NeedsApproval() {
		t.Error("a PR (reviewable) should not be human-gated")
	}
	if act.FindingID != "f1" || act.Payload["full_name"] != "acme/web" {
		t.Errorf("action not anchored to finding/repo: %+v", act)
	}
}

func TestPropose_CloudFindingIsGated(t *testing.T) {
	a := platform.Asset{TenantID: "t", Type: "cloud_account", Target: "aws:123"}
	f := types.Finding{ID: "f2", Title: "Public S3", Severity: types.SeverityCritical, Tool: "prowler"}

	act, _ := Propose(f, a, nil)
	if act.Kind != platform.ActApplyConfig || !act.NeedsApproval() {
		t.Errorf("a live config change must be tier-gated, got %s tier %d", act.Kind, act.Tier)
	}
}

// fakeGitHub records the action it was asked to apply.
type fakeGitHub struct{ applied *platform.Action }

func (fakeGitHub) Kind() string                   { return platform.ConnGitHub }
func (fakeGitHub) OAuthURL(string, string) string { return "" }
func (fakeGitHub) Exchange(context.Context, string, string) (platform.Connection, error) {
	return platform.Connection{}, nil
}
func (fakeGitHub) Discover(context.Context, platform.Connection, string) ([]platform.Asset, error) {
	return nil, nil
}
func (fakeGitHub) Watch(context.Context, platform.Connection, []byte) ([]connector.Trigger, error) {
	return nil, nil
}
func (f fakeGitHub) Apply(_ context.Context, _ platform.Connection, tok string, a platform.Action) error {
	if tok != "tok" {
		return context.Canceled
	}
	*f.applied = a
	return nil
}

type fakeTokens struct{}

func (fakeTokens) Resolve(context.Context, platform.Connection) (string, error) { return "tok", nil }

func TestDeliverer_RoutesPRToGitHubConnection(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutConnection(ctx, platform.Connection{ID: "c1", TenantID: "t", Kind: platform.ConnGitHub, Status: platform.ConnActive})

	var applied platform.Action
	reg := connector.NewRegistry(fakeGitHub{applied: &applied})
	d := &Deliverer{Store: st, Connectors: reg, Tokens: fakeTokens{}}

	act := platform.Action{ID: "a1", TenantID: "t", Kind: platform.ActOpenPR, Payload: map[string]any{"full_name": "acme/web"}}
	if err := d.Apply(ctx, act); err != nil {
		t.Fatal(err)
	}
	if applied.ID != "a1" {
		t.Errorf("deliverer should route the PR action to the github connector, got %+v", applied)
	}
}

func TestDeliverer_NoConnectionErrors(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory() // no github connection
	d := &Deliverer{Store: st, Connectors: connector.NewRegistry(fakeGitHub{applied: new(platform.Action)}), Tokens: fakeTokens{}}
	err := d.Apply(ctx, platform.Action{ID: "a1", TenantID: "t", Kind: platform.ActOpenPR, Payload: map[string]any{"full_name": "x"}})
	if err == nil {
		t.Error("applying with no active connection should error, not silently pass")
	}
}

func TestPropose_StampsConnectionID(t *testing.T) {
	a := platform.Asset{TenantID: "t", ConnectionID: "conn-9", Type: "repository", Target: "https://gitlab.com/acme/web", Meta: map[string]string{"path": "acme/web"}}
	act, _ := Propose(types.Finding{ID: "f1", Title: "SQLi"}, a, func() string { return "1" })
	if act.ConnectionID != "conn-9" {
		t.Errorf("action should carry the asset's connection id, got %q", act.ConnectionID)
	}
	if act.Payload["path"] != "acme/web" {
		t.Errorf("repo action should carry the gitlab path too, got %+v", act.Payload)
	}
}

func TestDeliverer_RoutesToActionsOwnConnection(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	// two active github connections; the action names the second one
	_ = st.PutConnection(ctx, platform.Connection{ID: "c1", TenantID: "t", Kind: platform.ConnGitHub, Status: platform.ConnActive})
	_ = st.PutConnection(ctx, platform.Connection{ID: "c2", TenantID: "t", Kind: platform.ConnGitHub, Status: platform.ConnActive})
	var applied platform.Action
	reg := connector.NewRegistry(fakeGitHub{applied: &applied})
	d := &Deliverer{Store: st, Connectors: reg, Tokens: fakeTokens{}}

	act := platform.Action{ID: "a1", TenantID: "t", ConnectionID: "c2", Kind: platform.ActOpenPR, Payload: map[string]any{"full_name": "acme/web"}}
	if err := d.Apply(ctx, act); err != nil {
		t.Fatal(err)
	}
	if applied.ConnectionID != "c2" {
		t.Errorf("delivery must route to the action's own connection c2, got %q", applied.ConnectionID)
	}
}

// fakeOkta records the action it was asked to apply (the live identity write path).
type fakeOkta struct{ applied *platform.Action }

func (fakeOkta) Kind() string                   { return platform.ConnOkta }
func (fakeOkta) OAuthURL(string, string) string { return "" }
func (fakeOkta) Exchange(context.Context, string, string) (platform.Connection, error) {
	return platform.Connection{}, nil
}
func (fakeOkta) Discover(context.Context, platform.Connection, string) ([]platform.Asset, error) {
	return nil, nil
}
func (fakeOkta) Watch(context.Context, platform.Connection, []byte) ([]connector.Trigger, error) {
	return nil, nil
}
func (f fakeOkta) Apply(_ context.Context, _ platform.Connection, tok string, a platform.Action) error {
	if tok != "tok" {
		return context.Canceled
	}
	*f.applied = a
	return nil
}

// The tier-2 gated suspend that proposeIdentity emits for an Okta stale account must,
// once approved, route through the Deliverer to the Okta connector's Apply — completing
// the non-tech autonomous-with-approval loop (GAP-1).
func TestDeliverer_RoutesGatedSuspendToOktaConnection(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutConnection(ctx, platform.Connection{ID: "conn-okta", TenantID: "t", Kind: platform.ConnOkta, Status: platform.ConnActive})
	var applied platform.Action
	d := &Deliverer{Store: st, Connectors: connector.NewRegistry(fakeOkta{applied: &applied}), Tokens: fakeTokens{}}

	act := platform.Action{ID: "a-sus", TenantID: "t", ConnectionID: "conn-okta",
		Kind: platform.ActApplyConfig, Tier: 2,
		Payload: map[string]any{"remediation_type": "account_suspend", "target": "bob@acme.com"}}
	if err := d.Apply(ctx, act); err != nil {
		t.Fatal(err)
	}
	if applied.ID != "a-sus" || applied.Payload["remediation_type"] != "account_suspend" {
		t.Errorf("gated suspend must route to the Okta connector carrying its payload, got %+v", applied)
	}
}

func TestDeliverer_TicketNoopWhenNoFiler(t *testing.T) {
	ctx := context.Background()
	d := &Deliverer{Store: store.NewMemory(), Connectors: connector.NewRegistry(), Tokens: fakeTokens{}}
	if err := d.Apply(ctx, platform.Action{ID: "a1", TenantID: "t", Kind: platform.ActFileTicket}); err != nil {
		t.Errorf("file-ticket with no filer is a recorded no-op, got %v", err)
	}
}

// recordingFiler captures file_ticket deliveries.
type recordingFiler struct{ filed []string }

func (f *recordingFiler) FileTicket(_ context.Context, a platform.Action) error {
	f.filed = append(f.filed, a.ID)
	return nil
}

func TestDeliverer_FileTicketRoutesToFiler(t *testing.T) {
	ctx := context.Background()
	f := &recordingFiler{}
	d := &Deliverer{Store: store.NewMemory(), Connectors: connector.NewRegistry(), Tokens: fakeTokens{}, Ticket: f}
	if err := d.Apply(ctx, platform.Action{ID: "tkt-1", TenantID: "t", Kind: platform.ActFileTicket, Title: "MFA gap"}); err != nil {
		t.Fatal(err)
	}
	if len(f.filed) != 1 || f.filed[0] != "tkt-1" {
		t.Errorf("file_ticket should route to the filer, got %v", f.filed)
	}
}

// A SIGNED incident-disclosure draft (A-RSP) files to the issue tracker for the human to
// actually send — and is a graceful no-op when no tracker is configured.
func TestDeliverer_SignedDraftRoutesToFiler(t *testing.T) {
	ctx := context.Background()
	f := &recordingFiler{}
	d := &Deliverer{Store: store.NewMemory(), Connectors: connector.NewRegistry(), Tokens: fakeTokens{}, Ticket: f}
	if err := d.Apply(ctx, platform.Action{ID: "draft-1", TenantID: "t", Kind: platform.ActDraftNotification, Title: "Breach disclosure"}); err != nil {
		t.Fatal(err)
	}
	if len(f.filed) != 1 || f.filed[0] != "draft-1" {
		t.Errorf("a signed draft should file to the tracker, got %v", f.filed)
	}
	// no tracker → recorded no-op, never an error
	d2 := &Deliverer{Store: store.NewMemory(), Connectors: connector.NewRegistry(), Tokens: fakeTokens{}}
	if err := d2.Apply(ctx, platform.Action{ID: "draft-2", TenantID: "t", Kind: platform.ActDraftNotification}); err != nil {
		t.Errorf("no-filer draft delivery must be a graceful no-op, got %v", err)
	}
}
