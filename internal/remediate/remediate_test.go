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

func TestDeliverer_TicketIsNoopDelivery(t *testing.T) {
	ctx := context.Background()
	d := &Deliverer{Store: store.NewMemory(), Connectors: connector.NewRegistry(), Tokens: fakeTokens{}}
	if err := d.Apply(ctx, platform.Action{ID: "a1", TenantID: "t", Kind: platform.ActFileTicket}); err != nil {
		t.Errorf("file-ticket delivery is a recorded no-op for the MVP, got %v", err)
	}
}
