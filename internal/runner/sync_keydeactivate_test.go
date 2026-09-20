package runner

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/hitl"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

type noApply struct{ applied []platform.Action }

func (n *noApply) Apply(_ context.Context, a platform.Action) error {
	n.applied = append(n.applied, a)
	return nil
}

// A leaked-key finding on a repository earns a SECOND action beside its PR: a tier-2 deactivation
// bound to the tenant's AWS connection, which QUEUES at the desk (never auto-applies). With no AWS
// connection, or a finding naming no key, nothing extra is proposed.
func TestProcessFinding_LeakedKeyProposesAGatedDeactivationBesideThePR(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	_ = st.PutConnection(ctx, platform.Connection{ID: "c-gh", TenantID: "t1", Kind: platform.ConnGitHub, Status: platform.ConnActive})
	_ = st.PutConnection(ctx, platform.Connection{ID: "c-aws", TenantID: "t1", Kind: platform.ConnAWS, Status: platform.ConnActive})
	app := &noApply{}
	desk := &hitl.Desk{Store: st, Apply: app}
	repo := platform.Asset{ID: "a1", TenantID: "t1", ConnectionID: "c-gh", Type: "repository", Target: "https://github.com/acme/shop.git"}
	n := 0
	svc := &Service{Store: st, Desk: desk, NewID: func() string { n++; return itoa(n) },
		Propose: func(f types.Finding, a platform.Asset) (platform.Action, bool) {
			return platform.Action{ID: "pr-" + f.ID, TenantID: a.TenantID, FindingID: f.ID, ConnectionID: a.ConnectionID, Kind: platform.ActOpenPR, Tier: 1, Payload: map[string]any{}}, true
		},
		KeyDeactivate: func(f types.Finding, c platform.Connection) (platform.Action, bool) {
			if c.Kind != platform.ConnAWS {
				t.Errorf("the hook must receive the AWS connection, got %s", c.Kind)
			}
			return platform.Action{ID: "deact-" + f.ID, TenantID: c.TenantID, FindingID: f.ID, ConnectionID: c.ID, Kind: platform.ActApplyConfig, Tier: 2,
				Payload: map[string]any{"remediation_type": "aws_key_deactivate", "target": "AKIAIOSFODNN7EXAMPLE"}}, true
		},
	}
	leak := types.Finding{ID: "f1", RuleID: "gitleaks::aws-access-key", Tool: "gitleaks", Severity: types.SeverityCritical,
		Title: "AWS access key AKIAIOSFODNN7EXAMPLE committed", Endpoint: "config/prod.env:3"}
	if err := svc.processFinding(ctx, repo, leak); err != nil {
		t.Fatal(err)
	}
	acts, _ := st.ListActions(ctx, "t1")
	var pr, deact *platform.Action
	for i := range acts {
		switch acts[i].Kind {
		case platform.ActOpenPR:
			pr = &acts[i]
		case platform.ActApplyConfig:
			deact = &acts[i]
		}
	}
	if pr == nil || deact == nil {
		t.Fatalf("want a PR and a deactivation, got %d actions: %+v", len(acts), acts)
	}
	if deact.ConnectionID != "c-aws" || deact.Status == platform.ActApplied {
		t.Errorf("the deactivation must bind to the AWS connection and QUEUE, not apply: %+v", deact)
	}
	for _, a := range app.applied {
		if a.Kind == platform.ActApplyConfig {
			t.Error("a tier-2 key deactivation auto-applied — the desk gate was bypassed")
		}
	}

	// No AWS connection → the PR alone.
	st2 := store.NewMemory()
	_ = st2.PutTenant(ctx, platform.Tenant{ID: "t2"})
	svc.Store, svc.Desk = st2, &hitl.Desk{Store: st2, Apply: &noApply{}}
	repo.TenantID = "t2"
	if err := svc.processFinding(ctx, repo, leak); err != nil {
		t.Fatal(err)
	}
	acts2, _ := st2.ListActions(ctx, "t2")
	for _, a := range acts2 {
		if a.Kind == platform.ActApplyConfig {
			t.Error("with no AWS connection there is nothing to deactivate through, yet an action was proposed")
		}
	}
}
