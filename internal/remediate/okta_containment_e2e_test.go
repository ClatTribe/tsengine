package remediate_test

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/detect"
	"github.com/ClatTribe/tsengine/internal/hitl"
	"github.com/ClatTribe/tsengine/internal/remediate"
	"github.com/ClatTribe/tsengine/internal/runner"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/ledger"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// identityScanner surfaces one CRITICAL identity-threat finding against a person.
type identityScanner struct{}

func (identityScanner) Scan(context.Context, platform.Asset) ([]types.Finding, error) {
	return []types.Finding{{
		ID: "f-spray", RuleID: "identitythreat::spray_success", Tool: "identitythreat", Severity: types.SeverityCritical,
		Title: "Password spray succeeded against ada@acme.io", Endpoint: "ada@acme.io",
	}}, nil
}

// THE WIRING, end to end: a critical identity incident on a tenant with an Okta connection queues a
// tier-2 session_revoke bound to Okta (never auto-applied), because the runner hands the tenant's
// connections to the connection-aware proposer. The runner change is one branch; this proves the
// branch is taken.
func TestARSP_IdentityIncidentQueuesAGatedOktaSessionRevoke(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", Name: "Acme"})
	_ = st.PutAsset(ctx, platform.Asset{ID: "w1", TenantID: "t1", Type: "repository", Target: "acme-repo"})
	_ = st.PutConnection(ctx, platform.Connection{ID: "c-ok", TenantID: "t1", Kind: platform.ConnOkta, Status: platform.ConnActive})

	app := &capApplier{}
	desk := &hitl.Desk{Store: st, Apply: app}
	n := 0
	gen := func() string { n++; return string(rune('a' + n)) }
	svc := &runner.Service{
		Store: st, Connectors: connector.NewRegistry(), Tokens: noTokens{},
		Scanner: identityScanner{}, NewID: gen, Desk: desk,
		Detector: &detect.Detector{Store: st, Recorder: ledger.NewRecorder(), NewID: gen},
		ProposeIncidentResponseWith: func(inc platform.Incident, conns []platform.Connection) ([]platform.Action, bool) {
			return remediate.ProposeIncidentResponseWith(inc, conns, gen)
		},
	}
	if _, err := svc.RescanTenant(ctx, "t1"); err != nil {
		t.Fatal(err)
	}
	pending, _ := desk.Pending(ctx, "t1")
	var revoke *platform.Action
	for i := range pending {
		if pending[i].Payload["remediation_type"] == "session_revoke" {
			revoke = &pending[i]
		}
	}
	if revoke == nil {
		t.Fatalf("the identity incident must queue a session_revoke through Okta; pending=%+v", pending)
	}
	if revoke.Kind != platform.ActApplyConfig || revoke.ConnectionID != "c-ok" || revoke.Payload["target"] != "ada@acme.io" {
		t.Errorf("session revoke shape: %+v", revoke)
	}
	for _, a := range app.got {
		if a.Payload["remediation_type"] == "session_revoke" {
			t.Fatal("a tier-2 session revoke must NEVER auto-apply")
		}
	}
}
