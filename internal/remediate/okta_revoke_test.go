package remediate

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func gen() func() string {
	n := 0
	return func() string { n++; return "x" }
}

// oauth_revoke is promoted to a gated live mutation ONLY on Okta and ONLY when the finding carries
// the client id and the user ids — the identifiers the write names. Anything less stays a ticket.
func TestProposeIdentity_OAuthRevokePromotesOnlyWithOktaIdentifiers(t *testing.T) {
	okta := platform.Asset{ID: "w1", TenantID: "t1", ConnectionID: "c-ok", Type: "workspace", Target: "okta", Meta: map[string]string{"provider": platform.ConnOkta}}
	f := types.Finding{ID: "f1", RuleID: "operate::oauth-admin-scope", Severity: types.SeverityCritical, Endpoint: "Shadow Admin App",
		ToolArgs: map[string]string{"client_id": "0oa-app", "user_ids": "00u-1,00u-2"}}
	act, ok := Propose(f, okta, gen())
	if !ok || act.Kind != platform.ActApplyConfig || act.Tier != tierApplyConfig {
		t.Fatalf("with ids on Okta the revoke must be a gated live mutation: %+v", act)
	}
	if act.Payload["client_id"] != "0oa-app" || act.Payload["user_ids"] != "00u-1,00u-2" || act.Payload["remediation_type"] != "oauth_revoke" {
		t.Errorf("payload must carry the identifiers the connector needs: %+v", act.Payload)
	}

	bare := f
	bare.ToolArgs = nil
	if act, _ := Propose(bare, okta, gen()); act.Kind != platform.ActFileTicket {
		t.Errorf("without identifiers the revoke must stay a runbook ticket, got %s", act.Kind)
	}
	gws := okta
	gws.Meta = map[string]string{"provider": platform.ConnGWorkspace}
	if act, _ := Propose(f, gws, gen()); act.Kind != platform.ActFileTicket {
		t.Errorf("Google has no grant-revoke write path; must stay a ticket, got %s", act.Kind)
	}
}

// An identity incident's containment becomes a gated Okta session revoke when the tenant has an
// active Okta connection and the entity is an account; otherwise the ticket stands. The T3 draft
// is untouched either way.
func TestProposeIncidentResponseWith_IdentityContainmentBecomesSessionRevokeOnOkta(t *testing.T) {
	inc := platform.Incident{ID: "i1", TenantID: "t1", FindingID: "f1", RuleID: "identitythreat::password_spray", Severity: string(types.SeverityCritical),
		Title: "Password spray against ada@acme.io", Key: "identitythreat::password_spray|ada@acme.io"}
	conns := []platform.Connection{{ID: "c-ok", TenantID: "t1", Kind: platform.ConnOkta, Status: platform.ConnActive}}

	acts, ok := ProposeIncidentResponseWith(inc, conns, gen())
	if !ok || len(acts) != 2 {
		t.Fatalf("want containment + draft, got ok=%v %d", ok, len(acts))
	}
	var contain, draft *platform.Action
	for i := range acts {
		switch acts[i].Kind {
		case platform.ActApplyConfig:
			contain = &acts[i]
		case platform.ActDraftNotification:
			draft = &acts[i]
		}
	}
	if contain == nil || contain.Payload["remediation_type"] != "session_revoke" || contain.Payload["target"] != "ada@acme.io" ||
		contain.ConnectionID != "c-ok" || contain.Tier != tierApplyConfig {
		t.Errorf("containment must be a gated session revoke bound to Okta: %+v", contain)
	}
	if rem, _ := contain.Payload["remediation"].(string); !strings.Contains(rem, "not suspended") {
		t.Errorf("the human must be told the account stays enabled: %q", rem)
	}
	if draft == nil || draft.Tier != platform.TierIrreversible {
		t.Errorf("the T3 draft must be untouched: %+v", draft)
	}

	// No Okta → the ticket stands. Not an identity rule → the ticket stands. Entity not an account → ticket.
	if acts, _ := ProposeIncidentResponseWith(inc, nil, gen()); acts[0].Kind != platform.ActFileTicket {
		t.Errorf("without Okta the containment must stay a ticket: %+v", acts[0])
	}
	cloud := inc
	cloud.RuleID, cloud.Key = "prowler::s3_bucket_public", "prowler::s3_bucket_public|arn:aws:s3:::data"
	if acts, _ := ProposeIncidentResponseWith(cloud, conns, gen()); acts[0].Kind != platform.ActFileTicket {
		t.Errorf("a cloud incident is not contained by revoking someone's sessions: %+v", acts[0])
	}
	svc := inc
	svc.Key = "identitythreat::privileged_grant|svc-deploy"
	if acts, _ := ProposeIncidentResponseWith(svc, conns, gen()); acts[0].Kind != platform.ActFileTicket {
		t.Errorf("an entity that is not an account must stay a ticket: %+v", acts[0])
	}
}
