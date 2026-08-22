package platformapi

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/connector/awsinventory"
	"github.com/ClatTribe/tsengine/internal/ghoidc"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// ciIdentityFindings assesses the CI/federated-identity trust surface of a posted AWS inventory.
//
// WHY THIS FILE EXISTS: internal/ghoidc is a complete, tested analyser of the GitHub-Actions → AWS
// role transition — the surface where a workflow reaches the account with NO stored credential, so
// there is no secret for a scanner to find and no over-grant for an IAM evaluator to flag; the trust
// policy's string conditions are the entire access-control decision. Nothing called it. Assess had
// zero callers anywhere outside its own tests, so every finding it can produce was unreachable from
// the product, and the surface was invisible in exactly the way that motivated building it.
//
// The data was already in hand: RawIAMRole.TrustPolicyJSON arrives on every posted AWS inventory and
// awsinventory already parses it for trust principals. So this is a wiring gap, not a data gap.
//
// GROUNDED (§10): findings come only from trust policies really present on really-named roles. A
// role with no trust policy is skipped rather than assumed open, an unparseable one is declared in
// ChecksNotRun by Assess rather than read as clean, and Privileged is taken from the collector's own
// Admin flag rather than guessed — it escalates a finding one step and says why, so a wrong guess
// would be a wrong severity on a real customer's role.
func ciIdentityFindings(provider string, body []byte) []types.Finding {
	if p := strings.ToLower(strings.TrimSpace(provider)); p != "" && p != "aws" {
		// GCP's workload-identity equivalent (internal/gcpwif) is NOT wired here, and deliberately not
		// half-wired: RawGCP carries no pool or provider objects at all, so there is nothing to assess.
		// Running it over an empty estate would return a confident zero — the clean-because-we-did-not-
		// look answer this codebase keeps having to fix. It needs an ingest field first.
		return nil
	}
	var raw awsinventory.RawAWS
	if json.Unmarshal(body, &raw) != nil {
		return nil // the caller has already reported the parse failure; do not double-report it
	}
	est := ghoidc.Estate{}
	for _, r := range raw.Roles {
		if strings.TrimSpace(r.TrustPolicyJSON) == "" {
			continue // no trust policy observed: nothing to assess, and nothing claimed
		}
		est.Roles = append(est.Roles, ghoidc.Role{
			ARN: r.ARN, Name: r.Name, TrustPolicy: r.TrustPolicyJSON, Privileged: r.Admin,
		})
	}
	if len(est.Roles) == 0 {
		return nil
	}
	// ReposComplete stays FALSE: a posted cloud inventory says nothing about which repositories the
	// organisation owns, so the unowned-repository check must not run. Assess declares that in
	// ChecksNotRun rather than passing it silently — accusing a customer's real repository of being
	// unowned because we never had the list would be worse than not running the check.
	return ghoidc.Assess(est, time.Now().UTC()).Findings
}

// persistCIIdentityFindings enriches and stores them through the SAME path every other ingest uses
// (§11), so a federated-trust finding flows into issues/incidents/grc/hitl like any other.
func (d Deps) persistCIIdentityFindings(ctx context.Context, tenantID string, fs []types.Finding) ([]types.Finding, int) {
	if len(fs) == 0 || d.Store == nil {
		return nil, 0
	}
	return d.persistDriftFindings(ctx, tenantID, fs)
}
