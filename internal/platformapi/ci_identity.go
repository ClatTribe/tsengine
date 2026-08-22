package platformapi

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/connector/awsinventory"
	"github.com/ClatTribe/tsengine/internal/connector/gcpinventory"
	"github.com/ClatTribe/tsengine/internal/gcpwif"
	"github.com/ClatTribe/tsengine/internal/ghoidc"
	"github.com/ClatTribe/tsengine/internal/samltrust"
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
	f, _ := ciIdentityAssess(provider, body)
	return f
}

// ciIdentityAssess returns the findings AND what the assessment could NOT look at.
//
// The declarations are the point of the second return. ghoidc and gcpwif each refuse to judge a
// federation whose issuer they do not model — an Okta or other SAML provider — and say so instead of
// staying silent, because "we could not look" and "we looked and it was fine" are different claims.
// Discarding that here left the honest half in the package and shipped only the verdicts, so an
// estate federating through Okta reached the platform looking exactly like one that federates
// through nothing.
func ciIdentityAssess(provider string, body []byte) ([]types.Finding, map[string]string) {
	switch p := strings.ToLower(strings.TrimSpace(provider)); p {
	case "", "aws":
	case "gcp":
		return gcpCIIdentityAssess(body)
	default:
		// Azure has no equivalent analyser yet, and running one over an estate it cannot read would
		// return a confident zero — the clean-because-we-did-not-look answer.
		return nil, nil
	}
	var raw awsinventory.RawAWS
	if json.Unmarshal(body, &raw) != nil {
		return nil, nil // the caller has already reported the parse failure; do not double-report it
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
		return nil, nil
	}
	// ReposComplete stays FALSE: a posted cloud inventory says nothing about which repositories the
	// organisation owns, so the unowned-repository check must not run. Assess declares that in
	// ChecksNotRun rather than passing it silently — accusing a customer's real repository of being
	// unowned because we never had the list would be worse than not running the check.
	now := time.Now().UTC()
	a := ghoidc.Assess(est, now)

	// SAML federation is the WORKFORCE path into the account — an Okta, Entra or ADFS identity — and
	// ghoidc deliberately refuses to judge it, declaring it unassessed instead. internal/samltrust
	// assesses the ONE case that is decidable from the trust policy alone: no SAML:aud condition,
	// which accepts an assertion minted for any service provider the IdP serves rather than only AWS.
	// Everything else about a SAML trust stays declared rather than guessed at.
	sam := samltrust.Assess(samltrust.Estate{Roles: samlRoles(raw)}, now)
	findings := append(a.Findings, sam.Findings...)
	notRun := a.ChecksNotRun
	if len(sam.ChecksNotRun) > 0 {
		if notRun == nil {
			notRun = map[string]string{}
		}
		for k, v := range sam.ChecksNotRun {
			notRun[k] = v
		}
	}
	return findings, notRun
}

// persistCIIdentityFindings enriches and stores them through the same L1.5 chain every other ingest
// uses (§11), so a federated-trust finding flows into issues/incidents/grc/hitl like any other —
// but with its OWN provenance.
//
// It reused persistDriftFindings, which stamps ids as "drift-…", marks the clouddrift posture
// assessed, and writes a ledger entry reading "cloud drift detected" with a drift_findings count. A
// role trusting an unconstrained SAML provider is not drift: nothing changed, the trust policy has
// most likely been that way since it was written. The ledger is where a claim is supposed to be
// checkable, so a false label there is worse than a vague one, and "we detected drift" is a claim
// about an EVENT that did not happen.
func (d Deps) persistCIIdentityFindings(ctx context.Context, tenantID string, fs []types.Finding) ([]types.Finding, int) {
	if len(fs) == 0 || d.Store == nil {
		return nil, 0
	}
	fs = enrichFindings(fs) // L1.5 parity (§11)
	// The CI-identity surface was assessed — recorded under its own kind so a tenant can tell that
	// this ran from the fact that clouddrift ran, which is a different question.
	d.markPostureAssessed(ctx, tenantID, "ci_identity", time.Now().UTC())

	saved := make([]types.Finding, 0, len(fs))
	for i, f := range fs {
		f.ID = d.newID("ciid") + "-" + strconv.Itoa(i)
		if err := d.Store.PutFinding(ctx, tenantID, f); err != nil {
			continue
		}
		d.foldIntoPosture(ctx, tenantID, []types.Finding{f})
		saved = append(saved, f)
	}
	if d.IncidentOpener != nil && len(saved) > 0 {
		_, _ = d.IncidentOpener.OpenFor(ctx, tenantID, saved, nil)
	}
	if d.Recorder != nil && len(saved) > 0 {
		d.Recorder.Record("federated trust assessed", "ci_identity",
			map[string]any{"tenant_id": tenantID, "findings": len(saved)},
			"a role's trust policy lets an external identity provider assume it")
	}
	return saved, len(saved)
}

// gcpCIIdentityFindings assesses the Workload Identity Federation surface of a posted GCP inventory.
//
// GCP splits this decision across TWO objects usually edited by different people: the pool
// PROVIDER's attribute condition (which tokens the pool accepts) and the SERVICE ACCOUNT's IAM
// binding (which identities may impersonate it). Neither half looks wrong alone — an unconditioned
// provider reads as "fine, the bindings are narrow", a pool-wide binding as "fine, the provider is
// conditioned" — and together every GitHub repository on the internet can impersonate the account.
// That join is why this runs at ingest rather than being left to a reader comparing two screens.
//
// Grounded (§10): Privileged comes from the collector's own admin flag, never inferred; an estate
// with no providers yields nothing; and gcpwif itself declares in ChecksNotRun any pool federating
// an issuer it does not model, so a non-GitHub IdP reads as unchecked rather than clean.
func gcpCIIdentityFindings(body []byte) []types.Finding {
	f, _ := gcpCIIdentityAssess(body)
	return f
}

func gcpCIIdentityAssess(body []byte) ([]types.Finding, map[string]string) {
	var raw gcpinventory.RawGCP
	if json.Unmarshal(body, &raw) != nil {
		return nil, nil // the caller already reported the parse failure
	}
	if len(raw.WIFProviders) == 0 {
		return nil, nil // nothing federates in, or the collector did not report it
	}
	est := gcpwif.Estate{}
	for _, p := range raw.WIFProviders {
		est.Providers = append(est.Providers, gcpwif.Provider{
			ProjectNumber: p.ProjectNumber, PoolID: p.PoolID, ID: p.ID,
			IssuerURI: p.IssuerURI, AllowedAudiences: p.AllowedAudiences,
			AttributeMapping: p.AttributeMapping, AttributeCondition: p.AttributeCondition,
		})
	}
	for _, sa := range raw.ServiceAccounts {
		acct := gcpwif.ServiceAccount{Email: sa.Email, Privileged: sa.Admin}
		for _, b := range sa.Bindings {
			acct.Bindings = append(acct.Bindings, gcpwif.Binding{
				Role: b.Role, Members: b.Members, Condition: b.Condition,
			})
		}
		est.ServiceAccounts = append(est.ServiceAccounts, acct)
	}
	// ReposComplete stays FALSE for the same reason as AWS: a cloud inventory says nothing about
	// which repositories the organisation owns, so the unowned-repository check must not run.
	a := gcpwif.Assess(est, time.Now().UTC())
	return a.Findings, a.ChecksNotRun
}

// samlRoles maps the posted AWS inventory into the SAML analyser's estate. Privileged comes from the
// collector's own admin flag — the same rule the GitHub path follows, and for the same reason: a
// trust policy does not say what a role can do, so inferring it here would fabricate blast radius.
func samlRoles(raw awsinventory.RawAWS) []samltrust.Role {
	var out []samltrust.Role
	for _, r := range raw.Roles {
		if strings.TrimSpace(r.TrustPolicyJSON) == "" {
			continue
		}
		out = append(out, samltrust.Role{
			ARN: r.ARN, Name: r.Name, TrustPolicy: r.TrustPolicyJSON, Privileged: r.Admin,
		})
	}
	return out
}
