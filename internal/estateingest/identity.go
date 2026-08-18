package estateingest

import (
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/estategraph"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// The IDENTITY join: the human.
//
// Three detectors already name the same person and cannot hear each other. OSINT finds a corporate
// credential in a stealer log; the identity posture finds an admin with no MFA; SaaS posture finds
// who owns the GitHub org. Each is a separate finding in a flat list, so the sentence that matters —
// "the password in the stealer log belongs to an admin with nothing standing behind it" — is one no
// single detector can say.
//
// It needs almost no machinery, because estategraph.Canonical already maps an email to a
// surface-shared "principal:" id. Two detectors naming alice@acme.com converge on ONE node by
// construction. What was missing is that nothing turned these findings into nodes at all.

// Surface names for the finding-derived surfaces, kept distinct so a node asserted by OSINT and by
// the identity posture genuinely spans two surfaces rather than collapsing into one.
const (
	SurfaceIdentity = "identity"
	SurfaceOSINT    = "osint"
	SurfaceSaaS     = "saas"
)

// Node attributes carrying what a surface CLAIMED about a person. They are claims with evidence
// behind them, not derived state — which is why each records the rule that made it.
const (
	// CredentialExposedAttr: this person's credential is known outside the organisation.
	CredentialExposedAttr = "credential_exposed"
	// MFAMissingAttr: this person's account has no second factor.
	MFAMissingAttr = "mfa_missing"
)

// exposureRules name findings that prove a person's own credential is in someone else's hands. A
// leaked API token in a repository is deliberately NOT here: that is a machine credential, and
// treating it as this human's password would overstate what was found.
var exposureRules = map[string]bool{
	"osint::stealer-log":         true,
	"osint::breached-credential": true,
}

// mfaRules name findings that prove the account has no second factor.
var mfaRules = map[string]bool{
	"operate::admin-without-mfa": true,
	"operate::user-without-mfa":  true,
}

// privilegeRules name findings that prove the account holds privilege. Deliberately narrow: only
// where the finding is about ONE named person. A finding about a count of super-admins names no
// individual, so inferring privilege for whoever its endpoint happens to be would be a guess.
var privilegeRules = map[string]bool{
	"operate::admin-without-mfa":      true,
	"operate::incomplete-offboarding": true,
}

// FromIdentityFindings turns person-scoped findings into principal nodes carrying what each surface
// claimed about them.
//
// GROUNDED (§10) in three ways. A finding contributes only if its endpoint really is an email — the
// canonical form decides, never a guess about what the endpoint "probably" is. The surface comes
// from the finding's own rule namespace, and an unrecognised namespace is skipped rather than
// assigned a plausible one. And every claim names the rule that made it, so a downstream reader can
// check it rather than trust it.
func FromIdentityFindings(findings []types.Finding, now time.Time) *estategraph.Graph {
	g := estategraph.New()
	for _, f := range findings {
		id := estategraph.Canonical("", strings.TrimSpace(f.Endpoint))
		if !strings.HasPrefix(id, "principal:") {
			continue // not a person-scoped finding — nothing to anchor
		}
		surface := surfaceForRule(f.RuleID)
		if surface == "" {
			continue // an unknown namespace gets no surface invented for it
		}
		rule := strings.TrimSpace(f.RuleID)
		attrs := map[string]string{}
		if exposureRules[rule] {
			attrs[CredentialExposedAttr] = rule
		}
		if mfaRules[rule] {
			attrs[MFAMissingAttr] = rule
		}
		if len(attrs) == 0 {
			attrs = nil
		}
		g.AddNode(estategraph.Node{
			ID: id, Kind: estategraph.KindPrincipal, Name: strings.TrimSpace(f.Endpoint),
			Surfaces: []string{surface}, Privileged: privilegeRules[rule],
			Attrs: attrs, Evidence: []string{f.ID}, ObservedAt: now,
		})
	}
	return g
}

// surfaceForRule maps a finding's rule namespace to the surface that produced it. Returns "" for an
// unrecognised namespace, so a new detector cannot be silently filed under an existing surface and
// make a single-surface claim look cross-surface.
func surfaceForRule(ruleID string) string {
	switch {
	case strings.HasPrefix(ruleID, "osint::"):
		return SurfaceOSINT
	case strings.HasPrefix(ruleID, "operate::"):
		return SurfaceIdentity
	case strings.HasPrefix(ruleID, "sspm::"):
		return SurfaceSaaS
	}
	return ""
}
