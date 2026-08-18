package estatedetect

import (
	"fmt"

	"github.com/ClatTribe/tsengine/internal/estategraph"
	"github.com/ClatTribe/tsengine/internal/estateingest"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// detectExposedIdentity reports a person whose credential is in someone else's hands AND whose
// account has nothing standing behind it.
//
// Each half is already reported on its own, and each on its own is routine: a breached credential is
// one of hundreds in a dark-web dump, and an account without MFA is a hygiene item. Together they
// are an account takeover with no remaining step — and no single detector can say so, because the
// OSINT feed does not know who is an admin and the identity posture does not read stealer logs.
//
// The two surfaces converge without any matching logic: estategraph.Canonical maps an email to one
// shared principal id, so both detectors naming the same person land on the same node. That
// convergence IS the detection.
func detectExposedIdentity(g *estategraph.Graph, o Options, id func() string) []types.Finding {
	var out []types.Finding
	for _, node := range sortedNodes(g) {
		if node.Kind != estategraph.KindPrincipal || len(node.Surfaces) < 2 {
			// One surface saying both things would not be a cross-surface finding; it would be that
			// detector's own finding, already delivered.
			continue
		}
		exposedBy := node.Attrs[estateingest.CredentialExposedAttr]
		mfaBy := node.Attrs[estateingest.MFAMissingAttr]
		if exposedBy == "" || mfaBy == "" {
			continue
		}

		// Privilege raises the stakes but is not required: an ordinary account with a known password
		// and no second factor is already an unauthenticated way in.
		sev := types.SeverityHigh
		who := "This account"
		if node.Privileged {
			sev = types.SeverityCritical
			who = "This ADMIN account"
		}
		desc := fmt.Sprintf(
			"%s (%s) has a credential known outside the organisation (%s) and no second factor (%s). "+
				"Neither finding is unusual on its own — a breached credential is one of thousands in a "+
				"dump, and a missing second factor is a hygiene item. Together they are a working way in "+
				"with no remaining step, and no single scanner can see it: the exposure feed does not "+
				"know who holds privilege, and the identity posture does not read stealer logs. "+
				"Reset the credential and enrol a second factor; revoke active sessions, because a "+
				"password reset alone does not end a session an attacker already holds.",
			who, nameOr(node.Name, node.ID), exposedBy, mfaBy)

		out = append(out, finding(id(), "estate::exposed-identity-no-mfa", sev,
			"Exposed credential on an account with no second factor: "+nameOr(node.Name, node.ID),
			node.ID, desc, o.Now, append([]string{}, node.Evidence...)))
	}
	return out
}
