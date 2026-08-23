package fieldevidence

import (
	"strings"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// FromActions derives observations from a tenant's verified remediation history.
//
// An observation exists ONLY where both kinds of evidence were actually obtained: a re-scan concluded
// the finding was gone (RescanSaidFixed) AND a live re-attack then ran to check. That is what makes
// this a labelled example rather than an opinion — the re-attack is the label.
//
// RescanSaidFixed is written in exactly one place, retest.ApplyReattack, which is the only path that
// has both kinds of evidence in hand. TestRescanSaidFixedHasOneWriter pins that, because a second
// writer that set it without running a re-attack would silently fill this corpus with unlabelled
// rows — every one of them counted as "the re-scan was right", which is the direction that quietly
// restores trust in a check nobody verified.
//
// One observation per DISTINCT class per action, never per key: an action that claims five findings
// of the same class was ONE verification event, and counting it five times would let a single
// remediation outvote five separate ones.
func FromActions(tenant string, actions []platform.Action) []Observation {
	var out []Observation
	for _, a := range actions {
		v := a.Verification
		if v == nil || !v.RescanSaidFixed {
			continue // no re-scan claim, or no re-attack to check it against — not a labelled example
		}
		contradicted := v.Disagreement == platform.DisagreeRescanMissedLiveExploit
		seen := map[string]bool{}
		for _, k := range a.FindingKeys {
			class := strings.TrimSpace(ClassOf(k))
			if class == "" || seen[class] {
				continue
			}
			seen[class] = true
			out = append(out, Observation{Tenant: tenant, Class: class, Contradicted: contradicted})
		}
	}
	return out
}

// ForTenant builds a corpus from ONE tenant's own history.
//
// MinContributors is 1 by explicit choice, not by omission: the k-anonymity gate exists to stop a
// SHARED statistic being computed from one estate, and a tenant reading its own record discloses
// nothing to anyone. The observation floor still applies — a tenant's own anecdote is still an
// anecdote. Promoting this to the cross-tenant corpus of ADR 0025 is a change of inputs and of
// MinContributors, not a redesign.
func ForTenant(tenant string, actions []platform.Action, opts Options) *Corpus {
	opts.MinContributors = 1
	return Aggregate(FromActions(tenant, actions), opts)
}
