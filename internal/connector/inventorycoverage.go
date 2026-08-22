package connector

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/internal/cloudiam"
	"github.com/ClatTribe/tsengine/internal/connector/awsinventory"
	"github.com/ClatTribe/tsengine/internal/connector/gcpinventory"
)

// inventorycoverage.go states what a POSTED cloud inventory could not answer.
//
// awsfetch.Coverage already does this for the LIVE read path, and its comment is the rule:
// "silence about coverage is how a partial picture passes for a whole one." But the posted
// path — POST /v1/cloud/inventory, which is how GCP arrives at all, since it has no live
// fetcher — bypasses awsfetch entirely and had no such disclosure.
//
// The specific failure that makes this worth its own file: escalation is computed from
// POLICY DOCUMENTS (AWS) and IAM BINDINGS (GCP). A snapshot that omits them yields exactly
// zero privilege-escalation edges, and an empty result is indistinguishable from a clean
// account. "Nobody can become admin here" is the most reassuring thing this product can
// say and the most damaging thing to say wrongly.
//
// Every message names the FIELD to populate, because a caller told only that something is
// missing will not know what to send next.

// InventoryCoverage reports what a posted snapshot supports and what it cannot.
type InventoryCoverage struct {
	// Notes are the per-gap explanations, keyed by the concern that is unanswerable.
	Notes map[string]string `json:"notes,omitempty"`
}

// Complete reports whether the snapshot could answer everything we know how to ask.
func (c InventoryCoverage) Complete() bool { return len(c.Notes) == 0 }

// Summary renders the one line a caller should show beside any conclusion. Never empty.
func (c InventoryCoverage) Summary() string {
	if len(c.Notes) == 0 {
		return "This snapshot carries everything the engine knows how to evaluate."
	}
	keys := make([]string, 0, len(c.Notes))
	for k := range c.Notes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return "NOT evaluated: " + strings.Join(keys, ", ") +
		" — an empty result for those means UNREAD, not safe."
}

// CoverAWS reports what a posted RawAWS cannot answer.
func CoverAWS(raw awsinventory.RawAWS) InventoryCoverage {
	c := InventoryCoverage{Notes: map[string]string{}}
	principals := len(raw.Roles) + len(raw.Users)
	if principals == 0 {
		c.Notes["identity"] = "no roles or users in the snapshot — no principal can be evaluated, so no " +
			"attack path can start from one. Populate `roles` and `users`."
		return c
	}
	withPolicies := 0
	for _, r := range raw.Roles {
		if len(r.PoliciesJSON) > 0 {
			withPolicies++
		}
	}
	for _, u := range raw.Users {
		if len(u.PoliciesJSON) > 0 {
			withPolicies++
		}
	}
	if withPolicies == 0 {
		c.Notes["privilege-escalation"] = fmt.Sprintf(
			"%d principals carry no policy documents, so no escalation can be computed. The `admin` flag "+
				"records who ALREADY is an administrator; it cannot answer who can BECOME one. Populate "+
				"`policies` (and `permission_boundary`) per principal.", principals)
		return c
	}

	// A policy that is PRESENT but unreadable is the case the check above cannot see: withPolicies
	// counts it, so no note fires, while the ingest skips every unparseable document and the account
	// comes back with no escalation paths. "We could not read your policies" and "nobody can escalate"
	// then look identical, and only one of them is true.
	//
	// This is not hypothetical. A snapshot carrying AWS's own URL-encoded documents produced zero
	// privescs and zero notes before this — a confident all-clear over an account nothing had been
	// evaluated in. cloudiam.Parse now reads that form, so what lands here is genuinely unreadable,
	// which is exactly when someone needs to be told.
	if names := unreadablePrincipals(raw); len(names) > 0 {
		c.Notes["unreadable-policies"] = fmt.Sprintf(
			"%d principal(s) carry policy documents that could not be parsed, so nothing was evaluated "+
				"for them and any escalation they permit is INVISIBLE here — not absent: %s. Check the "+
				"collector is forwarding the policy JSON intact.", len(names), strings.Join(names, ", "))
	}
	return c
}

// unreadablePrincipals names principals whose every policy document failed to parse. Every-not-any
// deliberately: a principal with one bad document and one good one was still evaluated against the
// good one, so its escalations are reported and it is not the silent case this note is about.
func unreadablePrincipals(raw awsinventory.RawAWS) []string {
	var out []string
	check := func(name string, docs []string) {
		var present, bad int
		for _, js := range docs {
			if strings.TrimSpace(js) == "" {
				continue
			}
			present++
			if d, err := cloudiam.Parse([]byte(js)); err != nil || d == nil {
				bad++
			}
		}
		if present > 0 && bad == present {
			out = append(out, name)
		}
	}
	for _, r := range raw.Roles {
		check(r.Name, r.PoliciesJSON)
	}
	for _, u := range raw.Users {
		check(u.Name, u.PoliciesJSON)
	}
	sort.Strings(out)
	return out
}

// CoverGCP reports what a posted RawGCP cannot answer.
//
// GCP has an extra failure mode AWS does not: gcpiam treats a role whose definition it
// lacks as POSSIBLY granting anything, and gcpinventory refuses to build an edge on that
// possibility (see derivePrivesc's firm-allow rule). So unresolvable roles cause SILENT
// under-reporting, and naming them is the only way a caller learns the answer was partial.
func CoverGCP(raw gcpinventory.RawGCP) InventoryCoverage {
	c := InventoryCoverage{Notes: map[string]string{}}
	if len(raw.ServiceAccounts)+len(raw.Members) == 0 {
		c.Notes["identity"] = "no service accounts or members in the snapshot — no principal can be " +
			"evaluated. Populate `service_accounts` and `members`."
	}
	if len(raw.Bindings) == 0 {
		c.Notes["privilege-escalation"] = "no IAM bindings in the snapshot, so no escalation can be " +
			"computed. The `admin` flag records who ALREADY is an administrator; it cannot answer who can " +
			"BECOME one. Populate `bindings` with the project IAM policy."
		return c
	}
	if unknown := gcpinventory.UnknownRoles(raw); len(unknown) > 0 {
		shown := unknown
		if len(shown) > 5 {
			shown = append(append([]string{}, shown[:5]...), fmt.Sprintf("…and %d more", len(unknown)-5))
		}
		c.Notes["custom-role-permissions"] = "the permissions of these roles were not supplied, so any " +
			"escalation through them is NOT reported (a role we cannot resolve is treated as proving " +
			"nothing, never as granting everything): " + strings.Join(shown, ", ") +
			". Populate `role_defs` with each role's permission list."
	}
	return c
}
