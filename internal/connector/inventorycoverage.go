package connector

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/internal/cloudiam"
	"github.com/ClatTribe/tsengine/internal/connector/awsinventory"
	"github.com/ClatTribe/tsengine/internal/connector/azinventory"
	"github.com/ClatTribe/tsengine/internal/connector/gcpinventory"
	"github.com/ClatTribe/tsengine/internal/connector/k8sinventory"
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

// CoverK8s reports what a posted RawK8s cannot answer.
//
// Kubernetes was the fourth provider to reach this ingest and the only one that returned an EMPTY
// coverage — so a manifest missing the very objects the analysis reads produced zero privesc edges,
// zero internet reach, and no note saying why. On an attack-path page zero reads as "nobody can
// become admin in this cluster", which is the single most reassuring thing this product can say and
// the most damaging to say wrongly. It is the same defect CoverAWS and CoverGCP exist to prevent,
// arriving through the door that had no guard.
//
// The gaps are named per CONCERN, and each names the FIELD to populate — the caller is usually a
// script running `kubectl get`, and "something is missing" is not something a script author can act
// on.
//
// Note what is NOT reported: an empty `secrets` or `pods` list. A cluster genuinely may have neither,
// and a note there would fire on healthy clusters until people learned to ignore all of them.
// Bindings and roles are different: without them RBAC cannot be evaluated AT ALL, so their absence
// changes what the result MEANS rather than what it contains.
func CoverK8s(raw k8sinventory.RawK8s) InventoryCoverage {
	c := InventoryCoverage{Notes: map[string]string{}}

	if len(raw.ServiceAccounts) == 0 {
		c.Notes["identity"] = "no service accounts in the snapshot — a cluster runs its workloads as " +
			"ServiceAccounts, so with none there is no principal an attack path can start from. " +
			"Populate `service_accounts` (kubectl get serviceaccounts -A)."
	}

	// RBAC is TWO objects and either one alone decides nothing: a role carries the verbs, a binding
	// says who holds them. Missing either yields no grant edge and therefore no escalation, and the
	// two are reported separately because the fix differs.
	if len(raw.Roles) == 0 {
		c.Notes["rbac-roles"] = "no roles in the snapshot — escalating VERBS (bind, escalate, " +
			"impersonate, create-pod) live on Roles and ClusterRoles, so with none present no " +
			"privilege escalation can be computed and an empty result means UNREAD. Populate `roles` " +
			"(kubectl get roles,clusterroles -A)."
	}
	if len(raw.Bindings) == 0 {
		c.Notes["rbac-bindings"] = "no bindings in the snapshot — a Role grants nothing until a " +
			"RoleBinding names who holds it, so no principal can be connected to any permission. " +
			"Populate `bindings` (kubectl get rolebindings,clusterrolebindings -A)."
	}

	// A binding pointing at a role we do not have is the cluster twin of GCP's unresolvable custom
	// role, and it fails the same way: the grant is real, the verbs are unknown, and no edge is
	// built. Silence there under-reports exactly the principals somebody granted something to.
	if missing := unresolvedRoleRefs(raw); len(missing) > 0 {
		c.Notes["unresolved-roles"] = fmt.Sprintf(
			"%d binding(s) reference a role that is not in the snapshot, so what they grant is unknown "+
				"and no escalation was computed for their subjects — not absent, UNREAD: %s. Include "+
				"ClusterRoles as well as namespaced Roles.", len(missing), strings.Join(missing, ", "))
	}

	// Exposure is the other half of a path. Without Services nothing is internet-reachable, which
	// makes every workload look internal — a cluster with a LoadBalancer in front of it would render
	// as unreachable from outside.
	if len(raw.Services) == 0 {
		c.Notes["exposure"] = "no services in the snapshot — internet reach is derived from " +
			"LoadBalancer / NodePort / externally-addressed Services, so with none present every " +
			"workload reads as internal whether or not it is. Populate `services` " +
			"(kubectl get services -A)."
	}
	return c
}

// unresolvedRoleRefs names bindings whose roleRef matches no role in the snapshot.
//
// Matched on NAME alone, deliberately: a RoleBinding may reference a ClusterRole, which carries no
// namespace, so requiring the namespaces to agree would report every legitimate cluster-role binding
// as unresolved — a note that fires constantly is one nobody reads.
func unresolvedRoleRefs(raw k8sinventory.RawK8s) []string {
	known := make(map[string]bool, len(raw.Roles))
	for _, r := range raw.Roles {
		known[r.Name] = true
	}
	seen := map[string]bool{}
	var out []string
	for _, b := range raw.Bindings {
		ref := strings.TrimSpace(b.RoleRef)
		if ref == "" || known[ref] {
			continue
		}
		if label := b.Name + "→" + ref; !seen[label] {
			seen[label] = true
			out = append(out, label)
		}
	}
	sort.Strings(out)
	return out
}

// CoverAzure reports what a posted RawAzure cannot answer.
//
// Azure returned an empty coverage with a comment saying "no coverage analyser yet: Azure reports
// nothing rather than claiming completeness it has not checked" — but an empty InventoryCoverage is
// not silence. Summary() renders it as "This snapshot carries everything the engine knows how to
// evaluate", so the honest intention produced the confident claim it was trying to avoid.
//
// AZURE HAS TWO AUTHORIZATION PLANES AND THEY ARE NEVER CONFLATED (§10). ARM RBAC decides what a
// principal may do to SUBSCRIPTION RESOURCES; Entra (Azure AD) decides what it may do to the
// DIRECTORY — and an attacker who owns the tenant through Entra never touches an ARM role assignment
// at all. This ingest carries the ARM plane only, so the Entra gap is declared on every snapshot
// rather than left to look like an absence of findings.
func CoverAzure(raw azinventory.RawAzure) InventoryCoverage {
	c := InventoryCoverage{Notes: map[string]string{}}

	if len(raw.Principals) == 0 {
		c.Notes["identity"] = "no principals in the snapshot — no managed identity, service principal " +
			"or user can be evaluated, so no attack path can start from one. Populate `principals`."
	}

	if len(raw.RoleAssignments) == 0 {
		c.Notes["privilege-escalation"] = "no role assignments in the snapshot, so no ARM escalation " +
			"can be computed. The `admin` flag records who ALREADY is an administrator; it cannot " +
			"answer who can BECOME one. Populate `role_assignments` (and `role_definitions` for custom " +
			"roles, `deny_assignments` where they exist)."
	} else if unknown := azinventory.UnknownRoles(raw); len(unknown) > 0 {
		// The firm-allow rule means an escalation through a role we lack the definition for is NOT
		// reported. That silence under-reports exactly the principals somebody granted a bespoke role
		// to, which is where the interesting permissions usually live.
		c.Notes["unresolved-roles"] = fmt.Sprintf(
			"%d custom role(s) are assigned but their definitions were not supplied, so what they "+
				"permit is unknown and no escalation was computed through them — not absent, UNREAD: %s. "+
				"Populate `role_definitions` for these.", len(unknown), strings.Join(unknown, ", "))
	}

	// ALWAYS declared, because this ingest has no field for it at all. A gap that can never be closed
	// by sending more of the same document has to be stated on every snapshot, or its absence reads
	// as a clean directory.
	c.Notes["entra-directory"] = "this snapshot carries the ARM plane only. Entra (Azure AD) is a " +
		"SEPARATE authorization plane — Graph application permissions, privileged directory roles and " +
		"service-principal ownership — and an attacker who takes the tenant through Entra never " +
		"touches an ARM role assignment. Nothing here evaluates it, so an empty Entra result is not a " +
		"finding about the directory."

	// Reachability is the other half of a path: with no VMs or storage, nothing is exposed and every
	// escalation leads nowhere in particular.
	if len(raw.VMs)+len(raw.Storage) == 0 {
		c.Notes["exposure"] = "no VMs or storage accounts in the snapshot — internet reachability and " +
			"public-data exposure are derived from those, so with none present nothing reads as " +
			"exposed whether or not it is. Populate `vms` and `storage`."
	}
	return c
}
