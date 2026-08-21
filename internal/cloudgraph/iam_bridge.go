package cloudgraph

import (
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/internal/azureiam"
	"github.com/ClatTribe/tsengine/internal/cloudiam"
	"github.com/ClatTribe/tsengine/internal/gcpiam"
)

// AdminID is the synthetic "effective admin" node. A principal that can run a
// known IAM privesc technique can reach admin-equivalent control, modelled as a
// privesc edge principal → admin — so FindPaths(…, PrivilegedIdentity) discovers
// "internet → … → principal → privesc → admin" chains.
const AdminID = "admin"

// AddPrivescEdges uses the IAM effective-permissions evaluator (cloudiam) to add
// a privesc edge from every escalation-capable principal to the synthetic admin
// node. This is how raw IAM policy documents become traversable attack edges —
// the resolve_access → graph bridge (ADR 0002 / design §2). policies maps a
// principal id → its combined policy docs.
// PrincipalPolicies is one principal's policy set as AWS actually evaluates it.
//
// It exists because a principal's ATTACHED policies are not its effective permissions.
// AWS computes effective = attached ∧ permission-boundary, and a bridge that reads only
// the attached half reports escalations the account genuinely blocks.
type PrincipalPolicies struct {
	// Identity are the attached/inline policy documents.
	Identity []*cloudiam.Document
	// Boundary is the permission boundary — a CEILING, not a grant. Nil means the
	// principal has none, which is different from having an empty one.
	Boundary *cloudiam.Document
}

// AddPrivescEdges uses the IAM effective-permissions evaluator (cloudiam) to add
// a privesc edge from every escalation-capable principal to the synthetic admin
// node. This is how raw IAM policy documents become traversable attack edges —
// the resolve_access → graph bridge (ADR 0002 / design §2). policies maps a
// principal id → its combined policy docs.
//
// Boundary-unaware: prefer AddPrivescEdgesWithBoundaries wherever the boundary is
// known. Kept because a caller that genuinely has no boundary data should not be
// forced to pass an empty one — nil boundary and no-boundary must stay distinguishable.
func (s *Snapshot) AddPrivescEdges(policies map[string][]*cloudiam.Document) {
	withBoundaries := make(map[string]PrincipalPolicies, len(policies))
	for pid, docs := range policies {
		withBoundaries[pid] = PrincipalPolicies{Identity: docs}
	}
	s.AddPrivescEdgesWithBoundaries(withBoundaries)
}

// AddPrivescEdgesWithBoundaries is AddPrivescEdges evaluating the PERMISSION BOUNDARY
// alongside the attached policies — i.e. the permission AWS would actually grant.
//
// WHY THIS EXISTS. The held-out generalization benchmark (cloudengine/holdout.go)
// measured a 50-point gap between inert shapes the engine encodes and inert shapes it
// does not, and named this one: a role whose attached policy allows
// iam:CreatePolicyVersion while its boundary permits only s3:Get* cannot escalate, and
// the engine reported a path to admin anyway. The interpretation in that file was
// exact — "tsengine HAS the evaluator to close this; the fix is wiring it into ingest"
// — so this is wiring, not new detection logic.
//
// A false attack path is worse than a missed one here: it sends someone to sever a route
// that was never open while the real one stays open, and it does it with the confidence
// of a rendered graph.
func (s *Snapshot) AddPrivescEdgesWithBoundaries(policies map[string]PrincipalPolicies) {
	// deterministic order
	ids := make([]string, 0, len(policies))
	for id := range policies {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var added bool
	for _, pid := range ids {
		pp := policies[pid]
		docs := pp.Identity
		if len(docs) == 0 {
			continue
		}
		ps := cloudiam.PolicySet{Identity: docs, Boundary: pp.Boundary, SameAccount: true}
		// The effective-permission question, answered by the evaluator rather than by
		// reading the attached policy alone. With no boundary this is exactly the old
		// behaviour; with one, the ceiling applies as AWS applies it.
		can := func(a string) bool {
			dec, _ := cloudiam.Authorize(cloudiam.Request{Principal: pid, Action: a, Resource: "*"}, ps)
			return dec == cloudiam.Allow
		}
		techs := cloudiam.DetectPrivesc(can)
		if len(techs) == 0 {
			continue
		}
		if !added {
			if s.Node(AdminID) == nil {
				s.AddNode(&Node{ID: AdminID, Kind: KindPrincipal, Name: "effective-admin", Privileged: true})
			}
			added = true
		}
		// If EVERY detected escalation depends on a condition-gated permission (no technique is reachable
		// UNCONDITIONALLY), the privesc is config-possible only, not definite: mark the edge conditional so
		// Path.Conditional() flags a path through it for live validation (ADR-0002 / §10), rather than
		// over-claiming a definite escalation. canFirm keeps only unconditional grants — and it applies the
		// SAME boundary, or a boundary-blocked escalation would be reported as merely conditional instead
		// of absent.
		canFirm := func(a string) bool {
			dec, cond := cloudiam.Authorize(cloudiam.Request{Principal: pid, Action: a, Resource: "*"}, ps)
			return dec == cloudiam.Allow && !cond
		}
		condition := ""
		if len(cloudiam.DetectPrivesc(canFirm)) == 0 {
			condition = condGated
		}
		s.AddEdge(Edge{From: pid, To: AdminID, Kind: EdgePrivesc, Detail: techNames(techs), Condition: condition})
	}
}

// PermitFunc answers "may this principal perform X" AND whether that answer rests on a condition
// we could not resolve. Both bits, because a caller wrapping gcpiam/azureiam.Authorize already has
// both — those return (Decision, bool) — and a plain func(string) bool discards the second at the
// boundary.
//
// Discarding it is not neutral. It forces a choice between two wrong answers, and BOTH have shipped
// here. Detect with allow-including-conditional and a condition-gated escalation is reported as
// DEFINITE. Detect with unconditional-only and it VANISHES — which is what the GCP ingest did: a
// member holding roles/resourcemanager.projectIamAdmin under an IAM condition produced no privesc at
// all, so the attack-path page said there was no way to become admin. The condition in the test that
// caught it is satisfied today.
//
// With both bits the edge is emitted AND marked config-possible, which is what the AWS path has
// always done and what InvPrivesc.Condition already exists for.
type PermitFunc func(permission string) (allowed, conditional bool)

// condGated is the shared wording, so all four clouds make the same claim about the same evidence
// rather than four slightly different ones.
const condGated = "iam-condition-gated escalation (config-possible; validate live)"

// Unconditional adapts a plain predicate for a source whose grants genuinely carry no conditions —
// Entra app-role assignments and directory-role memberships, for instance, unlike ARM RBAC.
//
// It exists so that claim has to be MADE. Accepting func(string) bool directly would let any caller
// assert "definitely allowed" by omission, which is how the conditional bit got dropped in the first
// place; spelling it Unconditional puts the assertion in the call site where a reviewer can see it.
func Unconditional(f func(string) bool) PermitFunc {
	return func(a string) (bool, bool) { return f(a), false }
}

// split turns one PermitFunc into the permissive and firm predicates DetectPrivesc takes. A nil
// entry yields predicates that permit nothing — a principal the caller could not evaluate gets no
// edge, rather than an edge built on a nil deref.
func split(p PermitFunc) (permits, firm func(string) bool) {
	if p == nil {
		return func(string) bool { return false }, func(string) bool { return false }
	}
	return func(a string) bool {
			allowed, _ := p(a)
			return allowed
		}, func(a string) bool {
			allowed, cond := p(a)
			return allowed && !cond
		}
}

// AddGCPPrivescEdges is the GCP twin of AddPrivescEdges: a per-principal effective-permission predicate
// (typically wrapping gcpiam.Authorize over the principal's hierarchy-inherited bindings) feeds
// gcpiam.DetectPrivesc, adding a privesc → admin edge for every escalation-capable GCP principal. So
// "internet → … → gcp-principal → privesc → admin" chains are discovered symmetrically with AWS (§10).
// The caller (ingest) builds the `can` predicates from the GCP snapshot's IAM bindings.
func (s *Snapshot) AddGCPPrivescEdges(can map[string]PermitFunc) {
	ids := make([]string, 0, len(can))
	for id := range can {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var added bool
	for _, pid := range ids {
		permits, firm := split(can[pid])
		techs := gcpiam.DetectPrivesc(permits)
		condition := ""
		if len(gcpiam.DetectPrivesc(firm)) == 0 {
			condition = condGated
		}
		if len(techs) == 0 {
			continue
		}
		if !added {
			if s.Node(AdminID) == nil {
				s.AddNode(&Node{ID: AdminID, Kind: KindPrincipal, Name: "effective-admin", Privileged: true})
			}
			added = true
		}
		s.AddEdge(Edge{From: pid, To: AdminID, Kind: EdgePrivesc, Detail: gcpTechNames(techs), Condition: condition})
	}
}

func gcpTechNames(ts []gcpiam.Technique) string {
	names := make([]string, len(ts))
	for i, t := range ts {
		names[i] = t.Name
	}
	return strings.Join(names, ",")
}

// AddAzurePrivescEdges is the Azure twin of AddPrivescEdges / AddGCPPrivescEdges: a per-principal
// effective-permission predicate (typically wrapping azureiam.Authorize over the principal's
// hierarchy-inherited role assignments) feeds azureiam.DetectPrivesc, adding a privesc → admin edge for
// every escalation-capable Azure principal — so privesc chains are discovered symmetrically across
// AWS+GCP+Azure (§10). The caller (ingest) builds the `can` predicates from the Azure snapshot's RBAC.
func (s *Snapshot) AddAzurePrivescEdges(can map[string]PermitFunc) {
	ids := make([]string, 0, len(can))
	for id := range can {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var added bool
	for _, pid := range ids {
		permits, firm := split(can[pid])
		techs := azureiam.DetectPrivesc(permits)
		condition := ""
		if len(azureiam.DetectPrivesc(firm)) == 0 {
			condition = condGated
		}
		if len(techs) == 0 {
			continue
		}
		if !added {
			if s.Node(AdminID) == nil {
				s.AddNode(&Node{ID: AdminID, Kind: KindPrincipal, Name: "effective-admin", Privileged: true})
			}
			added = true
		}
		s.AddEdge(Edge{From: pid, To: AdminID, Kind: EdgePrivesc, Detail: azureTechNames(techs), Condition: condition})
	}
}

func azureTechNames(ts []azureiam.Technique) string {
	names := make([]string, len(ts))
	for i, t := range ts {
		names[i] = t.Name
	}
	return strings.Join(names, ",")
}

// AddAzureEntraPrivescEdges is the ENTRA (Azure AD) graph-plane twin of AddAzurePrivescEdges: a
// per-principal predicate over the principal's effective Microsoft Graph permissions / directory roles
// feeds azureiam.DetectEntraPrivesc, adding a privesc → admin edge for every principal that can escalate
// on the IDENTITY plane (add a credential to a privileged app, self-assign a directory role, …). This is a
// DISTINCT authorization plane from ARM (§10 — the two are not conflated): an attacker can own the tenant
// via Entra without ever touching an ARM role assignment, so without this the attack path is invisible.
// The caller (ingest) builds the `can` predicates from the Entra snapshot's app-role assignments +
// directory-role memberships (the honest gate — same as the ARM side). Edge Detail is prefixed so an Entra
// escalation is distinguishable from an ARM one in the graph.
func (s *Snapshot) AddAzureEntraPrivescEdges(can map[string]PermitFunc) {
	ids := make([]string, 0, len(can))
	for id := range can {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var added bool
	for _, pid := range ids {
		permits, firm := split(can[pid])
		techs := azureiam.DetectEntraPrivesc(permits)
		condition := ""
		if len(azureiam.DetectEntraPrivesc(firm)) == 0 {
			condition = condGated
		}
		if len(techs) == 0 {
			continue
		}
		if !added {
			if s.Node(AdminID) == nil {
				s.AddNode(&Node{ID: AdminID, Kind: KindPrincipal, Name: "effective-admin", Privileged: true})
			}
			added = true
		}
		s.AddEdge(Edge{From: pid, To: AdminID, Kind: EdgePrivesc, Detail: azureTechNames(techs), Condition: condition})
	}
}

// AddEntraOwnershipEdges is the RELATIONSHIP half of Entra graph-plane privesc (the permission half is
// AddAzureEntraPrivescEdges) — the documented next slice from #988. In Entra, OWNING an app registration
// or service principal lets you add a credential to it and authenticate AS it, inheriting its privilege.
// So an owner of a PRIVILEGED service principal (or one that can itself escalate to admin) is effectively
// admin — the canonical BloodHound "Owns → AZServicePrincipal" attack edge, invisible to a permission-only
// view. ownerships maps an owner principal id → the node ids it owns; the ingest builds it from the Entra
// snapshot's app/SP `owners` (the honest gate — same as the permission side).
//
// Grounded (§10): an owner→admin edge is added ONLY when the OWNED node is really privileged — either its
// Node.Privileged flag is set OR it already has a privesc→admin edge (so run this AFTER
// AddAzureEntraPrivescEdges to pick up permission-escalating SPs too). Owning a NON-privileged SP adds
// nothing. Self-ownership and unknown owned nodes are skipped.
func (s *Snapshot) AddEntraOwnershipEdges(ownerships map[string][]string) {
	// nodes that can reach admin via their own privesc edge (so owning them = inheriting that escalation).
	escalates := map[string]bool{}
	for _, e := range s.Edges {
		if e.Kind == EdgePrivesc && e.To == AdminID {
			escalates[e.From] = true
		}
	}

	owners := make([]string, 0, len(ownerships))
	for o := range ownerships {
		owners = append(owners, o)
	}
	sort.Strings(owners)

	for _, owner := range owners {
		owned := append([]string(nil), ownerships[owner]...)
		sort.Strings(owned)
		for _, sp := range owned {
			if sp == owner {
				continue // self-ownership escalates nothing
			}
			n := s.Node(sp)
			privileged := (n != nil && n.Privileged) || escalates[sp]
			if !privileged {
				continue // owning a non-privileged SP is not an escalation (grounded)
			}
			if s.Node(AdminID) == nil {
				s.AddNode(&Node{ID: AdminID, Kind: KindPrincipal, Name: "effective-admin", Privileged: true})
			}
			s.AddEdge(Edge{From: owner, To: AdminID, Kind: EdgePrivesc, Detail: "Entra:OwnerOfPrivilegedSP(" + sp + ")"})
		}
	}
}

// HasAccess answers resolve_access for an (principal, action, resource): does the
// principal's combined policy permit it (and is it conditional)? The ingest uses
// this to build has_access edges.
func HasAccess(action, resource string, docs ...*cloudiam.Document) (allowed, conditional bool) {
	return cloudiam.Allows(action, resource, docs...)
}

func techNames(ts []cloudiam.Technique) string {
	names := make([]string, len(ts))
	for i, t := range ts {
		names[i] = t.Name
	}
	return strings.Join(names, ",")
}
