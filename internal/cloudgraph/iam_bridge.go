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
func (s *Snapshot) AddPrivescEdges(policies map[string][]*cloudiam.Document) {
	// deterministic order
	ids := make([]string, 0, len(policies))
	for id := range policies {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var added bool
	for _, pid := range ids {
		docs := policies[pid]
		can := func(a string) bool { return cloudiam.CanDo(a, docs...) }
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
		// over-claiming a definite escalation. canFirm keeps only unconditional grants (Allows cond=false).
		canFirm := func(a string) bool {
			ok, cond := cloudiam.Allows(a, "*", docs...)
			return ok && !cond
		}
		condition := ""
		if len(cloudiam.DetectPrivesc(canFirm)) == 0 {
			condition = "iam-condition-gated escalation (config-possible; validate live)"
		}
		s.AddEdge(Edge{From: pid, To: AdminID, Kind: EdgePrivesc, Detail: techNames(techs), Condition: condition})
	}
}

// AddGCPPrivescEdges is the GCP twin of AddPrivescEdges: a per-principal effective-permission predicate
// (typically wrapping gcpiam.Authorize over the principal's hierarchy-inherited bindings) feeds
// gcpiam.DetectPrivesc, adding a privesc → admin edge for every escalation-capable GCP principal. So
// "internet → … → gcp-principal → privesc → admin" chains are discovered symmetrically with AWS (§10).
// The caller (ingest) builds the `can` predicates from the GCP snapshot's IAM bindings.
func (s *Snapshot) AddGCPPrivescEdges(can map[string]func(permission string) bool) {
	ids := make([]string, 0, len(can))
	for id := range can {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var added bool
	for _, pid := range ids {
		techs := gcpiam.DetectPrivesc(can[pid])
		if len(techs) == 0 {
			continue
		}
		if !added {
			if s.Node(AdminID) == nil {
				s.AddNode(&Node{ID: AdminID, Kind: KindPrincipal, Name: "effective-admin", Privileged: true})
			}
			added = true
		}
		s.AddEdge(Edge{From: pid, To: AdminID, Kind: EdgePrivesc, Detail: gcpTechNames(techs)})
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
func (s *Snapshot) AddAzurePrivescEdges(can map[string]func(action string) bool) {
	ids := make([]string, 0, len(can))
	for id := range can {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var added bool
	for _, pid := range ids {
		techs := azureiam.DetectPrivesc(can[pid])
		if len(techs) == 0 {
			continue
		}
		if !added {
			if s.Node(AdminID) == nil {
				s.AddNode(&Node{ID: AdminID, Kind: KindPrincipal, Name: "effective-admin", Privileged: true})
			}
			added = true
		}
		s.AddEdge(Edge{From: pid, To: AdminID, Kind: EdgePrivesc, Detail: azureTechNames(techs)})
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
func (s *Snapshot) AddAzureEntraPrivescEdges(can map[string]func(perm string) bool) {
	ids := make([]string, 0, len(can))
	for id := range can {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var added bool
	for _, pid := range ids {
		techs := azureiam.DetectEntraPrivesc(can[pid])
		if len(techs) == 0 {
			continue
		}
		if !added {
			if s.Node(AdminID) == nil {
				s.AddNode(&Node{ID: AdminID, Kind: KindPrincipal, Name: "effective-admin", Privileged: true})
			}
			added = true
		}
		s.AddEdge(Edge{From: pid, To: AdminID, Kind: EdgePrivesc, Detail: azureTechNames(techs)})
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
