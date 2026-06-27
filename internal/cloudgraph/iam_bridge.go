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
		s.AddEdge(Edge{From: pid, To: AdminID, Kind: EdgePrivesc, Detail: techNames(techs)})
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
