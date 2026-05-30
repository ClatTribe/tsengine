package cloudgraph

import (
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/internal/cloudiam"
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
