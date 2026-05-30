package cloudgraph

import "time"

// Inventory is the normalized cloud state an ingest source produces — the seam
// between the (sandbox-side, AWS-touching) CloudQuery/Cartography runner and the
// pure graph model here. The runner extracts config into this shape; Ingest maps
// it into a Snapshot. Keeping the binary + AWS out of this package is what makes
// the engineer's reasoning fully unit-testable and reproducible.
//
// Edges are split by relationship so an ingest source can emit them
// independently (e.g. IAM trust analysis → Trusts; a reachability pass →
// Reaches). Computing Grants/Trusts from raw IAM policies (the effective-perms
// evaluation, wrapping cloudsplaining/PMapper) is the source's job — this mapper
// just assembles the graph.
type Inventory struct {
	AccountID  string
	Provider   string
	CapturedAt time.Time
	Resources  []InvResource
	Trusts     []InvTrust // principal → role it may assume
	Passes     []InvPass  // principal → role it may pass (iam:PassRole)
	Grants     []InvGrant // principal → resource it may access
	Reaches    []InvReach // network reachability (incl. internet exposure)
	RunsAs     []InvRunsAs
	Privescs   []InvPrivesc // known IAM privesc edges (PMapper-style)
}

// InvResource is one resource or identity.
type InvResource struct {
	ID         string
	Kind       NodeKind
	Type       string
	Name       string
	Region     string
	Public     bool
	Sensitive  Sensitivity
	Privileged bool
	Tags       map[string]string
}

type InvTrust struct {
	Principal, Role, Condition string
}
type InvPass struct {
	Principal, Role string
}
type InvGrant struct {
	Principal, Resource, Condition string
}
type InvReach struct {
	From, To, Condition string // From may be InternetID
}
type InvRunsAs struct {
	Compute, Principal string
}
type InvPrivesc struct {
	Principal, Target, Detail string
}

// Ingest assembles a Snapshot from a normalized Inventory.
func Ingest(inv Inventory) *Snapshot {
	s := New(inv.AccountID, inv.Provider)
	s.CapturedAt = inv.CapturedAt
	for _, r := range inv.Resources {
		s.AddNode(&Node{
			ID: r.ID, Kind: r.Kind, Type: r.Type, Name: r.Name, Region: r.Region,
			Public: r.Public, Sensitive: r.Sensitive, Privileged: r.Privileged, Tags: r.Tags,
		})
	}
	// The internet pseudo-node always exists so reachability from "the outside"
	// is expressible.
	if s.Node(InternetID) == nil {
		s.AddNode(&Node{ID: InternetID, Kind: KindNetwork, Name: "internet"})
	}
	for _, t := range inv.Trusts {
		s.AddEdge(Edge{From: t.Principal, To: t.Role, Kind: EdgeAssumeRole, Condition: t.Condition})
	}
	for _, p := range inv.Passes {
		s.AddEdge(Edge{From: p.Principal, To: p.Role, Kind: EdgePassRole})
	}
	for _, g := range inv.Grants {
		s.AddEdge(Edge{From: g.Principal, To: g.Resource, Kind: EdgeHasAccess, Condition: g.Condition})
	}
	for _, r := range inv.Reaches {
		s.AddEdge(Edge{From: r.From, To: r.To, Kind: EdgeNetworkReach, Condition: r.Condition})
	}
	for _, ra := range inv.RunsAs {
		s.AddEdge(Edge{From: ra.Compute, To: ra.Principal, Kind: EdgeRunsAs})
	}
	for _, pe := range inv.Privescs {
		s.AddEdge(Edge{From: pe.Principal, To: pe.Target, Kind: EdgePrivesc, Detail: pe.Detail})
	}
	return s
}
