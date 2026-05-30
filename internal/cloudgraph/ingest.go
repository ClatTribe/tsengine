package cloudgraph

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

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
	AccountID  string        `json:"account_id"`
	Provider   string        `json:"provider"`
	CapturedAt time.Time     `json:"captured_at,omitempty"`
	Resources  []InvResource `json:"resources,omitempty"`
	Trusts     []InvTrust    `json:"trusts,omitempty"`  // principal → role it may assume
	Passes     []InvPass     `json:"passes,omitempty"`  // principal → role it may pass (iam:PassRole)
	Grants     []InvGrant    `json:"grants,omitempty"`  // principal → resource it may access
	Reaches    []InvReach    `json:"reaches,omitempty"` // network reachability (incl. internet exposure)
	RunsAs     []InvRunsAs   `json:"runs_as,omitempty"`
	Privescs   []InvPrivesc  `json:"privescs,omitempty"` // known IAM privesc edges (PMapper-style)
}

// InvResource is one resource or identity.
type InvResource struct {
	ID         string            `json:"id"`
	Kind       NodeKind          `json:"kind"`
	Type       string            `json:"type,omitempty"`
	Name       string            `json:"name,omitempty"`
	Region     string            `json:"region,omitempty"`
	Public     bool              `json:"public,omitempty"`
	Sensitive  Sensitivity       `json:"sensitive,omitempty"`
	Privileged bool              `json:"privileged,omitempty"`
	Tags       map[string]string `json:"tags,omitempty"`
}

type InvTrust struct {
	Principal string `json:"principal"`
	Role      string `json:"role"`
	Condition string `json:"condition,omitempty"`
}
type InvPass struct {
	Principal string `json:"principal"`
	Role      string `json:"role"`
}
type InvGrant struct {
	Principal string `json:"principal"`
	Resource  string `json:"resource"`
	Condition string `json:"condition,omitempty"`
}
type InvReach struct {
	From      string `json:"from"` // may be InternetID
	To        string `json:"to"`
	Condition string `json:"condition,omitempty"`
}
type InvRunsAs struct {
	Compute   string `json:"compute"`
	Principal string `json:"principal"`
}
type InvPrivesc struct {
	Principal string `json:"principal"`
	Target    string `json:"target"`
	Detail    string `json:"detail,omitempty"`
}

// ParseInventory decodes a normalized inventory JSON document. This is the
// operator-facing seam: a CloudQuery/Cartography export (or any inventory
// script) emits this JSON; tsengine reasons over it. SUT-agnostic — no AWS, no
// network.
func ParseInventory(b []byte) (Inventory, error) {
	var inv Inventory
	if err := json.Unmarshal(b, &inv); err != nil {
		return inv, fmt.Errorf("cloudgraph: parse inventory: %w", err)
	}
	return inv, nil
}

// LoadSnapshot reads an inventory JSON file and ingests it into a Snapshot.
func LoadSnapshot(path string) (*Snapshot, error) {
	b, err := os.ReadFile(path) //nolint:gosec // operator-provided inventory path
	if err != nil {
		return nil, fmt.Errorf("cloudgraph: read inventory %s: %w", path, err)
	}
	inv, err := ParseInventory(b)
	if err != nil {
		return nil, err
	}
	return Ingest(inv), nil
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
