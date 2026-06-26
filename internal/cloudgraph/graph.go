// Package cloudgraph is the pinned cloud inventory snapshot the AI Cloud
// Security Engineer reasons over (ADR 0002, docs/design/ai-cloud-engineer.md).
//
// A Snapshot is a content-addressed graph of cloud resources, identities, and
// the relationships between them ("moves" an attacker can make: assume-role,
// pass-role, network-reach, has-access). It is the L3 hypothesis substrate: the
// engineer forms attack-path hypotheses cheaply and comprehensively over this
// static graph (zero live blast radius), then validates the few that matter.
//
// This package is pure (no cloud, no I/O): the live CloudQuery/Cartography
// runner that *populates* a Snapshot is a separate sandbox-side adapter; here we
// model the graph and the deterministic reasoning over it (FindPaths) so it is
// fully unit-testable and reproducible (snapshot_hash, CLAUDE.md §10).
package cloudgraph

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"time"
)

// NodeKind classifies a graph vertex.
type NodeKind string

const (
	KindResource  NodeKind = "resource"  // S3 bucket, EC2 instance, Lambda, …
	KindPrincipal NodeKind = "principal" // IAM user / role / group / external / service
	KindNetwork   NodeKind = "network"   // the "internet" pseudo-node, VPC, subnet
	KindData      NodeKind = "data"      // a data store, carrying a sensitivity signal
)

// Sensitivity is the data-classification signal (metadata only — never the data
// itself; ADR 0002 safety rule).
type Sensitivity string

const (
	SensNone Sensitivity = ""
	SensLow  Sensitivity = "low"
	SensHigh Sensitivity = "high" // PII / secrets / prod
)

// InternetID is the well-known pseudo-node representing any external attacker.
const InternetID = "internet"

// Node is one vertex: a cloud resource, identity, or pseudo-node.
type Node struct {
	ID         string            `json:"id"` // stable id (ARN, or "internet")
	Kind       NodeKind          `json:"kind"`
	Type       string            `json:"type,omitempty"` // "AWS::S3::Bucket", "AWS::IAM::Role", …
	Name       string            `json:"name,omitempty"`
	Region     string            `json:"region,omitempty"`
	Public     bool              `json:"public,omitempty"`     // internet-exposed per config
	Sensitive  Sensitivity       `json:"sensitive,omitempty"`  // data-class (metadata signal)
	Privileged bool              `json:"privileged,omitempty"` // high-privilege identity (admin-ish)
	Tags       map[string]string `json:"tags,omitempty"`
	Attrs      map[string]string `json:"attrs,omitempty"` // misc config signals
}

// EdgeKind is the relationship type — the "moves" that compose an attack path.
type EdgeKind string

const (
	EdgeAssumeRole   EdgeKind = "assume_role"   // principal can sts:AssumeRole target
	EdgePassRole     EdgeKind = "pass_role"     // principal can iam:PassRole target
	EdgeHasAccess    EdgeKind = "has_access"    // principal can read/write a resource
	EdgeNetworkReach EdgeKind = "network_reach" // src can reach dst over the network
	EdgeRunsAs       EdgeKind = "runs_as"       // compute runs with this principal (instance profile / exec role)
	EdgePrivesc      EdgeKind = "privesc"       // a known IAM privesc move (PMapper-style)
	// EdgeTriggers is a service-coupling: src (an API Gateway, ALB, EventBridge rule, S3 event
	// source, SNS/SQS, etc.) can INVOKE/trigger dst (a Lambda, ECS task, …). It closes the gap where
	// the graph modelled the compute's IAM trust (Lambda→role) but not how an attacker reaches the
	// compute in the first place — so "internet → (reach) public API Gateway → (triggers) Lambda →
	// (runs_as) role → (has_access) sensitive data" is now a discoverable chain. Config-possible like
	// every edge: the ingest source emits it only where the integration/event-source is actually wired.
	EdgeTriggers EdgeKind = "triggers"
)

// Edge is a directed relationship from→to of a given kind. Condition records a
// policy condition (IP/MFA/tag) that gates the edge at *runtime* — so the
// snapshot says the edge is *config-possible* but live validation may find it
// blocked (the config-possible ≠ exploitable gap, ADR 0002).
type Edge struct {
	From      string   `json:"from"`
	To        string   `json:"to"`
	Kind      EdgeKind `json:"kind"`
	Condition string   `json:"condition,omitempty"`
	Detail    string   `json:"detail,omitempty"`
}

// Snapshot is the pinned, content-addressed inventory graph.
type Snapshot struct {
	AccountID  string           `json:"account_id"`
	Provider   string           `json:"provider"` // aws | gcp | azure
	CapturedAt time.Time        `json:"captured_at"`
	Nodes      map[string]*Node `json:"nodes"`
	Edges      []Edge           `json:"edges"`

	out map[string][]Edge // out-adjacency, built lazily by index()
}

// New constructs an empty snapshot.
func New(accountID, provider string) *Snapshot {
	return &Snapshot{
		AccountID: accountID,
		Provider:  provider,
		Nodes:     map[string]*Node{},
	}
}

// AddNode inserts or replaces a node and invalidates the adjacency index.
func (s *Snapshot) AddNode(n *Node) {
	if n == nil || n.ID == "" {
		return
	}
	s.Nodes[n.ID] = n
	s.out = nil
}

// AddEdge appends a directed edge and invalidates the adjacency index.
func (s *Snapshot) AddEdge(e Edge) {
	s.Edges = append(s.Edges, e)
	s.out = nil
}

// Node returns the node with id, or nil.
func (s *Snapshot) Node(id string) *Node { return s.Nodes[id] }

// index builds the out-adjacency map once.
func (s *Snapshot) index() {
	if s.out != nil {
		return
	}
	s.out = make(map[string][]Edge, len(s.Nodes))
	for _, e := range s.Edges {
		s.out[e.From] = append(s.out[e.From], e)
	}
}

// edgesFrom returns the out-edges of a node (deterministically ordered).
func (s *Snapshot) edgesFrom(id string) []Edge {
	s.index()
	return s.out[id]
}

// Hash content-addresses the snapshot: sha256 over canonical JSON of the
// sorted nodes + sorted edges. This is the reproducibility base (snapshot_hash,
// §10) — re-pinning the same config produces the same hash.
func (s *Snapshot) Hash() string {
	type canon struct {
		AccountID string  `json:"account_id"`
		Provider  string  `json:"provider"`
		Nodes     []*Node `json:"nodes"`
		Edges     []Edge  `json:"edges"`
	}
	nodes := make([]*Node, 0, len(s.Nodes))
	for _, n := range s.Nodes {
		nodes = append(nodes, n)
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })

	edges := append([]Edge(nil), s.Edges...)
	sort.Slice(edges, func(i, j int) bool {
		a, b := edges[i], edges[j]
		if a.From != b.From {
			return a.From < b.From
		}
		if a.To != b.To {
			return a.To < b.To
		}
		return a.Kind < b.Kind
	})

	b, _ := json.Marshal(canon{s.AccountID, s.Provider, nodes, edges})
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}
