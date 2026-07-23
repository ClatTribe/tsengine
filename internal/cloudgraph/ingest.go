package cloudgraph

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
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
	AccountID  string            `json:"account_id"`
	Provider   string            `json:"provider"`
	CapturedAt time.Time         `json:"captured_at,omitempty"`
	Resources  []InvResource     `json:"resources,omitempty"`
	Trusts     []InvTrust        `json:"trusts,omitempty"`  // principal → role it may assume
	Passes     []InvPass         `json:"passes,omitempty"`  // principal → role it may pass (iam:PassRole)
	Grants     []InvGrant        `json:"grants,omitempty"`  // principal → resource it may access
	Reaches    []InvReach        `json:"reaches,omitempty"` // network reachability (incl. internet exposure)
	RunsAs     []InvRunsAs       `json:"runs_as,omitempty"`
	Privescs   []InvPrivesc      `json:"privescs,omitempty"` // known IAM privesc edges (PMapper-style)
	Triggers   []InvTrigger      `json:"triggers,omitempty"` // service-coupling: a service can invoke a compute resource
	Secrets    []InvSecretAccess `json:"secrets,omitempty"`  // secret-held-credential reuse (lateral movement)
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
	// Image is the container image a compute workload runs (ECR uri:tag / registry/repo:tag).
	// Set on ECS/EKS/Lambda-image/etc. resources; drives the agentless workload scan
	// (ADR 0009 Phase 2 — cloudengine.WorkloadScanPlan). Carried into Node.Attrs["image"].
	Image string `json:"image,omitempty"`
	// Entitlement carries the CIEM rightsizing inputs for a PRINCIPAL — optional; when present it is
	// carried into the principal Node's Attrs so cloudengine.RightsizePrincipals can flag over-privilege.
	Entitlement *Entitlement `json:"entitlement,omitempty"`
}

// Entitlement is a principal's granted action set plus the actions it actually USED in an observation
// window (the CIEM inputs). The granted side can come from policy ingest; the usage side is the gated
// live half (CloudTrail / IAM last-accessed / Access Analyzer). Observed is the honest gate (§10): true
// only when real usage data is available — absence of usage is never treated as "unused".
type Entitlement struct {
	GrantedActions []string `json:"granted_actions,omitempty"`
	UsedActions    []string `json:"used_actions,omitempty"`
	WindowDays     int      `json:"window_days,omitempty"`
	Observed       bool     `json:"observed,omitempty"`
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
	// Condition gates the escalation at runtime (e.g. iam:CreateAccessKey requires MFA) — the #827
	// config-possible-only flag. Like InvTrust/InvGrant/InvReach/InvTrigger/InvSecretAccess it must
	// round-trip, else ToInventory drops it and a re-ingested path over-claims a conditional escalation
	// as DEFINITE (§10: a config-possible escalation is never reported as confirmed).
	Condition string `json:"condition,omitempty"`
}

// InvTrigger is a service-coupling: Source (an API Gateway, ALB, EventBridge rule, S3 event source,
// SNS/SQS, etc.) can invoke Compute (a Lambda, ECS task). The ingest source emits one only where the
// integration/event-source is actually wired in the account, so the edge is config-grounded.
type InvTrigger struct {
	Source    string `json:"source"`  // the invoking service/resource (often public-reachable)
	Compute   string `json:"compute"` // the compute it invokes
	Condition string `json:"condition,omitempty"`
}

// InvSecretAccess is a credential-reuse toxic combination: Principal can READ Secret (a Secrets Manager
// secret / SSM SecureString / K8s secret / Key Vault secret) whose stored material is a long-lived
// credential for Yields (a more-privileged principal). Compromising Principal → reading the secret →
// authenticating as Yields = lateral movement. The ingest source emits one ONLY where it confirmed both
// that Principal can read the secret AND that the secret holds Yields's credential (grounded, §10 — never
// inferred from a name). Live detection (reading the secret's stored material / tags) is the gated half.
type InvSecretAccess struct {
	Principal string `json:"principal"` // who can read the secret
	Secret    string `json:"secret"`    // the secret resource id (named in the edge Detail)
	Yields    string `json:"yields"`    // the principal whose credential the secret holds
	Condition string `json:"condition,omitempty"`
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

// ToInventory serializes a Snapshot back into a normalized Inventory — the
// reverse of Ingest. Used to export a synthetic/emulated cloud account as the
// operator-facing inventory JSON, so the full pipeline (ingest → engine → LLM)
// can be exercised on it exactly as on a real CloudQuery export. Deterministic
// (nodes sorted by id) for reproducibility.
func (s *Snapshot) ToInventory() Inventory {
	inv := Inventory{AccountID: s.AccountID, Provider: s.Provider, CapturedAt: s.CapturedAt}
	ids := make([]string, 0, len(s.Nodes))
	for id := range s.Nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		n := s.Nodes[id]
		inv.Resources = append(inv.Resources, InvResource{
			ID: n.ID, Kind: n.Kind, Type: n.Type, Name: n.Name, Region: n.Region,
			Public: n.Public, Sensitive: n.Sensitive, Privileged: n.Privileged, Tags: n.Tags,
			Image: n.Attrs["image"], // round-trip the workload image (Phase 2)
		})
	}
	for _, e := range s.Edges {
		switch e.Kind {
		case EdgeAssumeRole:
			inv.Trusts = append(inv.Trusts, InvTrust{Principal: e.From, Role: e.To, Condition: e.Condition})
		case EdgePassRole:
			inv.Passes = append(inv.Passes, InvPass{Principal: e.From, Role: e.To})
		case EdgeHasAccess:
			inv.Grants = append(inv.Grants, InvGrant{Principal: e.From, Resource: e.To, Condition: e.Condition})
		case EdgeNetworkReach:
			inv.Reaches = append(inv.Reaches, InvReach{From: e.From, To: e.To, Condition: e.Condition})
		case EdgeRunsAs:
			inv.RunsAs = append(inv.RunsAs, InvRunsAs{Compute: e.From, Principal: e.To})
		case EdgePrivesc:
			inv.Privescs = append(inv.Privescs, InvPrivesc{Principal: e.From, Target: e.To, Detail: e.Detail, Condition: e.Condition})
		case EdgeTriggers:
			inv.Triggers = append(inv.Triggers, InvTrigger{Source: e.From, Compute: e.To, Condition: e.Condition})
		case EdgeSecretAccess:
			inv.Secrets = append(inv.Secrets, InvSecretAccess{Principal: e.From, Yields: e.To, Secret: strings.TrimPrefix(e.Detail, "via secret "), Condition: e.Condition})
		}
	}
	return inv
}

// Ingest assembles a Snapshot from a normalized Inventory.
func Ingest(inv Inventory) *Snapshot {
	s := New(inv.AccountID, inv.Provider)
	s.CapturedAt = inv.CapturedAt
	for _, r := range inv.Resources {
		n := &Node{
			ID: r.ID, Kind: r.Kind, Type: r.Type, Name: r.Name, Region: r.Region,
			Public: r.Public, Sensitive: r.Sensitive, Privileged: r.Privileged, Tags: r.Tags,
		}
		if r.Image != "" { // the container image a workload runs (agentless scan, Phase 2)
			n.Attrs = map[string]string{"image": r.Image}
		}
		if e := r.Entitlement; e != nil { // CIEM rightsizing inputs → Node.Attrs (read by RightsizePrincipals)
			if n.Attrs == nil {
				n.Attrs = map[string]string{}
			}
			if len(e.GrantedActions) > 0 {
				n.Attrs["granted_actions"] = strings.Join(e.GrantedActions, " ")
			}
			if len(e.UsedActions) > 0 {
				n.Attrs["used_actions"] = strings.Join(e.UsedActions, " ")
			}
			if e.WindowDays > 0 {
				n.Attrs["usage_window_days"] = strconv.Itoa(e.WindowDays)
			}
			if e.Observed {
				n.Attrs["usage_observed"] = "true"
			}
		}
		s.AddNode(n)
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
		s.AddEdge(Edge{From: pe.Principal, To: pe.Target, Kind: EdgePrivesc, Detail: pe.Detail, Condition: pe.Condition})
	}
	for _, tr := range inv.Triggers {
		s.AddEdge(Edge{From: tr.Source, To: tr.Compute, Kind: EdgeTriggers, Condition: tr.Condition})
	}
	for _, sa := range inv.Secrets {
		// the reader can become the principal whose credential the secret holds (lateral movement);
		// the secret itself is named in Detail for the evidence trail.
		s.AddEdge(Edge{From: sa.Principal, To: sa.Yields, Kind: EdgeSecretAccess, Detail: "via secret " + sa.Secret, Condition: sa.Condition})
	}
	return s
}
