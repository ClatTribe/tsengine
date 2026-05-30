package types

// AIAssessment is the AI Cloud Security Engineer's output — the "engineer says"
// half of the dual-view dashboard, shipped alongside FindingsRaw ("tools say").
// See ADR 0002 + docs/design/ai-cloud-engineer.md §8.1. It is a separate,
// clearly-labelled stream: it never mutates the deterministic FindingsRaw the
// security engineer / compliance auditor reads.
type AIAssessment struct {
	SnapshotHash       string       `json:"snapshot_hash"` // the pinned config+env (§10 reproducibility base)
	Paths              []AttackPath `json:"attack_paths"`
	Downgraded         []string     `json:"downgraded,omitempty"`          // prowler finding ids judged inert (config-bad, not reachable) — the FP-reduction lens
	AuditLog           []string     `json:"audit_log,omitempty"`           // every query + live call touched
	PendingValidations []string     `json:"pending_validations,omitempty"` // rung-5 awaiting human approval
}

// AttackPath is one validated (or hypothesised) chain to real impact.
type AttackPath struct {
	ID           string            `json:"id"`
	Narrative    string            `json:"narrative"` // plain-English chain (non-security view)
	Graph        PathGraph         `json:"path_graph"`
	RealImpact   RealImpact        `json:"real_impact"`
	Verification VerificationState `json:"verification_status"`    // reasoned → corroborated → verified
	RungReached  int               `json:"rung_reached"`           // validation ladder rung (1–5)
	Confidence   float64           `json:"confidence"`             // 0–1
	Evidence     []EvidenceItem    `json:"evidence_bundle"`        // replayable vs snapshot_hash
	Corroborates []string          `json:"corroborates,omitempty"` // prowler finding ids this path chains
	Downgrades   []string          `json:"downgrades,omitempty"`   // prowler "criticals" proven inert
	Remediation  string            `json:"remediation"`            // the cheapest edge to cut + retest
	Affected     []string          `json:"affected_resources"`
	Compliance   *Compliance       `json:"compliance,omitempty"` // controls this path violates (compliance-auditor view, §8)
}

// RealImpact decomposes real_impact = config_possible ∧ live_reachable ∧
// (sensitive_data ∨ meaningful_privilege) (ADR 0002).
type RealImpact struct {
	ConfigPossible  bool    `json:"config_possible"`
	LiveReachable   bool    `json:"live_reachable"`
	DataSensitivity string  `json:"data_sensitivity,omitempty"` // none|low|high
	Privilege       string  `json:"privilege,omitempty"`        // the privilege gained
	Score           float64 `json:"score"`                      // 0–1 composite
}

// PathGraph is the renderable attack-path graph (for tswrap visualisation).
type PathGraph struct {
	Nodes []PathNode `json:"nodes"`
	Edges []PathEdge `json:"edges"`
}

// PathNode is one vertex on the rendered path.
type PathNode struct {
	ID    string `json:"id"`
	Label string `json:"label,omitempty"`
	Kind  string `json:"kind,omitempty"`
}

// PathEdge is one move on the rendered path.
type PathEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"`
}

// EvidenceItem is one query + its observation — the unit of the evidence bundle.
// Replaying the queries against snapshot_hash re-confirms the finding (the
// reproducibility mechanism, §10), and is simultaneously the anti-hallucination
// guard: no claim without a recorded query/observation.
type EvidenceItem struct {
	Query       string `json:"query"`             // what the engineer asked (tool + args)
	Observation string `json:"observation"`       // what it got back
	AtRung      int    `json:"at_rung,omitempty"` // 0 = snapshot reasoning; 2–5 = live validation
}
