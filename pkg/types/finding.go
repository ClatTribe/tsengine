package types

import (
	"encoding/json"
	"time"
)

// Finding is a single vulnerability / hygiene / compliance observation.
// The same shape appears in both Scan.FindingsRaw (pre-L1.5) and
// Scan.FindingsEnriched (post-L1.5) — the difference is which annotation
// fields are populated.
//
// raw_output is preserved verbatim so the security-engineer audience can
// see the OSS tool's native output unchanged. Do not transform.
type Finding struct {
	ID              string            `json:"id"`
	RuleID          string            `json:"rule_id"`
	Tool            string            `json:"tool"`
	Severity        Severity          `json:"severity"`
	CWE             []string          `json:"cwe,omitempty"`
	Endpoint        string            `json:"endpoint,omitempty"`
	Title           string            `json:"title"`
	Description     string            `json:"description,omitempty"`
	RawOutput       json.RawMessage   `json:"raw_output,omitempty"`
	MITRETechniques []string          `json:"mitre_techniques,omitempty"`
	CorpusVersion   string            `json:"corpus_version,omitempty"`
	ToolArgs        map[string]string `json:"tool_args,omitempty"`
	DiscoveredAt    time.Time         `json:"discovered_at"`

	// L1.5 enrichment annotations. Only populated on FindingsEnriched.
	SurfacePriority *SurfacePriority `json:"surface_priority,omitempty"`
	Exploitability  *Exploitability  `json:"exploitability,omitempty"`
	CorroboratedBy  []string         `json:"corroborated_by,omitempty"`
	ThreatIntel     *ThreatIntel     `json:"threat_intel,omitempty"`
	Compliance      *Compliance      `json:"compliance,omitempty"`

	// DiscoveryMethod tracks how this finding was produced. Replay-sourced
	// findings carry the original replay_id.
	DiscoveryMethod *DiscoveryMethod `json:"discovery_method,omitempty"`

	// L2 is the L2 Lead's developer/PM-facing translation, authored entirely
	// as reasoning-as-parameters on create_vulnerability_report (CLAUDE.md
	// §2.7). Only populated on L2-authored reports (Tool == "l2"); nil on raw
	// L1/L1.5 findings. This is the artifact the non-security audience reads
	// (§2.2) — the kill-chain narrative, plain-English explanation, and
	// remediation that L1's raw scanner output never carries.
	L2 *L2Report `json:"l2,omitempty"`
}

// L2Report is the L2 Lead's translation of one or more L1 findings into a
// developer/PM-facing vulnerability report. Every field is authored by the
// model as a tool PARAMETER (reasoning-as-parameters) — the reasoning is the
// report, not a side-channel.
type L2Report struct {
	// EvidenceIDs are the L1 finding ids this report rests on. A report MUST
	// cite at least one (CLAUDE.md §2.2 "L2 cannot translate findings L1
	// didn't surface" + the "never invent" prompt rule) — the agent grounds
	// its narrative in real evidence, never fabricates a vulnerability.
	EvidenceIDs []string `json:"evidence_finding_ids,omitempty"`
	// KillChain is the attack-chain narrative: how an attacker reaches and
	// exploits this, step by step.
	KillChain string `json:"kill_chain,omitempty"`
	// PlainEnglish explains the issue for a non-security reader (the §2.2
	// developer/PM audience).
	PlainEnglish string `json:"plain_english,omitempty"`
	// Remediation is the prioritized fix guidance / patch direction.
	Remediation string `json:"remediation,omitempty"`

	// Verification is the evidence-strength of this report. L2-4 formalizes
	// the ladder (pattern_match → verified) and the ≥2-independent-methods
	// rule for HIGH/CRITICAL. Empty until set by update_finding.
	Verification VerificationState `json:"verification,omitempty"`
	// VerifiedBy lists the independent methods that corroborated this report
	// (e.g. "send_request", "dispatch_l2_probe:sqlmap"). L2-4 enforces ≥2 for
	// HIGH/CRITICAL before Verification may become "verified".
	VerifiedBy []string `json:"verified_by,omitempty"`
}

// VerificationState is the L2 evidence-strength ladder. A freshly emitted
// report is a pattern_match (it rests on a tool's signature match);
// update_finding upgrades it to verified once independent methods confirm it
// (L2-4 discipline).
type VerificationState string

const (
	// VerificationPatternMatch is the default: rests on an L1 tool's
	// signature/pattern match, not yet independently confirmed.
	VerificationPatternMatch VerificationState = "pattern_match"
	// VerificationVerified means independent method(s) confirmed it. For
	// HIGH/CRITICAL this requires ≥2 independent methods (L2-4).
	VerificationVerified VerificationState = "verified"
)

// SurfacePriority is the L1.5 hook annotation indicating how
// reachable/important this finding's surface is (login form > internal
// admin page > robots.txt entry, etc.).
type SurfacePriority struct {
	Score  int    `json:"score"`
	Reason string `json:"reason,omitempty"`
}

// Exploitability is the L1.5 hook annotation indicating how exploitable
// this finding is given the surrounding context (e.g. SQLi behind auth
// vs. unauthenticated).
type Exploitability struct {
	Score  int    `json:"score"`
	Reason string `json:"reason,omitempty"`
}

// DiscoveryMethod tracks the provenance of a finding. ReplayOf is set
// when the finding was produced by the tool-replay API rather than the
// original anchor prepass.
type DiscoveryMethod struct {
	Primary  string `json:"primary,omitempty"`
	ReplayOf string `json:"replay_of,omitempty"`
}
