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
	ID       string   `json:"id"`
	RuleID   string   `json:"rule_id"`
	Tool     string   `json:"tool"`
	Severity Severity `json:"severity"`
	CWE      []string `json:"cwe,omitempty"`
	Endpoint string   `json:"endpoint,omitempty"`
	// AssetID ties this finding to the platform asset it was found on. Set by the platform
	// runner, which knows the asset at the moment it stores each finding; the engine and the
	// CLI never populate it, hence omitempty and a contract that stays byte-compatible.
	//
	// IT EXISTS BECAUSE THE ALTERNATIVE IS A HEURISTIC THAT CANNOT WORK. Three consumers
	// (coverage, per-asset compliance, data-tier prioritisation) each re-derived the link by
	// matching the asset's Target inside this Endpoint. That works for a URL or a host and
	// cannot work for a repository, whose findings are file-relative ("src/app.py:12") while
	// the target is a workspace path that never appears in them — so a scanned repo holding a
	// leaked key attributed to nothing, and the coverage page reported "No findings recorded".
	//
	// Consumers PREFER this and fall back to target matching, because findings stored before
	// this field existed, and those arriving through the ingest paths where no asset is in
	// scope, legitimately carry no id. An empty AssetID means "not recorded", never "no asset".
	AssetID         string            `json:"asset_id,omitempty"`
	Title           string            `json:"title"`
	Description     string            `json:"description,omitempty"`
	RawOutput       json.RawMessage   `json:"raw_output,omitempty"`
	MITRETechniques []string          `json:"mitre_techniques,omitempty"`
	CorpusVersion   string            `json:"corpus_version,omitempty"`
	ToolArgs        map[string]string `json:"tool_args,omitempty"`

	// Rung is HOW this finding was established — exploited | provider_confirmed |
	// reachability_confirmed | corroborated | scanner_reported (ADR 0029 D2d).
	//
	// DERIVED, not authored: Rung() computes it from the fields above and is the authority. It is
	// stamped onto the finding by the L1.5 chain so every consumer — the API, the finding page, the
	// exports — reads one word without each re-deriving it, and so a stored finding carries the same
	// claim the report does.
	//
	// It exists because VerificationStatus could not carry the distinction: "verified" means an
	// exploit RAN when the offensive agent sets it and means the cloud provider AUTHORIZED it when the
	// cloud agent does, and the finding page rendered that single word as a bare tag.
	Rung         EvidenceRung `json:"rung,omitempty"`
	DiscoveredAt time.Time    `json:"discovered_at"`

	// L1.5 enrichment annotations. Only populated on FindingsEnriched.
	SurfacePriority *SurfacePriority `json:"surface_priority,omitempty"`
	Exploitability  *Exploitability  `json:"exploitability,omitempty"`
	CorroboratedBy  []string         `json:"corroborated_by,omitempty"`
	// DerivedFrom are the finding ids a DERIVED finding rests on — one produced by joining other
	// findings rather than by a tool observing something directly (internal/estatedetect's
	// cross-surface detections are the first). §10 requires every recorded issue to cite its
	// evidence, and for a derived finding the evidence IS the findings it was derived from; without
	// this it would be an assertion with nothing behind it.
	//
	// Deliberately NOT CorroboratedBy: that field means "≥2 independent tools saw THIS SAME thing"
	// and feeds the L1.5 confidence score. These are different findings on different surfaces that
	// CHAIN — reusing that field would silently inflate confidence on a claim nobody corroborated.
	DerivedFrom []string     `json:"derived_from,omitempty"`
	ThreatIntel *ThreatIntel `json:"threat_intel,omitempty"`
	Compliance  *Compliance  `json:"compliance,omitempty"`

	// VerificationStatus + Confidence are the L1.5 quality signal (strix
	// parity — its #1 triage signal). They tell the security engineer + L2
	// HOW MUCH to trust a finding. Status ladder: pattern_match (one tool's
	// signature match) → corroborated (≥2 independent tools agree) →
	// verified (re-fired + confirmed; L2.5). Confidence is a 0–1 scalar from
	// per-tool reliability bumped by corroboration. Derived, so populated on
	// FindingsEnriched only (never on the verbatim raw view).
	VerificationStatus VerificationState `json:"verification_status,omitempty"`
	Confidence         float64           `json:"confidence,omitempty"`

	// CodeProvenance ties a runtime cloud finding back to the IaC resource +
	// file:line that provisioned it (the "Cloud-to-Code" capability). Populated
	// only on cloud findings that the IaC correlator confidently linked to a
	// source resource; nil otherwise (no guessed links — §10 grounding).
	CodeProvenance *CodeProvenance `json:"code_provenance,omitempty"`

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
	// VerificationCorroborated means ≥2 INDEPENDENT tools agreed on the same
	// (endpoint, CWE) / CVE — cross-source agreement, set at L1.5 by the
	// corroborator→confidence chain without re-firing anything.
	VerificationCorroborated VerificationState = "corroborated"
	// VerificationVerified means independent method(s) actively confirmed it
	// (re-fire via tool-replay). For HIGH/CRITICAL this requires ≥2
	// independent methods (L2-4 / L2.5).
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
