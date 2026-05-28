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
}

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
