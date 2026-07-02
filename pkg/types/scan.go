package types

import "time"

// Scan is the top-level vulnerabilities.json shape — the webappsec
// handoff contract (CLAUDE.md §6).
//
// FindingsRaw is the pre-L1.5 view consumed by the security-engineer
// audience. FindingsEnriched is the post-L1.5 view consumed by compliance
// auditors and (when wired) L2. Both ship.
//
// L15AuditLog records every L1.5 hook decision (demotion, dismissal,
// merge) with reason. Webappsec exposes this to the security engineer for
// override.
//
// Attestation is the cryptographic integrity block produced by signing
// the canonical form of this struct. Required for compliance evidence
// bundles.
type Scan struct {
	ScanID           string       `json:"scan_id"`
	Asset            Asset        `json:"asset"`
	StartedAt        time.Time    `json:"started_at"`
	CompletedAt      time.Time    `json:"completed_at"`
	Engine           Engine       `json:"engine"`
	Corpus           Corpus       `json:"corpus"`
	AnchorsFired     []string     `json:"anchors_fired"`
	RegistryFired    []string     `json:"registry_fired,omitempty"`
	// DiscoveredSurface is the deduped, filtered request surface the L1 recon stage found (katana
	// crawl, spec ingest, etc.) — the endpoints the detection tools fanned out over. Persisted so a
	// consumer can SEED the L2 offensive agent from it (web-investigate --scan) instead of running the
	// agent blind. Recon output that was previously computed and thrown away. Empty for single-stage
	// assets (repo/container) that have no crawl surface.
	DiscoveredSurface []string     `json:"discovered_surface,omitempty"`
	FindingsRaw      []Finding    `json:"findings_raw"`
	FindingsEnriched []Finding    `json:"findings_enriched"`
	L15AuditLog      []AuditEntry `json:"l15_audit_log,omitempty"`
	ChildAssets      []ChildAsset `json:"child_assets,omitempty"`
	// AIAssessment is the AI Cloud Security Engineer's "engineer says" lens
	// (attack paths over the inventory snapshot), shipped alongside FindingsRaw
	// ("tools say"). Present for cloud_account when the engineer runs. ADR 0002.
	AIAssessment *AIAssessment `json:"ai_assessment,omitempty"`
	Attestation  *Attestation  `json:"attestation,omitempty"`

	// Partial is true when the scan did not run to completion (e.g. the
	// --timeout deadline fired mid-fan-out). The findings present are what
	// completed before the cutoff — never silently discarded. StopReason
	// records why. The security-engineer audience MUST be able to tell a
	// 0-finding timeout from a clean bill of health.
	Partial    bool   `json:"partial,omitempty"`
	StopReason string `json:"stop_reason,omitempty"`
}

// ChildAsset is an asset discovered DURING a scan that warrants its own
// downstream scan — e.g. a subdomain found by a domain scan becomes a
// web_application (if it serves HTTP) or ip_address target. Emitting these
// as a first-class dashboard artifact (rather than having webappsec
// re-enumerate) is strix's "consume, don't re-derive" lesson (its
// re-enumeration trap). webappsec spawns child scans from this list.
type ChildAsset struct {
	Host      string    `json:"host"`
	AssetType AssetType `json:"asset_type"`
	Scheme    string    `json:"scheme,omitempty"`
	Source    string    `json:"source,omitempty"`
}

// Engine captures the tsengine version and the sandbox container image
// digest used. The digest is load-bearing for reproducibility — re-runs
// MUST use the same image.
type Engine struct {
	Version            string `json:"version"`
	SandboxImageDigest string `json:"sandbox_image_digest"`
}

// AuditEntry is a single L1.5 decision record. Actions: "demote",
// "dismiss", "merge", "promote", "annotate".
type AuditEntry struct {
	FindingID    string   `json:"finding_id"`
	Action       string   `json:"action"`
	FromSeverity Severity `json:"from_severity,omitempty"`
	ToSeverity   Severity `json:"to_severity,omitempty"`
	Rule         string   `json:"rule"`
	Reason       string   `json:"reason,omitempty"`
}

// Attestation binds a scan to its content via a SHA-256 of the canonical
// JSON form, signed with ed25519. See CLAUDE.md §10 and
// internal/dashboard for the canonicalization + signing implementations.
type Attestation struct {
	SHA256    string    `json:"sha256"`
	SignedAt  time.Time `json:"signed_at"`
	Signer    string    `json:"signer"`
	Signature string    `json:"signature"`
}

// SandboxEmittedFinding is the minimal projection of a Finding that
// crosses the sandbox → host boundary via the sidecar pattern (CLAUDE.md
// §12.4). Wire format only; the host re-emits these through the L1.5
// hook chain to produce real Findings.
type SandboxEmittedFinding struct {
	RuleID          string            `json:"rule_id"`
	Tool            string            `json:"tool"`
	Severity        Severity          `json:"severity"`
	CWE             []string          `json:"cwe,omitempty"`
	Endpoint        string            `json:"endpoint,omitempty"`
	Title           string            `json:"title"`
	Description     string            `json:"description,omitempty"`
	RawOutput       []byte            `json:"raw_output,omitempty"`
	MITRETechniques []string          `json:"mitre_techniques,omitempty"`
	ToolArgs        map[string]string `json:"tool_args,omitempty"`
}
