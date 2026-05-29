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
	FindingsRaw      []Finding    `json:"findings_raw"`
	FindingsEnriched []Finding    `json:"findings_enriched"`
	L15AuditLog      []AuditEntry `json:"l15_audit_log,omitempty"`
	ChildAssets      []ChildAsset `json:"child_assets,omitempty"`
	Attestation      *Attestation `json:"attestation,omitempty"`
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
