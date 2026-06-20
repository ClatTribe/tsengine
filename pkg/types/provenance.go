package types

// CodeProvenance links a runtime cloud finding back to the Infrastructure-as-Code
// resource that provisioned it — the "Cloud-to-Code" capability (trace an S3
// public-access misconfig prowler found in the live account to the exact
// `aws_s3_bucket` block + file:line in Terraform that created it).
//
// Grounding (CLAUDE.md §10): every field is a real token read from the source
// tree. The correlation is conservative — a provenance is attached ONLY when a
// concrete identifier from the cloud finding (physical name, ARN tail, or
// normalized logical name) literally appears in an IaC resource whose type
// provisions the cloud finding's service. No matched token, or no type nexus →
// no provenance (never a guessed link). So a developer can trust that the
// cited file:line is where the fix belongs.
type CodeProvenance struct {
	// File is the IaC source file, repo-relative (e.g. "infra/s3.tf").
	File string `json:"file"`
	// Line is the 1-based line of the resource block header.
	Line int `json:"line"`
	// IaCResource is the addressable IaC resource (e.g. "aws_s3_bucket.assets").
	IaCResource string `json:"iac_resource"`
	// MatchedOn is the literal token that tied the cloud finding to this
	// resource (e.g. the bucket name "acme-prod-assets"). The evidence.
	MatchedOn string `json:"matched_on"`
	// MatchBasis is a human-readable explanation of why this is the source
	// (e.g. "physical name matched the `bucket` attribute").
	MatchBasis string `json:"match_basis"`
	// Confidence is "high" (exact physical-name / ARN-tail match) or "medium"
	// (normalized logical-name match — the developer named the block after the
	// resource but the physical name is computed, so it's a strong-but-inferred
	// link).
	Confidence string `json:"confidence"`
}
