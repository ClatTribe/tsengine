package remediate

import (
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// The live cloud-STORAGE remediation_types. Each writes to a single resource (a bucket / storage
// account) whose name lives in a GLOBAL namespace, so a broadly-scoped write credential could reach a
// resource outside the tenant — the deliver gate (Deliverer.verifyCloudTargetGrounded) re-binds these
// to the cited finding's endpoint before the write.
const (
	rtypeS3Block    = "s3_block_public_access"
	rtypeGCSPrevent = "gcs_public_access_prevention"
	rtypeAzureBlock = "azure_storage_disable_public_access"
)

// cloudStorageRemediations is the set of those remediation_types (target == the finding's endpoint).
var cloudStorageRemediations = map[string]bool{rtypeS3Block: true, rtypeGCSPrevent: true, rtypeAzureBlock: true}

// rtypeIAMRestrict labels a cloud IAM over-privilege / privesc finding with its RIGHT-LAYER fix —
// tighten the offending principal's policy — so the action names the correct cut instead of a generic
// "remediate the account". Deliberately NOT in cloudStorageRemediations: there's no live connector
// write for IAM yet, so it stays a documented (HITL-gated) action until an IAM-write path lands, exactly
// like identity's oauth_revoke. Grounded: the target is the finding's own principal/policy.
const rtypeIAMRestrict = "iam_restrict"

// isIAMPrivescFinding reports whether a cloud finding is an IAM over-privilege / privilege-escalation
// issue — the class whose right-layer fix is tightening a principal's policy, not a storage toggle.
func isIAMPrivescFinding(f types.Finding) bool {
	hay := strings.ToLower(f.RuleID + " " + f.Title + " " + f.Description)
	if !strings.Contains(hay, "iam") && !strings.Contains(hay, "role") && !strings.Contains(hay, "policy") &&
		!strings.Contains(hay, "principal") && !strings.Contains(hay, "permission") {
		return false
	}
	return strings.Contains(hay, "privesc") || strings.Contains(hay, "privilege escalation") ||
		strings.Contains(hay, "over-privileg") || strings.Contains(hay, "overprivileg") ||
		strings.Contains(hay, "escalat") || strings.Contains(hay, "administratoraccess") ||
		strings.Contains(hay, "*:*") || strings.Contains(hay, "wildcard")
}

// liveCloudMutation returns the live, reversible cloud remediation (remediation_type + the
// resource-level target) for a finding when a connector write path exists — today only AWS S3
// public-access block, the fix for a publicly-exposed bucket (DSPM/CSPM). Empty rtype → no live
// write path, so the generic cloud action (account-scoped runbook) is used instead. Mirrors
// liveIdentityMutation; promotion to a new (finding-class, provider) is one entry here once its
// connector.Apply lands. Grounded: the target is the finding's own resource, never guessed.
func liveCloudMutation(f types.Finding, provider string) (rtype, target string) {
	if f.Endpoint == "" {
		return "", ""
	}
	switch {
	// Empty provider is treated as AWS (the original single cloud connector).
	case provider == "" || strings.EqualFold(provider, "aws"):
		if isPublicStorageFinding(f) {
			return rtypeS3Block, f.Endpoint
		}
	case strings.EqualFold(provider, "gcp"):
		if isPublicStorageFinding(f) {
			return rtypeGCSPrevent, f.Endpoint
		}
	case strings.EqualFold(provider, "azure"):
		if isPublicStorageFinding(f) {
			return rtypeAzureBlock, f.Endpoint
		}
	}
	return "", ""
}

// isPublicStorageFinding reports whether a finding is a publicly-exposed object-storage bucket — the
// class with a live remediation (S3 Block Public Access / GCS Public Access Prevention). Matches on
// the finding's own text — public + a storage-bucket keyword.
func isPublicStorageFinding(f types.Finding) bool {
	hay := strings.ToLower(f.RuleID + " " + f.Title + " " + f.Description + " " + f.Endpoint)
	return strings.Contains(hay, "public") &&
		(strings.Contains(hay, "s3") || strings.Contains(hay, "bucket") || strings.Contains(hay, "gcs") || strings.Contains(hay, "storage"))
}
