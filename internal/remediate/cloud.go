package remediate

import (
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

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
			return "s3_block_public_access", f.Endpoint
		}
	case strings.EqualFold(provider, "gcp"):
		if isPublicStorageFinding(f) {
			return "gcs_public_access_prevention", f.Endpoint
		}
	case strings.EqualFold(provider, "azure"):
		if isPublicStorageFinding(f) {
			return "azure_storage_disable_public_access", f.Endpoint
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
