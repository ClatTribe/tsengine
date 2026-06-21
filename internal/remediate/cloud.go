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
	// Only AWS has a live cloud write path today (connector.AWS.Apply). An explicit non-AWS
	// provider has none; empty provider is treated as AWS (the only cloud connector wired).
	if provider != "" && !strings.EqualFold(provider, "aws") {
		return "", ""
	}
	if isS3PublicFinding(f) && f.Endpoint != "" {
		return "s3_block_public_access", f.Endpoint
	}
	return "", ""
}

// isS3PublicFinding reports whether a finding is a publicly-exposed S3 bucket (the only class
// with a live AWS remediation today). Matches on the finding's own text — public + S3/bucket.
func isS3PublicFinding(f types.Finding) bool {
	hay := strings.ToLower(f.RuleID + " " + f.Title + " " + f.Description + " " + f.Endpoint)
	return strings.Contains(hay, "public") && (strings.Contains(hay, "s3") || strings.Contains(hay, "bucket"))
}
