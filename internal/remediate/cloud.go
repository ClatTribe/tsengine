package remediate

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/platform"
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
		if sg := openSecurityGroupID(f); sg != "" {
			return rtypeSGRevoke, sg
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

// rtypeKeyRevoke labels the CROSS-SURFACE fix for a leaked cloud access key — the wedge's classic entry
// point: a key committed to a repo. Removing it from code is NOT sufficient (the key is compromised the
// moment it lands in git); the right fix is REVOKING it in the cloud. The repo PR scrubs the code; this
// remediation_type + the key id name the revoke so a future cloud-containment connector can promote it to
// a live IAM mutation (today gated, like rtypeIAMRestrict). This is "fixes it across all three" for the
// finding that bridges code → cloud root.
const rtypeKeyRevoke = "aws_key_revoke"

// rtypeKeyDeactivate is the LIVE half of rtypeKeyRevoke: a tier-2, HITL-gated action against the
// tenant's AWS connection that sets the leaked key Inactive through connector.AWS.Apply.
const rtypeKeyDeactivate = "aws_key_deactivate"

// IsLeakedAWSKey reports whether a finding is a leaked AWS access key (exported for the runner,
// which proposes the gated deactivation beside the repository PR).
func IsLeakedAWSKey(f types.Finding) bool { return isLeakedAWSKeyFinding(f) }

// KeyDeactivateAction is the second action a leaked-key finding earns: the repository PR (tier 1,
// scrub the file) says the key must be revoked; this one DOES it, in the cloud, after a human
// approves. It is separate from the PR because the two have different consequences and different
// gates — a PR is reversible by not merging it, a deactivated key stops a workload the moment it is
// applied — and because they are delivered through different connections (GitHub, AWS).
//
// Grounded (§10): only a key id the finding itself carries (the AKIA/ASIA token in its text) is
// targeted; a leaked-key finding that names no id gets no action here, because deactivating a key
// the finding did not name would be a guess with a blast radius.
func KeyDeactivateAction(f types.Finding, aws platform.Connection, idgen func() string) (platform.Action, bool) {
	kid := awsKeyID(f)
	if kid == "" || aws.Kind != platform.ConnAWS {
		return platform.Action{}, false
	}
	return platform.Action{
		ID: id("act", idgen), TenantID: aws.TenantID, FindingID: f.ID, ConnectionID: aws.ID,
		Kind: platform.ActApplyConfig, Tier: tierApplyConfig, Status: platform.ActProposed,
		Title: "tsengine: deactivate leaked AWS access key " + kid,
		Payload: map[string]any{
			"remediation_type": rtypeKeyDeactivate,
			"target":           kid,
			"remediation": "Access key " + kid + " appears in " + nz(f.Endpoint, "the repository") + " and must be treated as compromised. " +
				"Approving this sets the key INACTIVE in IAM (reversible — re-activate it if something undocumented still depends on it, " +
				"then rotate); it does not delete the key. Scrubbing the file is a separate pull request and does not by itself close this finding.",
			"owner": "",
		},
	}, true
}

// akiaRe matches an AWS access key id (AKIA/ASIA + 16 base32 chars) — the grounded extractor.
var akiaRe = regexp.MustCompile(`(?:AKIA|ASIA)[A-Z0-9]{16}`)

// isLeakedAWSKeyFinding reports whether a finding is a leaked AWS access key (a secret scanner's AWS-key
// rule, or any finding whose evidence carries an AKIA/ASIA key id). Grounded: matches the finding's own
// text, never a guess.
func isLeakedAWSKeyFinding(f types.Finding) bool {
	hay := f.RuleID + " " + f.Title + " " + f.Description + " " + f.Endpoint
	if akiaRe.MatchString(hay) {
		return true
	}
	low := strings.ToLower(hay)
	return strings.Contains(low, "aws") &&
		(strings.Contains(low, "access key") || strings.Contains(low, "access-key") ||
			strings.Contains(low, "access-token") || strings.Contains(low, "access token") ||
			strings.Contains(low, "secret key") || strings.Contains(low, "secret access"))
}

// awsKeyID extracts the leaked access key id (AKIA/ASIA…) from the finding, or "" if none is present
// (secret scanners often redact the value — then the revoke names the key generically, never invented).
func awsKeyID(f types.Finding) string {
	return akiaRe.FindString(f.RuleID + " " + f.Title + " " + f.Description + " " + f.Endpoint)
}

// keyRevokeBody is the PR/runbook body for a leaked key: lead with the revoke (the code scrub is secondary).
func keyRevokeBody(f types.Finding) string {
	kid := awsKeyID(f)
	named := kid
	if named == "" {
		named = "the leaked key"
	}
	placeholder := kid
	if placeholder == "" {
		placeholder = "<ACCESS_KEY_ID>"
	}
	return fmt.Sprintf(`CRITICAL — leaked AWS access key (%s). This key is compromised the moment it hit the repo; removing it from code is NOT enough. Revoke it in the cloud first:
  1. aws iam update-access-key --access-key-id %s --status Inactive
  2. confirm nothing breaks, then: aws iam delete-access-key --access-key-id %s
  3. rotate any credential that depended on it
Then this PR scrubs the secret from the codebase.`, named, placeholder, placeholder)
}

// rtypeSGRevoke is the LIVE half of the open-security-group runbook (rtypeSGRestrict): a tier-2,
// HITL-gated action against the tenant's AWS connection that removes the 0.0.0.0/0 and ::/0 source
// ranges from the group's ingress rules through connector.AWS.Apply. A DISTINCT remediation_type
// from the runbook so cloudRunbookRemediations (which routes runbooks to a ticket) is untouched and
// the two cannot be confused: the runbook remains the answer for GCP/Azure and for an AWS finding
// that names no group.
const rtypeSGRevoke = "sg_revoke_open_ingress"

// sgIDRe matches a security group id in a finding's text — the grounded extractor.
var sgIDRe = regexp.MustCompile(`\bsg-[0-9a-f]{8,17}\b`)

// sgPortRe pulls the port a finding names ("port 22", "tcp_port_3389", "port: 5432").
var sgPortRe = regexp.MustCompile(`(?i)(?:port[_:\s]+)(\d{1,5})\b`)

// openSecurityGroupID returns the security group id when the finding is an open-to-the-internet
// ingress rule on a group it NAMES — the two facts a revoke needs. Grounded (§10): the class match is
// the catalog's own (an SG keyword + a world-open keyword), and the id comes from the finding's text;
// a finding that describes an open group without naming it stays a runbook, because revoking rules
// on a group the finding did not name would be a guess with a blast radius.
func openSecurityGroupID(f types.Finding) string {
	hay := strings.ToLower(f.RuleID + " " + f.Title + " " + f.Description + " " + f.Endpoint)
	if !(anyOf(hay, "security group", "security-group", "securitygroup", "sg-", "ingress", "inbound") &&
		anyOf(hay, "0.0.0.0/0", "::/0", "open to", "internet", "any source", "world", "unrestricted", "wide open")) {
		return ""
	}
	return sgIDRe.FindString(f.RuleID + " " + f.Title + " " + f.Description + " " + f.Endpoint)
}

// openSecurityGroupPort returns the port the finding names, or 0 when it names none (then every
// world-open rule on the group is in scope, and the action's text says so).
func openSecurityGroupPort(f types.Finding) int {
	m := sgPortRe.FindStringSubmatch(f.RuleID + " " + f.Title + " " + f.Description + " " + f.Endpoint)
	if len(m) < 2 {
		return 0
	}
	n, _ := strconv.Atoi(m[1])
	if n <= 0 || n > 65535 {
		return 0
	}
	return n
}

// sgRevokePayload completes the payload for a live SG revoke: the port (when named) and a
// remediation text that says exactly what approving does and does not do.
func sgRevokePayload(f types.Finding, group string, payload map[string]any) {
	port := openSecurityGroupPort(f)
	scope := "every ingress rule on " + group + " whose source is 0.0.0.0/0 or ::/0"
	if port > 0 {
		payload["port"] = port
		scope = fmt.Sprintf("the ingress rule(s) on %s covering port %d whose source is 0.0.0.0/0 or ::/0", group, port)
	}
	payload["remediation"] = "Approving this removes " + scope + ". The group is read first and ONLY the world-open " +
		"source ranges are removed — a narrower range sharing the same rule is kept, and no other rule is touched. " +
		"Reversible: re-add the range if a client you expected to reach the service can no longer. If the group has " +
		"nothing world-open when this runs, the apply FAILS rather than reporting a change it did not make.\n\n" + fixBody(f)
}
