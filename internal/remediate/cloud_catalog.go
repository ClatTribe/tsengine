package remediate

import (
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// Respond breadth — the class-correct cloud remediation catalog.
//
// Before this catalog, a cloud finding with no live storage-write path (§ liveCloudMutation) fell to a
// GENERIC account-scoped runbook ("review before merge") — the whole non-storage majority of CSPM/CIS
// findings (open security groups, unencrypted volumes, public snapshots/DBs, missing MFA, disabled
// logging, root keys, weak password policy). That made Respond narrow: most findings became a vague
// ticket, not a fix.
//
// cloudFixCatalog closes that: for each common cloud-misconfig class it emits a MACHINE-READABLE
// remediation_type + a SPECIFIC, copy-pasteable runbook (the exact CLI/console cut). Same shape as
// rtypeIAMRestrict — named + grounded + promotable: the moment a live connector write for that class
// lands (an EC2 SG-revoke Writer, a KMS enable-encryption Writer, …), that class is upgraded to a real
// HITL-gated mutation with ONE entry, exactly like S3 public-access block. Until then the human gets the
// precise steps instead of "figure it out".
//
// Grounding (§10): every matcher reads ONLY the finding's own text; the target is the finding's own
// resource (its Endpoint), never invented. A finding that matches no class returns ok=false and keeps
// today's generic runbook — so a clean/unknown finding is never mislabeled. §13 holds: this is
// remediation glue over an existing grounded finding, not a new detector.
//
// The new remediation_types (none live-writable yet — the honest gate):
const (
	rtypeSGRestrict       = "sg_restrict_ingress"        // an open 0.0.0.0/0 security-group / firewall ingress rule
	rtypeEnableEncryption = "enable_encryption"          // an unencrypted-at-rest volume / disk / bucket / DB / snapshot
	rtypeDisablePublicRes = "disable_public_access"      // a publicly-reachable compute resource (snapshot / AMI / image / DB instance)
	rtypeEnforceMFA       = "enforce_mfa"                // a principal (root / IAM user) without MFA
	rtypeEnableLogging    = "enable_logging"             // audit logging / CloudTrail / flow logs disabled
	rtypeRemoveRootKey    = "remove_root_access_key"     // a standing root-account access key
	rtypePasswordPolicy   = "strengthen_password_policy" // a weak account password policy
	rtypePublicIPExposure = "restrict_public_exposure"   // a service directly bound to a public IP with no restriction
)

// cloudMatcher is one class in the catalog: a grounded predicate over the finding's own text plus the
// class's remediation_type and a runbook builder that names the exact fix for that resource.
type cloudMatcher struct {
	rtype   string
	match   func(hay string) bool
	runbook func(f types.Finding) string
}

// contains-any helper: true if hay contains any of the needles.
func anyOf(hay string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(hay, n) {
			return true
		}
	}
	return false
}

// resourceOf names the resource a runbook acts on — the finding's endpoint, else a generic placeholder.
func resourceOf(f types.Finding) string {
	if f.Endpoint != "" {
		return f.Endpoint
	}
	return "the affected resource"
}

// cloudCatalog is ordered MOST-SPECIFIC first — the first matching class wins, so e.g. IAM-privesc is
// tested before the broad MFA/logging classes. Storage-public and leaked-key are handled on their own
// live paths (liveCloudMutation / the repo key-revoke) and are deliberately NOT in this catalog.
var cloudCatalog = []cloudMatcher{
	{
		rtype: rtypeIAMRestrict,
		match: func(hay string) bool { return isIAMPrivescHay(hay) },
		runbook: func(f types.Finding) string {
			return "Tighten the offending principal's policy (" + resourceOf(f) + "): remove the wildcard/" +
				"privilege-escalation permission (e.g. iam:PassRole + a compute create, or a \"*\":\"*\" action) and " +
				"replace it with a least-privilege policy scoped to the resources it actually uses.\n" +
				"  aws iam list-attached-role-policies / put-role-policy with the scoped document, then re-run the scan to confirm the privesc edge is gone."
		},
	},
	{
		rtype: rtypeSGRestrict,
		match: func(hay string) bool {
			return anyOf(hay, "security group", "security-group", "sg-", "firewall", "ingress", "inbound", "nsg", "network security group") &&
				anyOf(hay, "0.0.0.0/0", "::/0", "open to", "internet", "any source", "world", "public", "unrestricted", "wide open")
		},
		runbook: func(f types.Finding) string {
			return "Restrict the wide-open ingress rule on " + resourceOf(f) + ": remove the 0.0.0.0/0 (or ::/0) " +
				"source and scope it to the specific CIDR / prefix-list / peered SG that needs it.\n" +
				"  aws ec2 revoke-security-group-ingress --group-id <sg> --protocol tcp --port <port> --cidr 0.0.0.0/0\n" +
				"  then re-add a narrowed rule for the real client range."
		},
	},
	{
		rtype: rtypeEnableEncryption,
		match: func(hay string) bool {
			return anyOf(hay, "unencrypted", "not encrypted", "no encryption", "encryption disabled", "encryption is not", "without encryption", "encryption at rest") &&
				anyOf(hay, "volume", "ebs", "disk", "rds", "database", "bucket", "snapshot", "s3", "storage", "efs", "sqs", "sns", "dynamodb", "kms")
		},
		runbook: func(f types.Finding) string {
			return "Enable encryption at rest on " + resourceOf(f) + " using a CMK.\n" +
				"  EBS/RDS: create an encrypted snapshot/copy with --kms-key-id and replace the resource; new resources: enable default encryption.\n" +
				"  S3: aws s3api put-bucket-encryption with aws:kms. Verify the resource reports SSE/CMK enabled."
		},
	},
	{
		rtype: rtypeDisablePublicRes,
		match: func(hay string) bool {
			return anyOf(hay, "public", "publicly", "internet-exposed", "internet exposed", "exposed to the internet") &&
				anyOf(hay, "snapshot", "ami", "image", "rds", "database", "db instance", "redshift", "elasticsearch", "opensearch", "instance is public", "publicly accessible")
		},
		runbook: func(f types.Finding) string {
			return "Make " + resourceOf(f) + " private: remove the public attribute / grant.\n" +
				"  Snapshot/AMI: aws ec2 modify-snapshot-attribute (or modify-image-attribute) --operation-type remove --group-names all\n" +
				"  RDS/Redshift: modify the instance to PubliclyAccessible=false and place it in a private subnet."
		},
	},
	{
		rtype: rtypeRemoveRootKey,
		match: func(hay string) bool {
			return anyOf(hay, "root") && anyOf(hay, "access key", "access-key", "api key") && !anyOf(hay, "mfa")
		},
		runbook: func(f types.Finding) string {
			return "Delete the root-account access key (" + resourceOf(f) + "). The root user must never have a standing programmatic key.\n" +
				"  Sign in as root → Security credentials → delete the access key. Use scoped IAM roles/users for automation instead."
		},
	},
	{
		rtype: rtypeEnforceMFA,
		match: func(hay string) bool {
			return anyOf(hay, "mfa", "multi-factor", "multifactor", "two-factor", "2fa") &&
				anyOf(hay, "not enabled", "disabled", "missing", "without", "no mfa", "lacks", "not configured", "not registered", "not set")
		},
		runbook: func(f types.Finding) string {
			return "Enforce MFA on " + resourceOf(f) + ".\n" +
				"  Root: enable a virtual/hardware MFA device on the root user.\n" +
				"  IAM users: attach an IAM policy that denies actions unless aws:MultiFactorAuthPresent is true, and register a device."
		},
	},
	{
		rtype: rtypeEnableLogging,
		match: func(hay string) bool {
			return anyOf(hay, "cloudtrail", "audit log", "logging", "flow log", "flow-log", "access log", "trail") &&
				anyOf(hay, "disabled", "not enabled", "no logging", "not configured", "missing", "off", "not logging")
		},
		runbook: func(f types.Finding) string {
			return "Enable audit logging for " + resourceOf(f) + ".\n" +
				"  CloudTrail: create a multi-region trail delivering to a locked S3 bucket + CloudWatch Logs.\n" +
				"  VPC flow logs / S3 access logs / RDS logs: enable and route to your log sink. Confirm events are landing."
		},
	},
	{
		rtype: rtypePasswordPolicy,
		match: func(hay string) bool {
			return anyOf(hay, "password policy", "password requirement", "password complexity", "password length", "password reuse", "password expir") &&
				anyOf(hay, "weak", "does not", "not meet", "insufficient", "missing", "no minimum", "too short", "not enforced")
		},
		runbook: func(f types.Finding) string {
			return "Strengthen the account password policy (" + resourceOf(f) + ").\n" +
				"  aws iam update-account-password-policy --minimum-password-length 14 --require-symbols --require-numbers " +
				"--require-uppercase-characters --require-lowercase-characters --max-password-age 90 --password-reuse-prevention 24"
		},
	},
	{
		rtype: rtypePublicIPExposure,
		match: func(hay string) bool {
			return anyOf(hay, "public ip", "public-ip", "publicly reachable", "directly exposed", "reachable from the internet", "internet reachable", "internet-reachable") &&
				!anyOf(hay, "bucket", "s3", "snapshot", "ami", "rds", "database") // those have their own, more specific classes
		},
		runbook: func(f types.Finding) string {
			return "Remove the direct public exposure of " + resourceOf(f) + ": move it behind a load balancer / bastion / private subnet, " +
				"or restrict its security group to known sources. Public IPs should front only intentionally-public endpoints."
		},
	},
}

// isIAMPrivescHay is the text-only core of isIAMPrivescFinding (so the catalog can reuse it over a
// pre-lowercased haystack without re-concatenating the finding fields).
func isIAMPrivescHay(hay string) bool {
	if !anyOf(hay, "iam", "role", "policy", "principal", "permission") {
		return false
	}
	return anyOf(hay, "privesc", "privilege escalation", "over-privileg", "overprivileg", "escalat",
		"administratoraccess", "*:*", "wildcard")
}

// cloudFixCatalog returns the class-correct remediation_type + a specific runbook for a cloud finding
// that has no live storage-write path. ok=false → no class matched → keep the generic account runbook.
// Grounded: matches the finding's own text only.
func cloudFixCatalog(f types.Finding) (rtype, runbook string, ok bool) {
	hay := strings.ToLower(f.RuleID + " " + f.Title + " " + f.Description + " " + f.Endpoint)
	for _, m := range cloudCatalog {
		if m.match(hay) {
			return m.rtype, m.runbook(f), true
		}
	}
	return "", "", false
}
