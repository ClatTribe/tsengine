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
// class's remediation_type and a runbook builder that names the exact fix for that resource on the
// finding's OWN cloud (aws | gcp | azure).
type cloudMatcher struct {
	rtype   string
	match   func(hay string) bool
	runbook func(f types.Finding, provider string) string
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

// pp picks the provider-specific runbook step so a GCP or Azure finding never gets AWS CLI guidance.
// Empty provider is treated as AWS (the original single-cloud default, matching liveCloudMutation); an
// unrecognized provider also falls back to the AWS phrasing (the most common), which is honest — the
// descriptive "what to do" half of every runbook is provider-agnostic, only this CLI line differs.
func pp(provider, aws, gcp, azure string) string {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "gcp", "google", "gcloud":
		return gcp
	case "azure", "az":
		return azure
	default:
		return aws
	}
}

// cloudCatalog is ordered MOST-SPECIFIC first — the first matching class wins, so e.g. IAM-privesc is
// tested before the broad MFA/logging classes. Storage-public and leaked-key are handled on their own
// live paths (liveCloudMutation / the repo key-revoke) and are deliberately NOT in this catalog.
var cloudCatalog = []cloudMatcher{
	{
		rtype: rtypeIAMRestrict,
		match: func(hay string) bool { return isIAMPrivescHay(hay) },
		runbook: func(f types.Finding, provider string) string {
			return "Tighten the offending principal's policy (" + resourceOf(f) + "): remove the wildcard/" +
				"privilege-escalation permission and replace it with a least-privilege policy scoped to the resources it actually uses, then re-run the scan to confirm the privesc edge is gone.\n" +
				pp(provider,
					"  aws iam list-attached-role-policies / put-role-policy with the scoped document; strip iam:PassRole + compute-create or a \"*\":\"*\" action.",
					"  gcloud projects remove-iam-policy-binding <proj> --member=<principal> --role=<broad-role>, then add a least-privilege custom role; watch for actAs / setIamPolicy.",
					"  az role assignment delete --assignee <principal> --role <broad-role>, then assign a least-privilege built-in/custom role; watch for roleAssignments/write + elevateAccess.")
		},
	},
	{
		rtype: rtypeSGRestrict,
		match: func(hay string) bool {
			return anyOf(hay, "security group", "security-group", "sg-", "firewall", "ingress", "inbound", "nsg", "network security group") &&
				anyOf(hay, "0.0.0.0/0", "::/0", "open to", "internet", "any source", "world", "public", "unrestricted", "wide open")
		},
		runbook: func(f types.Finding, provider string) string {
			return "Restrict the wide-open ingress rule on " + resourceOf(f) + ": remove the 0.0.0.0/0 (or ::/0) " +
				"source and scope it to the specific CIDR / prefix-list / peered network that needs it, then re-add a narrowed rule for the real client range.\n" +
				pp(provider,
					"  aws ec2 revoke-security-group-ingress --group-id <sg> --protocol tcp --port <port> --cidr 0.0.0.0/0",
					"  gcloud compute firewall-rules update <rule> --source-ranges=<narrow-cidr>  (or delete the rule allowing 0.0.0.0/0)",
					"  az network nsg rule update -g <rg> --nsg-name <nsg> -n <rule> --source-address-prefixes <narrow-cidr>")
		},
	},
	{
		rtype: rtypeEnableEncryption,
		match: func(hay string) bool {
			return anyOf(hay, "unencrypted", "not encrypted", "no encryption", "encryption disabled", "encryption is not", "without encryption", "encryption at rest") &&
				anyOf(hay, "volume", "ebs", "disk", "rds", "database", "bucket", "snapshot", "s3", "storage", "efs", "sqs", "sns", "dynamodb", "kms")
		},
		runbook: func(f types.Finding, provider string) string {
			return "Enable encryption at rest on " + resourceOf(f) + " using a customer-managed key (CMK), then verify the resource reports it.\n" +
				pp(provider,
					"  EBS/RDS: create an encrypted snapshot/copy with --kms-key-id and replace the resource; S3: aws s3api put-bucket-encryption with aws:kms; enable account default encryption.",
					"  Disks/Cloud SQL: recreate with a CMEK (Cloud KMS) key; buckets: gcloud storage buckets update gs://<b> --default-encryption-key=<kms-key>.",
					"  Managed disks / storage: set customer-managed keys (az disk-encryption-set / az storage account update --encryption-key-source Microsoft.Keyvault) and enable infrastructure encryption.")
		},
	},
	{
		rtype: rtypeDisablePublicRes,
		match: func(hay string) bool {
			return anyOf(hay, "public", "publicly", "internet-exposed", "internet exposed", "exposed to the internet") &&
				anyOf(hay, "snapshot", "ami", "image", "rds", "database", "db instance", "redshift", "elasticsearch", "opensearch", "instance is public", "publicly accessible")
		},
		runbook: func(f types.Finding, provider string) string {
			return "Make " + resourceOf(f) + " private: remove the public attribute / grant and place it in a private network.\n" +
				pp(provider,
					"  Snapshot/AMI: aws ec2 modify-snapshot-attribute (or modify-image-attribute) --operation-type remove --group-names all; RDS/Redshift: modify to PubliclyAccessible=false in a private subnet.",
					"  Remove allUsers/allAuthenticatedUsers bindings (images/snapshots); Cloud SQL: remove authorized public networks / disable the public IP and use Private Service Connect.",
					"  Disable public network access (az sql server update --enable-public-network false / the resource's publicNetworkAccess=Disabled) and use a private endpoint.")
		},
	},
	{
		rtype: rtypeRemoveRootKey,
		match: func(hay string) bool {
			return anyOf(hay, "root") && anyOf(hay, "access key", "access-key", "api key") && !anyOf(hay, "mfa")
		},
		runbook: func(f types.Finding, provider string) string {
			return "Remove the standing programmatic credential on the most-privileged account (" + resourceOf(f) + "). A break-glass/root-equivalent identity must never hold a long-lived key.\n" +
				pp(provider,
					"  Sign in as root → Security credentials → delete the access key. Use scoped IAM roles/users for automation instead.",
					"  GCP has no root user; the analog is an Owner service account with a long-lived key: gcloud iam service-accounts keys delete <key> --iam-account=<sa>, then use workload identity / short-lived tokens.",
					"  Azure has no root user; the analog is a Global Admin or an over-privileged service principal with a standing secret: remove the app credential (az ad app credential delete) and use managed identities / short-lived tokens.")
		},
	},
	{
		rtype: rtypeEnforceMFA,
		match: func(hay string) bool {
			return anyOf(hay, "mfa", "multi-factor", "multifactor", "two-factor", "2fa") &&
				anyOf(hay, "not enabled", "disabled", "missing", "without", "no mfa", "lacks", "not configured", "not registered", "not set")
		},
		runbook: func(f types.Finding, provider string) string {
			return "Enforce multi-factor authentication on " + resourceOf(f) + ".\n" +
				pp(provider,
					"  Root: enable a virtual/hardware MFA device on the root user. IAM users: attach a policy that denies actions unless aws:MultiFactorAuthPresent is true, and register a device.",
					"  Enforce 2-Step Verification in the Google Admin console for the org unit, and require it via a Cloud Identity policy; enroll the affected accounts.",
					"  Require MFA via an Entra ID Conditional Access policy (or enable security defaults) and register the affected users' methods.")
		},
	},
	{
		rtype: rtypeEnableLogging,
		match: func(hay string) bool {
			return anyOf(hay, "cloudtrail", "audit log", "logging", "flow log", "flow-log", "access log", "trail") &&
				anyOf(hay, "disabled", "not enabled", "no logging", "not configured", "missing", "off", "not logging")
		},
		runbook: func(f types.Finding, provider string) string {
			return "Enable audit logging for " + resourceOf(f) + " and confirm events are landing in your log sink.\n" +
				pp(provider,
					"  CloudTrail: create a multi-region trail delivering to a locked S3 bucket + CloudWatch Logs; enable VPC flow logs / S3 access logs / RDS logs.",
					"  Cloud Audit Logs: enable Data Access logs (Admin Activity is always on) via the IAM audit config; enable VPC Flow Logs on the subnets.",
					"  Enable a diagnostic setting to export the Activity Log + resource logs to a Log Analytics workspace / storage; turn on NSG flow logs.")
		},
	},
	{
		rtype: rtypePasswordPolicy,
		match: func(hay string) bool {
			return anyOf(hay, "password policy", "password requirement", "password complexity", "password length", "password reuse", "password expir") &&
				anyOf(hay, "weak", "does not", "not meet", "insufficient", "missing", "no minimum", "too short", "not enforced")
		},
		runbook: func(f types.Finding, provider string) string {
			return "Strengthen the account password policy (" + resourceOf(f) + "): ≥14 chars, complexity, rotation, and reuse-prevention.\n" +
				pp(provider,
					"  aws iam update-account-password-policy --minimum-password-length 14 --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters --max-password-age 90 --password-reuse-prevention 24",
					"  Set the password policy in the Google Admin console (Security → Password management): min length, strength enforcement, and reuse limits for the org unit.",
					"  Enable Entra password protection (banned-password list + lockout) and require strong passwords via policy; for hybrid, deploy the on-prem agent.")
		},
	},
	{
		rtype: rtypePublicIPExposure,
		match: func(hay string) bool {
			return anyOf(hay, "public ip", "public-ip", "publicly reachable", "directly exposed", "reachable from the internet", "internet reachable", "internet-reachable") &&
				!anyOf(hay, "bucket", "s3", "snapshot", "ami", "rds", "database") // those have their own, more specific classes
		},
		runbook: func(f types.Finding, provider string) string {
			return "Remove the direct public exposure of " + resourceOf(f) + ": move it behind a load balancer / bastion / private subnet, " +
				"or restrict its firewall to known sources. Public IPs should front only intentionally-public endpoints.\n" +
				pp(provider,
					"  Detach the public IP / put the instance in a private subnet behind an ALB or SSM Session Manager (no bastion needed).",
					"  Remove the external IP (gcloud compute instances delete-access-config) and reach it via IAP TCP forwarding or a load balancer.",
					"  Remove the public IP association / set the NIC to private and reach it via Azure Bastion or a load balancer.")
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

// cloudRunbookRemediations is the set of cloud remediation_types that have NO live connector write path
// yet — every class in cloudCatalog (they name the exact fix but can't self-apply). A cloud ActApplyConfig
// carrying one of these is a RUNBOOK: the Deliverer files it as an actionable ticket (the payload holds
// the steps) instead of calling connector.Apply, which would error "no live write path". Derived from
// cloudCatalog so a newly-added class is runbook-routed automatically; when a class gains a live write,
// move it out (add its connector.Apply case + a live remediation_type entry). Distinct from
// cloudStorageRemediations (those DO write live) and from identity types (account_suspend etc., a
// different surface) — so this never mis-catches a live or non-cloud action.
var cloudRunbookRemediations = func() map[string]bool {
	m := make(map[string]bool, len(cloudCatalog))
	for _, c := range cloudCatalog {
		m[c.rtype] = true
	}
	return m
}()

// cloudFixCatalog returns the class-correct remediation_type + a specific, PROVIDER-AWARE runbook for a
// cloud finding that has no live storage-write path. ok=false → no class matched → keep the generic
// account runbook. provider (aws|gcp|azure, from the asset) selects the right CLI so a GCP/Azure finding
// never gets AWS guidance. Grounded: matches the finding's own text only.
func cloudFixCatalog(f types.Finding, provider string) (rtype, runbook string, ok bool) {
	hay := strings.ToLower(f.RuleID + " " + f.Title + " " + f.Description + " " + f.Endpoint)
	for _, m := range cloudCatalog {
		if m.match(hay) {
			return m.rtype, m.runbook(f, provider), true
		}
	}
	return "", "", false
}
