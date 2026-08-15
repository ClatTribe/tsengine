package ctoreadiness

// The practices, staged. Wording follows the widely-circulated AI-native CTO checklist so a customer
// comparing the two sees the same rows; the evidence mapping is ours and is where the honesty lives.
//
// EVERY OBSERVED ROW NAMES THE OSS THAT ANSWERS IT. That is deliberate on two counts. It is the §13
// rule — detection is wrapped community tooling, never an in-house scanner — and it is what makes a
// tick checkable: a customer can run the same tool and get the same answer. The agents reason over
// that output, they do not replace it. An LLM asserting "your dependencies are fine" is worth nothing;
// govulncheck saying so is worth something, and the agent's job starts after that.
//
// Four rows are ATTESTED and three are UNBUILT. Those seven are the reason this list is worth reading:
// a checklist that scored itself 30/30 would tell a CTO nothing they could act on.

func Items() []Item {
	return []Item{
		// ── Application Security ──────────────────────────────────────────────────────────────────
		{
			ID: "appsec.version_control_review", Category: "Application Security", Tier: TierSeed,
			Text: "Use version control with code review on every change", Evidence: EvidenceAttested,
			Why: "We can review pull requests for you and block a merge on high-severity findings, but " +
				"whether every change goes through review is a rule in your repo settings, not something " +
				"a scan can see. Confirm it and we'll record who did.",
		},
		{
			ID: "appsec.dependency_scanning", Category: "Application Security", Tier: TierSeed, Agent: "engineer",
			Text:     "Scan dependencies and container images for known vulnerabilities in CI",
			Evidence: EvidenceObserved, Needs: []string{"repository", "container_image", "github"},
			Tools:    []string{"trivy", "govulncheck", "grype", "osv-scanner"},
			GapRules: []string{"trivy", "grype", "govulncheck", "osv", "sca"},
		},
		{
			ID: "appsec.continuous_pentest", Category: "Application Security", Tier: TierSeriesA, Agent: "pentester",
			Text:     "Continuously test production for real, exploitable vulnerabilities",
			Evidence: EvidenceObserved, Needs: []string{"web_application", "api"},
			Tools:    []string{"nuclei", "sqlmap", "dalfox", "wpscan"},
			GapRules: []string{"nuclei", "sqlmap", "dalfox", "wpscan", "pentest"},
		},
		{
			ID: "appsec.agent_redteam", Category: "Application Security", Tier: TierSeriesB,
			Text:     "Red-team agent workflows for jailbreaks and data exfiltration before launch",
			Evidence: EvidenceUnbuilt,
			Instead: "Testing your own LLM features is real whitespace we have not shipped — garak is the " +
				"OSS to run today, and it is the anchor tool in our design for it.",
		},
		{
			ID: "appsec.remediation_sla", Category: "Application Security", Tier: TierSeriesB,
			Text: "Track remediation SLAs and verify every fix", Evidence: EvidenceCapability,
		},

		// ── Cloud & Infrastructure ────────────────────────────────────────────────────────────────
		{
			ID: "cloud.encryption", Category: "Cloud & Infrastructure", Tier: TierSeed, Agent: "engineer",
			Text: "Encrypt data at rest and in transit by default", Evidence: EvidenceObserved,
			// Cloud only. This row claims BOTH at-rest and in-transit; a connected domain alone
			// establishes neither, and passing it because a hostname exists would be the same
			// false-clean the Needs gate is here to prevent.
			Needs:    []string{"cloud_account", "aws", "gcp", "azure"},
			Tools:    []string{"prowler", "scoutsuite", "testssl.sh"},
			GapRules: []string{"prowler", "tlsscan", "cloudengine::encryption"},
		},
		{
			ID: "cloud.least_privilege", Category: "Cloud & Infrastructure", Tier: TierSeed, Agent: "engineer",
			Text: "Apply least-privilege IAM and offboard promptly", Evidence: EvidenceObserved,
			Needs:    []string{"cloud_account", "aws", "gcp", "azure", "workspace", "okta", "gworkspace", "m365"},
			Tools:    []string{"prowler", "scoutsuite"},
			GapRules: []string{"prowler", "operate::stale", "operate::admin", "operate::offboard", "cloudengine::iam"},
		},
		{
			ID: "cloud.iac_policy", Category: "Cloud & Infrastructure", Tier: TierSeriesA, Agent: "engineer",
			Text:     "Manage infrastructure as code with policy-as-code checks in CI",
			Evidence: EvidenceObserved, Needs: []string{"repository", "github"},
			Tools: []string{"checkov"}, GapRules: []string{"checkov"},
		},
		{
			ID: "cloud.attack_paths", Category: "Cloud & Infrastructure", Tier: TierSeriesB, Agent: "engineer",
			Text:     "Map privilege-escalation and lateral-movement paths across accounts",
			Evidence: EvidenceObserved, Needs: []string{"cloud_account", "aws", "gcp", "azure"},
			Tools: []string{"prowler", "cloudgraph"}, GapRules: []string{"attack-path", "privesc", "lateral"},
		},
		{
			ID: "cloud.drift", Category: "Cloud & Infrastructure", Tier: TierSeriesC, Agent: "engineer",
			Text:     "Detect drift and what changed since yesterday across cloud accounts",
			Evidence: EvidenceObserved, Needs: []string{"cloud_account", "aws", "gcp", "azure"},
			Tools: []string{"prowler", "clouddrift"}, GapRules: []string{"clouddrift", "cloudcdr"},
		},

		// ── Business Logic & Access ───────────────────────────────────────────────────────────────
		{
			ID: "access.sso_mfa", Category: "Business Logic & Access", Tier: TierSeed, Agent: "engineer",
			Text:     "Enforce SSO and phishing-resistant MFA on all critical systems",
			Evidence: EvidenceObserved, Needs: []string{"workspace", "okta", "gworkspace", "m365", "github"},
			Tools:    []string{"operate", "sspm"},
			GapRules: []string{"operate::mfa", "sspm::", "operate::sso"},
		},
		{
			ID: "access.authorize_endpoints", Category: "Business Logic & Access", Tier: TierSeed, Agent: "pentester",
			Text: "Authorize every endpoint; deny by default", Evidence: EvidenceObserved,
			Needs: []string{"api"}, Tools: []string{"apiauthz", "schemathesis"},
			GapRules: []string{"apiauthz", "bfla", "missing-auth"},
		},
		{
			ID: "access.authz_testing", Category: "Business Logic & Access", Tier: TierSeriesA, Agent: "pentester",
			Text: "Test for auth bypass, IDOR, and privilege escalation", Evidence: EvidenceObserved,
			Needs: []string{"web_application", "api"}, Tools: []string{"apiauthz", "nuclei"},
			GapRules: []string{"idor", "bola", "privesc", "auth-bypass", "apiauthz"},
		},
		{
			ID: "access.jit_elevation", Category: "Business Logic & Access", Tier: TierSeriesB,
			Text: "Gate production access behind just-in-time, audited elevation", Evidence: EvidenceAttested,
			Why: "This lives in your access tooling — Teleport, StrongDM, or your cloud's own session " +
				"manager. We gate every change WE propose behind your approval, which is a different " +
				"thing from gating your engineers' access to production.",
		},
		{
			ID: "access.workflow_abuse", Category: "Business Logic & Access", Tier: TierSeriesC,
			Text: "Review multi-step workflow-abuse and business-logic risks", Evidence: EvidenceAttested,
			Why: "We prove the slice a machine can prove: a user escalating their own privileges, and " +
				"reading another user's object. Whether a multi-step workflow can be abused depends on " +
				"what your business rules intend, which no response body reveals.",
		},

		// ── Attack Surface ────────────────────────────────────────────────────────────────────────
		{
			ID: "surface.inventory", Category: "Attack Surface", Tier: TierSeed, Agent: "engineer",
			Text: "Keep a continuous inventory of internet-facing assets", Evidence: EvidenceObserved,
			Needs: []string{"domain", "ip_address"}, Tools: []string{"subfinder", "amass", "naabu"},
			GapRules: []string{"osint::exposed-host"},
		},
		{
			ID: "surface.default_creds", Category: "Attack Surface", Tier: TierSeed, Agent: "pentester",
			Text: "Remove default credentials and unused services", Evidence: EvidenceObserved,
			Needs:    []string{"ip_address", "web_application", "domain"},
			Tools:    []string{"nuclei", "hydra", "naabu"},
			GapRules: []string{"default-login", "default-credential", "hydra"},
		},
		{
			ID: "surface.change_monitoring", Category: "Attack Surface", Tier: TierSeriesA, Agent: "engineer",
			Text:     "Monitor domains, endpoints, and exposed services for changes",
			Evidence: EvidenceObserved, Needs: []string{"domain"},
			Tools:    []string{"crt.sh", "subfinder", "naabu"},
			GapRules: []string{"osint::cert", "osint::exposed-host"},
		},
		{
			ID: "surface.shadow_it", Category: "Attack Surface", Tier: TierSeriesB, Agent: "engineer",
			Text: "Track shadow IT and forgotten subdomains", Evidence: EvidenceObserved,
			Needs:    []string{"domain", "workspace", "okta", "gworkspace", "m365"},
			Tools:    []string{"subfinder", "crt.sh", "dnstwist"},
			GapRules: []string{"osint::subdomain-takeover", "osint::typosquat", "shadowit"},
		},
		{
			ID: "surface.perimeter_map", Category: "Attack Surface", Tier: TierSeriesC, Agent: "engineer",
			Text: "Continuously map the external perimeter", Evidence: EvidenceObserved,
			Needs:    []string{"domain", "ip_address"},
			Tools:    []string{"subfinder", "amass", "naabu", "httpx"},
			GapRules: []string{"osint::"},
		},

		// ── Sensitive Data & Secrets ──────────────────────────────────────────────────────────────
		{
			ID: "data.secrets_out_of_vcs", Category: "Sensitive Data & Secrets", Tier: TierSeed, Agent: "engineer",
			Text:     "Keep secrets out of source control; use a secrets manager",
			Evidence: EvidenceObserved, Needs: []string{"repository", "github"},
			Tools:    []string{"gitleaks", "trufflehog"},
			GapRules: []string{"gitleaks", "trufflehog", "secret"},
		},
		{
			ID: "data.pii_inventory", Category: "Sensitive Data & Secrets", Tier: TierSeed, Agent: "engineer",
			Text: "Classify and inventory where PII lives", Evidence: EvidenceObserved,
			Needs: []string{"cloud_account", "aws", "gcp", "azure", "repository"},
			Tools: []string{"prowler", "dataclass"}, GapRules: []string{"dspm", "dataclass"},
		},
		{
			ID: "data.secret_pii_scanning", Category: "Sensitive Data & Secrets", Tier: TierSeriesA, Agent: "engineer",
			Text:     "Scan code, cloud storage, and pipelines for secrets and PII",
			Evidence: EvidenceObserved, Needs: []string{"repository", "cloud_account", "github", "aws"},
			Tools:    []string{"gitleaks", "trufflehog", "prowler"},
			GapRules: []string{"gitleaks", "trufflehog", "dspm", "secret"},
		},
		{
			ID: "data.leaked_credentials", Category: "Sensitive Data & Secrets", Tier: TierSeriesB, Agent: "engineer",
			Text: "Validate leaked credentials and rotate on exposure", Evidence: EvidenceObserved,
			Needs: []string{"domain", "workspace"}, Tools: []string{"theHarvester", "dnstwist"},
			GapRules: []string{"osint::stealer-log", "osint::breached-credential", "osint::leaked-secret"},
		},
		{
			ID: "data.ai_retention_policy", Category: "Sensitive Data & Secrets", Tier: TierSeriesB,
			Text:     "Set a data-retention and PII policy for AI model inputs and outputs",
			Evidence: EvidenceAttested,
			Why: "We inventory which AI tools reach your code and map you against ISO 42001 and the NIST " +
				"AI RMF, but the retention policy itself is a document you own and publish.",
		},

		// ── Monitoring & Response ─────────────────────────────────────────────────────────────────
		{
			ID: "monitor.log_centralization", Category: "Monitoring & Response", Tier: TierSeed,
			Text:     "Centralize security-relevant logs with alerting on high-risk events",
			Evidence: EvidenceUnbuilt,
			Instead: "We are not a SIEM. Send your logs somewhere that is — OpenSearch and Wazuh are the " +
				"OSS answers, Datadog or Splunk the commercial ones.",
		},
		{
			ID: "monitor.disclosure_policy", Category: "Monitoring & Response", Tier: TierSeed, Agent: "engineer",
			Text:     "Publish a vulnerability disclosure policy and a security contact",
			Evidence: EvidenceObserved, Needs: []string{"domain", "web_application"},
			Tools: []string{"security.txt"}, GapRules: []string{"security-txt", "missing-security-txt"},
		},
		{
			ID: "monitor.telemetry_triage", Category: "Monitoring & Response", Tier: TierSeriesA,
			Text:     "Ingest telemetry (Datadog, Splunk, Wiz) and triage every alert",
			Evidence: EvidenceUnbuilt,
			Instead: "We triage what our own scanners and your posture feeds produce. Pulling alerts out " +
				"of Datadog, Splunk or Wiz and triaging those is not built.",
		},
		{
			ID: "monitor.zeroday_watch", Category: "Monitoring & Response", Tier: TierSeriesB,
			Text:     "Monitor 0-day disclosures affecting your stack with a named owner and SLA",
			Evidence: EvidenceCapability,
		},
		{
			ID: "monitor.compliance_program", Category: "Monitoring & Response", Tier: TierSeriesC,
			Text:     "Achieve SOC 2 / ISO 27001 and report security to the board",
			Evidence: EvidenceCapability,
		},
	}
}
