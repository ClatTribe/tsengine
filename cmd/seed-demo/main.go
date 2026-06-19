// Command seed-demo writes a populated demo tenant into a file-backed platform store
// so the frontend renders the full redesign (posture, findings, approvals, compliance,
// incidents, activity) instead of the cold-start onboarding. Dev-only; not committed.
//
//	go run ./cmd/seed-demo /tmp/tsengine-demo.json
package main

import (
	"context"
	"log"
	"os"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/authn"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func main() {
	path := "/tmp/tsengine-demo.json"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	// store.Open routes by extension (.db/.sqlite → SQLite prod store; else snapshot
	// file), so the demo can seed whichever backend the platform will read.
	st, err := store.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	now := time.Now().UTC()
	ago := func(d time.Duration) time.Time { return now.Add(-d) }
	const tid = "ten-1"

	must := func(err error) {
		if err != nil {
			log.Fatal(err)
		}
	}

	must(st.PutTenant(ctx, platform.Tenant{ID: tid, Name: "Northwind Labs", Plan: "growth", CreatedAt: ago(45 * 24 * time.Hour)}))

	// a demo owner account so you can sign in to the seeded workspace with the new
	// email/password auth (login: founder@northwind.io / sentinel123).
	hash, err := authn.HashPassword("sentinel123")
	if err != nil {
		log.Fatal(err)
	}
	must(st.PutUser(ctx, platform.User{
		ID: "usr-demo", TenantID: tid, Email: "founder@northwind.io", Name: "Ada Founder",
		Role: platform.RoleOwner, PasswordHash: hash, CreatedAt: ago(45 * 24 * time.Hour),
	}))

	// --- connections ---
	conns := []platform.Connection{
		{ID: "conn-gh", TenantID: tid, Kind: platform.ConnGitHub, Status: platform.ConnActive, Account: "northwind-labs", SecretRef: "sealed:gh", Scopes: []string{"repo", "read:org"}, CreatedAt: ago(45 * 24 * time.Hour)},
		{ID: "conn-gw", TenantID: tid, Kind: platform.ConnGWorkspace, Status: platform.ConnActive, Account: "northwind.io", SecretRef: "sealed:gw", Scopes: []string{"admin.directory.user.readonly"}, CreatedAt: ago(40 * 24 * time.Hour)},
		{ID: "conn-aws", TenantID: tid, Kind: platform.ConnAWS, Status: platform.ConnActive, Account: "aws:4417-2290-1180", SecretRef: "sealed:aws", CreatedAt: ago(30 * 24 * time.Hour)},
	}
	for _, c := range conns {
		must(st.PutConnection(ctx, c))
	}

	// --- assets ---
	assets := []platform.Asset{
		{ID: "ast-api", TenantID: tid, ConnectionID: "conn-gh", Type: "repository", Target: "github.com/northwind-labs/payments-api", DiscoveredAt: ago(45 * 24 * time.Hour)},
		{ID: "ast-web", TenantID: tid, ConnectionID: "conn-gh", Type: "repository", Target: "github.com/northwind-labs/storefront", DiscoveredAt: ago(45 * 24 * time.Hour)},
		{ID: "ast-ws", TenantID: tid, ConnectionID: "conn-gw", Type: "workspace", Target: "northwind.io", DiscoveredAt: ago(40 * 24 * time.Hour)},
		{ID: "ast-cloud", TenantID: tid, ConnectionID: "conn-aws", Type: "cloud_account", Target: "aws:4417-2290-1180", DiscoveredAt: ago(30 * 24 * time.Hour)},
	}
	for _, a := range assets {
		must(st.PutAsset(ctx, a))
	}

	// --- engagements (scan history) ---
	for i, a := range assets {
		st := st
		must(st.PutEngagement(ctx, platform.Engagement{
			ID: "eng-" + a.ID, TenantID: tid, AssetID: a.ID, Trigger: platform.TriggerSchedule,
			ScanID: "scan-" + a.ID, StartedAt: ago(time.Duration(i+2) * time.Hour), CompletedAt: ago(time.Duration(i+1) * time.Hour),
		}))
	}
	// a couple of manual + push runs for a livelier activity feed
	must(st.PutEngagement(ctx, platform.Engagement{ID: "eng-push-1", TenantID: tid, AssetID: "ast-api", Trigger: platform.TriggerPush, ScanID: "scan-push-1", StartedAt: ago(26 * time.Hour), CompletedAt: ago(25 * time.Hour)}))
	must(st.PutEngagement(ctx, platform.Engagement{ID: "eng-man-1", TenantID: tid, AssetID: "ast-cloud", Trigger: platform.TriggerManual, ScanID: "scan-man-1", StartedAt: ago(50 * time.Hour), CompletedAt: ago(49 * time.Hour)}))

	// --- findings ---
	// mkComp mirrors the real CWE-89 (SQLi) crosswalk so the demo's compliance posture spans
	// the full framework set the live engine emits — not just SOC2/PCI.
	mkComp := func() *types.Compliance {
		return &types.Compliance{
			SOC2: []string{"CC6.1", "CC6.6"}, PCI: []string{"6.2.1", "6.2.4"}, CISv8: []string{"16.11"},
			NISTCSF: []string{"PR.IP-12", "DE.CM-8"}, GDPR: []string{"Art. 32", "Art. 5(1)(f)"},
			NIST80053: []string{"SI-10"}, NIST800171: []string{"3.14.1"}, CCPA: []string{"1798.150"},
			FedRAMP: []string{"SI-10"}, DPDP: []string{"Sec. 8(5)"},
		}
	}
	findings := []types.Finding{
		{ID: "f-001", RuleID: "nuclei::sqli-error-based", Tool: "nuclei", Severity: types.SeverityCritical, CWE: []string{"CWE-89"}, Endpoint: "https://api.northwind.io/v2/search?q=", Title: "SQL injection in /v2/search query parameter", Description: "Error-based SQL injection confirmed on the `q` parameter — the database error message is reflected, and a boolean payload changes the result set.", MITRETechniques: []string{"T1190"}, Compliance: mkComp(), Confidence: 0.95, VerificationStatus: "verified", DiscoveredAt: ago(25 * time.Hour)},
		{ID: "f-002", RuleID: "trivy::CVE-2024-3094", Tool: "trivy", Severity: types.SeverityCritical, CWE: []string{"CWE-506"}, Endpoint: "payments-api/go.mod → xz-utils", Title: "Known-exploited backdoor in transitive dependency (xz-utils)", Description: "A KEV-listed supply-chain backdoor is reachable through a transitive dependency. Upgrade past the affected range.", Compliance: mkComp(), Confidence: 0.99, VerificationStatus: "verified", DiscoveredAt: ago(25 * time.Hour)},
		{ID: "f-003", RuleID: "semgrep::jwt-none-alg", Tool: "semgrep", Severity: types.SeverityHigh, CWE: []string{"CWE-347"}, Endpoint: "payments-api/auth/token.go:88", Title: "JWT signature verification accepts 'none' algorithm", Description: "The token verifier does not pin an algorithm, so an attacker can forge a token with `alg: none`.", Confidence: 0.88, VerificationStatus: "corroborated", DiscoveredAt: ago(25 * time.Hour)},
		{ID: "f-004", RuleID: "operate::admin-without-mfa", Tool: "operate", Severity: types.SeverityHigh, Endpoint: "ana@northwind.io", Title: "Workspace admin without MFA enrolled", Description: "A Google Workspace super-admin has no second factor. Compromise of this account is full-tenant takeover.", Compliance: &types.Compliance{SOC2: []string{"CC6.1", "CC6.6"}, CISv8: []string{"6.5"}, NISTCSF: []string{"PR.AA-01"}, GDPR: []string{"Art. 32"}, NIST80053: []string{"IA-2", "AC-6"}, NIST800171: []string{"3.5.3", "3.1.5"}, CCPA: []string{"1798.150"}, FedRAMP: []string{"IA-2", "AC-6"}, DPDP: []string{"Sec. 8(5)"}}, Confidence: 0.9, VerificationStatus: "verified", DiscoveredAt: ago(49 * time.Hour)},
		{ID: "f-005", RuleID: "prowler::s3-public-bucket", Tool: "prowler", Severity: types.SeverityHigh, Endpoint: "arn:aws:s3:::northwind-invoices", Title: "S3 bucket grants public read", Description: "The `northwind-invoices` bucket policy allows `s3:GetObject` to `*`. Invoices may be world-readable.", Compliance: &types.Compliance{SOC2: []string{"CC6.1", "CC6.6"}, PCI: []string{"1.2.1", "3.4"}, CISv8: []string{"3.3", "13.4"}, NISTCSF: []string{"PR.DS-1", "PR.AC-5"}, GDPR: []string{"Art. 32", "Art. 5(1)(f)"}, ISO27701: []string{"6.11"}, NIST80053: []string{"SC-7", "SC-28"}, NIST800171: []string{"3.13.16", "3.13.1"}, CCPA: []string{"1798.150", "1798.100"}, SOX: []string{"ITGC: Access to Programs & Data"}, FedRAMP: []string{"SC-7", "SC-28"}, DPDP: []string{"Sec. 8(5)"}}, Confidence: 0.92, VerificationStatus: "verified", DiscoveredAt: ago(49 * time.Hour)},
		{ID: "f-006", RuleID: "nuclei::missing-hsts", Tool: "nuclei", Severity: types.SeverityMedium, Endpoint: "https://storefront.northwind.io", Title: "HSTS header not set", Description: "Responses lack `Strict-Transport-Security`, leaving first-load downgrade attacks possible.", Confidence: 0.7, VerificationStatus: "pattern_match", DiscoveredAt: ago(time.Hour)},
		{ID: "f-007", RuleID: "operate::dmarc-missing", Tool: "operate", Severity: types.SeverityMedium, Endpoint: "_dmarc.northwind.io", Title: "Domain has no DMARC policy", Description: "Without a DMARC record, the domain can be spoofed in phishing campaigns.", Compliance: &types.Compliance{SOC2: []string{"CC6.7"}, PCI: []string{"5.4.1"}, CISv8: []string{"9.5"}, GDPR: []string{"Art. 32"}, NIST80053: []string{"SI-8"}, FedRAMP: []string{"SI-8"}, DPDP: []string{"Sec. 8(5)"}}, Confidence: 0.85, VerificationStatus: "verified", DiscoveredAt: ago(49 * time.Hour)},
		{ID: "f-008", RuleID: "gitleaks::generic-api-key", Tool: "gitleaks", Severity: types.SeverityMedium, Endpoint: "storefront/.env.example:12", Title: "Possible API key committed to source", Description: "A high-entropy string matching an API-key shape was found in tracked source.", Confidence: 0.6, VerificationStatus: "pattern_match", DiscoveredAt: ago(time.Hour)},
		{ID: "f-009", RuleID: "nuclei::tech-detect", Tool: "nuclei", Severity: types.SeverityLow, Endpoint: "https://storefront.northwind.io", Title: "Server version disclosed in headers", Description: "The `Server` header reveals an exact version, aiding targeted exploitation.", Confidence: 0.5, VerificationStatus: "pattern_match", DiscoveredAt: ago(time.Hour)},
		{ID: "f-010", RuleID: "prowler::cloudtrail-not-multiregion", Tool: "prowler", Severity: types.SeverityLow, Endpoint: "aws:cloudtrail", Title: "CloudTrail is not multi-region", Description: "Audit logging is single-region; activity in other regions is not captured.", Compliance: &types.Compliance{SOC2: []string{"CC7.2"}, NISTCSF: []string{"DE.CM-1"}, GDPR: []string{"Art. 32"}, NIST80053: []string{"AU-2", "AU-12"}, FedRAMP: []string{"AU-2"}, DPDP: []string{"Sec. 8(5)"}}, Confidence: 0.8, VerificationStatus: "verified", DiscoveredAt: ago(49 * time.Hour)},
	}
	for _, f := range findings {
		must(st.PutFinding(ctx, tid, f))
	}

	// --- actions (pending approvals = the "needs you" CTA) ---
	actions := []platform.Action{
		{ID: "act-001", TenantID: tid, FindingID: "f-002", ConnectionID: "conn-gh", Kind: platform.ActOpenPR, Tier: 2, Status: platform.ActPendingApproval, Title: "Upgrade xz-utils past the backdoored range", Payload: map[string]any{"summary": "Bumps the transitive xz-utils dependency to a patched version and re-locks go.sum. CI passed on the branch.", "target": "payments-api"}, CreatedAt: ago(24 * time.Hour)},
		{ID: "act-002", TenantID: tid, FindingID: "f-005", ConnectionID: "conn-aws", Kind: platform.ActApplyConfig, Tier: 2, Status: platform.ActPendingApproval, Title: "Make northwind-invoices bucket private", Payload: map[string]any{"summary": "Removes the public-read statement from the bucket policy and enables Block Public Access. Reversible.", "target": "arn:aws:s3:::northwind-invoices"}, CreatedAt: ago(23 * time.Hour)},
		{ID: "act-003", TenantID: tid, FindingID: "f-004", Kind: platform.ActFileTicket, Tier: 1, Status: platform.ActApplied, Title: "Enforce MFA for ana@northwind.io", Payload: map[string]any{"summary": "Filed a runbook ticket: enroll the admin in 2-step verification and enforce org-wide.", "target": "ana@northwind.io"}, CreatedAt: ago(48 * time.Hour), DecidedAt: ago(47 * time.Hour)},
		// A-RSP: the critical SQLi incident (inc-001) → a T3 breach-disclosure DRAFT awaiting a human signature.
		{ID: "act-004", TenantID: tid, FindingID: "f-001", Kind: platform.ActDraftNotification, Tier: 3, Status: platform.ActPendingApproval, Title: "Draft breach disclosure: SQL injection in /v2/search", Payload: map[string]any{"incident_id": "inc-001", "rule_id": "nuclei::sqli-error-based", "severity": "critical", "remediation_type": "breach_notification", "draft": "DRAFT — security incident disclosure. Review, edit, and SIGN before sending.\n\nAutomated continuous monitoring detected and confirmed a critical security issue:\n\n  • Issue:    SQL injection in /v2/search\n  • Rule:     nuclei::sqli-error-based\n  • Severity: critical\n  • Evidence: finding f-001\n\nBefore any external communication, a named human MUST confirm scope and affected parties, determine regulatory obligations and deadlines (GDPR 72h / India DPDP / US state breach laws), and edit this draft to match VERIFIED facts — do NOT send unverified claims.\n\nPrepared by the autonomous security agent; it requires a named human signature before it is filed or sent. The agent does not send regulatory or customer communications on its own."}, CreatedAt: ago(24 * time.Hour)},
	}
	for _, a := range actions {
		must(st.PutAction(ctx, a))
	}

	// --- incidents (continuous monitoring) ---
	incidents := []platform.Incident{
		{ID: "inc-001", TenantID: tid, Key: "nuclei::sqli-error-based|https://api.northwind.io/v2/search?q=", RuleID: "nuclei::sqli-error-based", Title: "SQL injection in /v2/search", Severity: "critical", Status: platform.IncidentOpen, FindingID: "f-001", OpenedAt: ago(25 * time.Hour)},
		{ID: "inc-002", TenantID: tid, Key: "prowler::s3-public-bucket|arn:aws:s3:::northwind-invoices", RuleID: "prowler::s3-public-bucket", Title: "S3 bucket grants public read", Severity: "high", Status: platform.IncidentOpen, FindingID: "f-005", OpenedAt: ago(49 * time.Hour)},
		{ID: "inc-003", TenantID: tid, Key: "operate::okta-stale-admin|carlos@northwind.io", RuleID: "operate::okta-stale-admin", Title: "Stale admin account suspended", Severity: "high", Status: platform.IncidentResolved, FindingID: "f-old", OpenedAt: ago(8 * 24 * time.Hour), ResolvedAt: ago(6 * 24 * time.Hour)},
	}
	for _, i := range incidents {
		must(st.PutIncident(ctx, i))
	}

	// --- compliance control state ---
	type cs struct {
		fw, id, state string
	}
	controls := []cs{
		{"soc2", "CC6.1", "gap"}, {"soc2", "CC6.6", "gap"}, {"soc2", "CC6.7", "gap"},
		{"soc2", "CC7.2", "gap"}, {"soc2", "CC1.1", "met"}, {"soc2", "CC2.1", "met"},
		{"soc2", "CC5.2", "met"}, {"soc2", "CC8.1", "met"}, {"soc2", "A1.2", "met"},
		{"iso27001", "A.5.1", "met"}, {"iso27001", "A.8.2", "gap"}, {"iso27001", "A.8.9", "met"},
		{"iso27001", "A.9.4", "gap"}, {"iso27001", "A.12.6", "met"}, {"iso27001", "A.5.15", "met"},
		{"pci", "1.2.1", "gap"}, {"pci", "6.2.4", "gap"}, {"pci", "8.3.1", "met"}, {"pci", "10.2.1", "met"},
		{"hipaa", "164.312(a)(1)", "met"}, {"hipaa", "164.312(b)", "gap"}, {"hipaa", "164.308(a)(5)", "met"},
		{"cis_v8", "16.11", "gap"}, {"cis_v8", "6.5", "gap"}, {"cis_v8", "9.5", "gap"}, {"cis_v8", "5.3", "met"}, {"cis_v8", "3.3", "met"},
		{"nist_csf", "PR.IP-12", "gap"}, {"nist_csf", "PR.AA-01", "gap"}, {"nist_csf", "PR.DS-1", "gap"}, {"nist_csf", "DE.CM-8", "met"}, {"nist_csf", "ID.AM-2", "met"},
		// Privacy + government + financial frameworks (the expanded set, #172/#182/#183) — a
		// realistic met/gap mix so the demo's compliance posture spans the breadth, not just 4.
		{"gdpr", "Art. 32", "gap"}, {"gdpr", "Art. 5(1)(f)", "gap"}, {"gdpr", "Art. 28", "met"}, {"gdpr", "Art. 25", "met"},
		{"iso27701", "6.11", "gap"}, {"iso27701", "6.12", "met"}, {"iso27701", "7.2", "met"},
		{"nist_800_53", "SI-10", "gap"}, {"nist_800_53", "IA-2", "gap"}, {"nist_800_53", "SC-7", "gap"},
		{"nist_800_53", "SC-28", "gap"}, {"nist_800_53", "AC-6", "met"}, {"nist_800_53", "AC-2", "met"},
		{"nist_800_53", "AU-2", "met"}, {"nist_800_53", "CM-6", "met"},
		{"nist_800_171", "3.14.1", "gap"}, {"nist_800_171", "3.5.3", "gap"}, {"nist_800_171", "3.1.5", "met"}, {"nist_800_171", "3.13.1", "met"},
		{"ccpa", "1798.150", "gap"}, {"ccpa", "1798.100", "met"}, {"ccpa", "1798.140", "met"},
		{"sox", "ITGC: Access to Programs & Data", "gap"}, {"sox", "ITGC: Program Changes", "met"}, {"sox", "ITGC: Computer Operations", "met"},
		{"fedramp", "SI-10", "gap"}, {"fedramp", "IA-2", "gap"}, {"fedramp", "SC-7", "met"}, {"fedramp", "AU-2", "met"}, {"fedramp", "CM-6", "met"},
		{"dpdp", "Sec. 8(5)", "gap"}, {"dpdp", "Sec. 8(7)", "met"}, {"dpdp", "Sec. 9", "met"},
	}
	// gapRef picks a plausible evidence finding for a gap so the drill-down isn't every gap
	// citing the same SQLi: access/MFA gaps → the admin-MFA finding; cloud/data → the public
	// S3 bucket; audit → CloudTrail; email-auth → DMARC; everything else → the SQLi.
	gapRef := func(fw, id string) string {
		switch {
		case id == "IA-2" || id == "3.5.3" || fw == "gdpr" && id == "Art. 28":
			return "f-004"
		case id == "SC-7" || id == "SC-28" || id == "1798.150" || id == "3.13.1" || strings.HasPrefix(id, "ITGC: Access"):
			return "f-005"
		case strings.HasPrefix(id, "AU-"):
			return "f-010"
		case id == "SI-8":
			return "f-007"
		default:
			return "f-001"
		}
	}
	for _, c := range controls {
		refs := []string(nil)
		if c.state == "gap" {
			refs = []string{gapRef(c.fw, c.id)}
		}
		must(st.UpsertControlState(ctx, platform.ControlState{TenantID: tid, Framework: c.fw, ControlID: c.id, State: c.state, EvidenceRefs: refs, UpdatedAt: ago(time.Hour)}))
	}

	log.Printf("seeded demo tenant %q → %s (%d findings, %d actions, %d incidents)", tid, path, len(findings), len(actions), len(incidents))
}
