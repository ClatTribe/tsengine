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
	st, err := store.OpenFile(path)
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
	mkComp := func() *types.Compliance {
		return &types.Compliance{SOC2: []string{"CC6.1"}, PCI: []string{"6.2.4"}}
	}
	findings := []types.Finding{
		{ID: "f-001", RuleID: "nuclei::sqli-error-based", Tool: "nuclei", Severity: types.SeverityCritical, CWE: []string{"CWE-89"}, Endpoint: "https://api.northwind.io/v2/search?q=", Title: "SQL injection in /v2/search query parameter", Description: "Error-based SQL injection confirmed on the `q` parameter — the database error message is reflected, and a boolean payload changes the result set.", MITRETechniques: []string{"T1190"}, Compliance: mkComp(), Confidence: 0.95, VerificationStatus: "verified", DiscoveredAt: ago(25 * time.Hour)},
		{ID: "f-002", RuleID: "trivy::CVE-2024-3094", Tool: "trivy", Severity: types.SeverityCritical, CWE: []string{"CWE-506"}, Endpoint: "payments-api/go.mod → xz-utils", Title: "Known-exploited backdoor in transitive dependency (xz-utils)", Description: "A KEV-listed supply-chain backdoor is reachable through a transitive dependency. Upgrade past the affected range.", Compliance: mkComp(), Confidence: 0.99, VerificationStatus: "verified", DiscoveredAt: ago(25 * time.Hour)},
		{ID: "f-003", RuleID: "semgrep::jwt-none-alg", Tool: "semgrep", Severity: types.SeverityHigh, CWE: []string{"CWE-347"}, Endpoint: "payments-api/auth/token.go:88", Title: "JWT signature verification accepts 'none' algorithm", Description: "The token verifier does not pin an algorithm, so an attacker can forge a token with `alg: none`.", Confidence: 0.88, VerificationStatus: "corroborated", DiscoveredAt: ago(25 * time.Hour)},
		{ID: "f-004", RuleID: "operate::admin-without-mfa", Tool: "operate", Severity: types.SeverityHigh, Endpoint: "ana@northwind.io", Title: "Workspace admin without MFA enrolled", Description: "A Google Workspace super-admin has no second factor. Compromise of this account is full-tenant takeover.", Compliance: &types.Compliance{SOC2: []string{"CC6.1", "CC6.6"}}, Confidence: 0.9, VerificationStatus: "verified", DiscoveredAt: ago(49 * time.Hour)},
		{ID: "f-005", RuleID: "prowler::s3-public-bucket", Tool: "prowler", Severity: types.SeverityHigh, Endpoint: "arn:aws:s3:::northwind-invoices", Title: "S3 bucket grants public read", Description: "The `northwind-invoices` bucket policy allows `s3:GetObject` to `*`. Invoices may be world-readable.", Compliance: &types.Compliance{SOC2: []string{"CC6.1"}, PCI: []string{"1.2.1"}}, Confidence: 0.92, VerificationStatus: "verified", DiscoveredAt: ago(49 * time.Hour)},
		{ID: "f-006", RuleID: "nuclei::missing-hsts", Tool: "nuclei", Severity: types.SeverityMedium, Endpoint: "https://storefront.northwind.io", Title: "HSTS header not set", Description: "Responses lack `Strict-Transport-Security`, leaving first-load downgrade attacks possible.", Confidence: 0.7, VerificationStatus: "pattern_match", DiscoveredAt: ago(time.Hour)},
		{ID: "f-007", RuleID: "operate::dmarc-missing", Tool: "operate", Severity: types.SeverityMedium, Endpoint: "_dmarc.northwind.io", Title: "Domain has no DMARC policy", Description: "Without a DMARC record, the domain can be spoofed in phishing campaigns.", Compliance: &types.Compliance{SOC2: []string{"CC6.7"}}, Confidence: 0.85, VerificationStatus: "verified", DiscoveredAt: ago(49 * time.Hour)},
		{ID: "f-008", RuleID: "gitleaks::generic-api-key", Tool: "gitleaks", Severity: types.SeverityMedium, Endpoint: "storefront/.env.example:12", Title: "Possible API key committed to source", Description: "A high-entropy string matching an API-key shape was found in tracked source.", Confidence: 0.6, VerificationStatus: "pattern_match", DiscoveredAt: ago(time.Hour)},
		{ID: "f-009", RuleID: "nuclei::tech-detect", Tool: "nuclei", Severity: types.SeverityLow, Endpoint: "https://storefront.northwind.io", Title: "Server version disclosed in headers", Description: "The `Server` header reveals an exact version, aiding targeted exploitation.", Confidence: 0.5, VerificationStatus: "pattern_match", DiscoveredAt: ago(time.Hour)},
		{ID: "f-010", RuleID: "prowler::cloudtrail-not-multiregion", Tool: "prowler", Severity: types.SeverityLow, Endpoint: "aws:cloudtrail", Title: "CloudTrail is not multi-region", Description: "Audit logging is single-region; activity in other regions is not captured.", Compliance: &types.Compliance{SOC2: []string{"CC7.2"}}, Confidence: 0.8, VerificationStatus: "verified", DiscoveredAt: ago(49 * time.Hour)},
	}
	for _, f := range findings {
		must(st.PutFinding(ctx, tid, f))
	}

	// --- actions (pending approvals = the "needs you" CTA) ---
	actions := []platform.Action{
		{ID: "act-001", TenantID: tid, FindingID: "f-002", ConnectionID: "conn-gh", Kind: platform.ActOpenPR, Tier: 2, Status: platform.ActPendingApproval, Title: "Upgrade xz-utils past the backdoored range", Payload: map[string]any{"summary": "Bumps the transitive xz-utils dependency to a patched version and re-locks go.sum. CI passed on the branch.", "target": "payments-api"}, CreatedAt: ago(24 * time.Hour)},
		{ID: "act-002", TenantID: tid, FindingID: "f-005", ConnectionID: "conn-aws", Kind: platform.ActApplyConfig, Tier: 2, Status: platform.ActPendingApproval, Title: "Make northwind-invoices bucket private", Payload: map[string]any{"summary": "Removes the public-read statement from the bucket policy and enables Block Public Access. Reversible.", "target": "arn:aws:s3:::northwind-invoices"}, CreatedAt: ago(23 * time.Hour)},
		{ID: "act-003", TenantID: tid, FindingID: "f-004", Kind: platform.ActFileTicket, Tier: 1, Status: platform.ActApplied, Title: "Enforce MFA for ana@northwind.io", Payload: map[string]any{"summary": "Filed a runbook ticket: enroll the admin in 2-step verification and enforce org-wide.", "target": "ana@northwind.io"}, CreatedAt: ago(48 * time.Hour), DecidedAt: ago(47 * time.Hour)},
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
	}
	for _, c := range controls {
		refs := []string(nil)
		if c.state == "gap" {
			refs = []string{"f-001"}
		}
		must(st.UpsertControlState(ctx, platform.ControlState{TenantID: tid, Framework: c.fw, ControlID: c.id, State: c.state, EvidenceRefs: refs, UpdatedAt: ago(time.Hour)}))
	}

	log.Printf("seeded demo tenant %q → %s (%d findings, %d actions, %d incidents)", tid, path, len(findings), len(actions), len(incidents))
}
