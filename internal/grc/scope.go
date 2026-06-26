package grc

import (
	"fmt"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// scope.go is the BEFORE-analysis layer — the scoping questions a compliance consultant asks first:
// which framework(s) does the customer actually need, and which systems must they connect so we can
// assess them. Without this we'd analyze blind (all 14 frameworks, no idea what's missing) and risk a
// false-compliant read from a half-connected estate. Pairs with the coverage honesty layer (Coverage):
// scope says "here's what you should connect for SOC2"; coverage says "here's how much we've assessed".

// SuggestedFrameworks maps a customer's applicability profile → the frameworks that actually apply, so we
// recommend a real scope instead of dumping all 14. The trust baseline (SOC2/ISO27001/CIS/NIST-CSF) always
// applies; the rest are gated on a real applicability fact (§10 — we don't suggest HIPAA without PHI).
func SuggestedFrameworks(p platform.ComplianceProfile) []string {
	out := []string{FrameworkSOC2, FrameworkISO27001, FrameworkCISv8, FrameworkNISTCSF}
	if p.HandlesPHI {
		out = append(out, FrameworkHIPAA)
	}
	if p.ProcessesCards {
		out = append(out, FrameworkPCI)
	}
	if p.SellsToGov {
		out = append(out, FrameworkFedRAMP, FrameworkNIST80053, FrameworkNIST800171)
	}
	if p.EUDataSubjects {
		out = append(out, FrameworkGDPR, FrameworkISO27701)
	}
	if p.IndiaDataSubject {
		out = append(out, FrameworkDPDP)
	}
	if p.PublicCompany {
		out = append(out, FrameworkSOX)
	}
	return dedupeFrameworks(out)
}

// IntegrationNeed is one recommended system the customer should connect for compliance coverage, and
// whether they have. The "asset integration to the customer before analysis" ask.
type IntegrationNeed struct {
	Category   string `json:"category"`   // identity | cloud | code | saas | email | web_api | endpoint | logging | backup | hr
	Label      string `json:"label"`      // human label
	Connectors string `json:"connectors"` // what satisfies it (e.g. "Google Workspace, Microsoft 365, or Okta")
	Unlocks    string `json:"unlocks"`    // the compliance signal it provides (which controls)
	Connected  bool   `json:"connected"`  // does the tenant have it (always false for an unsupported area)
}

// ReadinessReport is the connect-this-first checklist for a tenant's target frameworks.
type ReadinessReport struct {
	TargetFrameworks []string          `json:"target_frameworks"`
	Integrations     []IntegrationNeed `json:"integrations"` // SUPPORTED, automatable — counted toward coverage
	// ManualAreas are control areas that matter for the target frameworks but tsengine does NOT yet
	// assess automatically (no connector) — endpoint/MDM, centralized logging, backup/DR, HR/training.
	// Surfaced explicitly so the customer never reads "compliant" without them; they require manual
	// evidence + auditor attestation (the no-false-compliant rule applied to asset-type COVERAGE).
	ManualAreas []IntegrationNeed `json:"manual_areas"`
	Connected   int               `json:"connected"`
	Recommended int               `json:"recommended"`
	Note        string            `json:"note"`
}

// ManualControlAreas are the asset types / control domains that every framework needs but tsengine has no
// automated connector for yet. Naming them is the honest answer to "any asset type we should be checking
// and currently are not" — they're out of AUTOMATED scope and require manual attestation (§ no-false-
// compliant): we will never mark them met from a scan.
func ManualControlAreas() []IntegrationNeed {
	return []IntegrationNeed{
		{Category: "endpoint", Label: "Endpoint / device posture (MDM)", Connectors: "Jamf, Kandji, or Intune — not yet automated", Unlocks: "laptop disk encryption, screen-lock, OS patch level (SOC2 CC6.7, CIS 4, HIPAA 164.310)"},
		{Category: "logging", Label: "Centralized logging / monitoring", Connectors: "Datadog, Splunk, CloudWatch — not yet automated", Unlocks: "security-event logging + anomaly monitoring (SOC2 CC7.2, NIST-CSF DE.CM)"},
		{Category: "backup", Label: "Backup & disaster recovery", Connectors: "your backup/DR tooling — not yet automated", Unlocks: "availability + recoverability (SOC2 A1.2, CIS 11)"},
		{Category: "hr", Label: "HR / security training", Connectors: "your HRIS / LMS — not yet automated", Unlocks: "background checks, security-awareness training (SOC2 CC1.4, CC2.2)"},
	}
}

// RecommendedIntegrations is the standard set of systems whose data feeds compliance controls. The set is
// largely framework-independent (every technical framework needs identity + cloud + code posture); the
// per-framework nuance is applicability (SuggestedFrameworks), not which integrations to connect.
func RecommendedIntegrations() []IntegrationNeed {
	return []IntegrationNeed{
		{Category: "identity", Label: "Identity provider", Connectors: "Google Workspace, Microsoft 365, or Okta", Unlocks: "access control, MFA, least-privilege (SOC2 CC6.x, NIST IA-2/AC-x) — applies to every framework"},
		{Category: "cloud", Label: "Cloud account", Connectors: "AWS, GCP, or Azure", Unlocks: "infra config, encryption, network segmentation (CC6.x, SC-7/SC-28, PCI 1.x/3.x, HIPAA 164.312)"},
		{Category: "code", Label: "Source code", Connectors: "GitHub or GitLab", Unlocks: "SAST/SCA, leaked secrets, change management (CC7.1/CC8.1, PCI 6.x)"},
		{Category: "saas", Label: "SaaS apps", Connectors: "GitHub org, Slack, Zoom, Atlassian, Salesforce", Unlocks: "SaaS config + vendor posture (CC9.2, third-party app review)"},
		{Category: "email", Label: "Email / sending domain", Connectors: "your domain", Unlocks: "anti-spoofing SPF/DKIM/DMARC (CIS 9.5, NIST-CSF PR.DS-2)"},
		{Category: "web_api", Label: "Web apps & APIs", Connectors: "your deployed apps and APIs", Unlocks: "appsec / DAST (CC6.1, PCI 6.2.4)"},
	}
}

// ScopeReadiness builds the connect-this-first checklist: which recommended integrations the tenant has
// connected vs is missing, given its target frameworks. `connected` is keyed by category (the API derives
// it from the tenant's connections + monitored assets). Honest note — partial connection ⇒ partial coverage.
func ScopeReadiness(targets []string, connected map[string]bool) ReadinessReport {
	ints := RecommendedIntegrations()
	c := 0
	for i := range ints {
		if connected[ints[i].Category] {
			ints[i].Connected = true
			c++
		}
	}
	manual := ManualControlAreas()
	note := fmt.Sprintf("%d of %d automatable integrations connected. The rest stay unassessed until connected; and %d control areas (endpoint, logging, backup, HR) aren't automated at all — they need manual evidence + auditor attestation. So this is not a certification on its own.", c, len(ints), len(manual))
	if c == len(ints) {
		note = fmt.Sprintf("All %d automatable integrations connected — the assessment sees every control class it supports. But %d areas (endpoint, logging, backup, HR) still require manual attestation, so this is not a certification.", len(ints), len(manual))
	}
	return ReadinessReport{
		TargetFrameworks: targets, Integrations: ints, ManualAreas: manual,
		Connected: c, Recommended: len(ints), Note: note,
	}
}

func dedupeFrameworks(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, f := range in {
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	return out
}
