// Package samplereport builds the public sample VAPT report — the marketing asset a
// prospect reads before they trust us with an account.
//
// WHY IT IS GENERATED RATHER THAN WRITTEN. Every competitor's sample report is a PDF
// somebody exported once and uploaded, so the reader has to take on faith that it still
// describes what the product emits. Ours is produced by grc.ReportFromFindings — the SAME
// function that renders a paying customer's report — over a fixed set of example findings.
// That makes the claim structural instead of asserted: if the report format changes, this
// changes with it, and a test fails if it ever stops going through that path. A hand-written
// sample would drift from the product silently, and the drift would always flatter us,
// because nobody updates a marketing PDF to add a caveat.
//
// TWO REFUSALS, both structural:
//
//  1. THE SUBJECT IS A RESERVED DOMAIN. Scope is example.com, reserved by RFC 2606
//     precisely so documentation cannot name a real party. A sample report that named a
//     plausible company would be a fabricated security assessment of someone who never
//     consented to one — and unlike a fictional logo on a landing page, a document listing
//     exploitable vulnerabilities against a named domain is damaging if it is mistaken for
//     real. The name carries "(sample)" for the reader; the reserved domain is what makes
//     it impossible to mistake even out of context.
//
//  2. IT SHOWS THE ADMISSIONS, NOT ONLY THE WINS. The dataset deliberately includes an
//     UNCONFIRMED finding, a scope target nothing assessed (Untested) and one whose last
//     scan lost a tool (PartiallyAssessed). A sample built only from proven criticals would
//     misrepresent the product in the flattering direction — which is the exact failure
//     this engine exists to prevent, committed in our own shop window. The honesty layer IS
//     the differentiator; hiding it from the sales asset would sell the wrong product.
//
// The findings are illustrative examples in the product's own shape. They are not a record
// of any assessment, and no claim here is made about any real system.
package samplereport

import (
	"time"

	"github.com/ClatTribe/tsengine/internal/grc"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Name is the report subject. "(sample)" is for the reader; the reserved scope domain below
// is what makes the document structurally unmistakable.
const Name = "Example Corp (sample)"

// Scope targets. RFC 2606 reserves example.com for documentation — see refusal 1 above.
var scope = []string{
	"https://app.example.com",
	"https://api.example.com",
	"github.com/example-corp/payments",
	"example.com",
	"aws:123456789012",
}

// untested is a scope target NOTHING assessed. Present on purpose: a report that silently
// omitted it would let zero findings across unscanned scope read as a clean result, which is
// the single most damaging thing a document like this can do.
var untested = []string{"aws:123456789012"}

// partiallyAssessed was scanned, but its most recent scan lost a tool. Distinct from
// untested — it WAS looked at, so it is not unassessed, but it has not earned "clean" either.
var partiallyAssessed = []string{"github.com/example-corp/payments"}

// Findings returns the example finding set, in the product's own types.
//
// SIX FINDINGS ACROSS SIX SURFACES, deliberately — api, code, cloud, identity, domain, web.
// The product is sold on finding the path that crosses them, so a sample confined to one
// surface would be a worked example of a different, smaller product. The set mirrors the
// preview rendered on /sample-report, and a guard test fails if the two drift apart: a
// prospect who sees one company in the page and another in the download has caught us being
// careless on the one asset whose entire argument is that we are not.
//
// `now` anchors the timestamps so the caller controls freshness (and so the output is
// deterministic in tests — nothing here reads the clock).
func Findings(now time.Time) []types.Finding {
	ago := func(d time.Duration) time.Time { return now.Add(-d) }
	return []types.Finding{
		{
			// API. The differentiator: not "a scanner matched a pattern" but "the agent ran the
			// request and the application answered". The PoC marker is the same format the
			// active driver emits, so the report renders it as distinguished evidence.
			ID: "s-001", RuleID: "pentest::sqli-boolean", Tool: "pentest",
			Severity: types.SeverityCritical, CWE: []string{"CWE-89"},
			Endpoint: "https://api.example.com/v1/search?q=",
			Title:    "SQL injection in the product search API — exploitation-proven",
			Description: "The `q` parameter is concatenated into a SQL statement without parameterization. " +
				"Proven by a boolean differential that changes the result set without reading any data " +
				"out of the database.\n\n" +
				"[Exploitation PoC · sql-injection] GET /v1/search?q=1%20AND%201=1 vs q=1%20AND%201=2 → " +
				"result sets differ (boolean injection confirmed) (HTTP 200)",
			MITRETechniques:    []string{"T1190"},
			VerificationStatus: types.VerificationVerified, Confidence: 1,
			Compliance: &types.Compliance{
				SOC2: []string{"CC6.1", "CC7.1"}, PCI: []string{"6.2.4"},
				CISv8: []string{"16.11"}, NISTCSF: []string{"PR.PS-06"},
				GDPR: []string{"Art. 32"}, NIST80053: []string{"SI-10"},
			},
			DiscoveredAt: ago(26 * time.Hour),
		},
		{
			// CODE. The threat-intel tier: why this one is first on Monday, in the authorities'
			// own terms — CISA says it is exploited and automatable, and ransomware crews use it.
			// A severity number alone cannot say any of that.
			ID: "s-002", RuleID: "grype::CVE-2021-44228", Tool: "grype",
			Severity: types.SeverityCritical, CWE: []string{"CWE-502"},
			Endpoint: "github.com/example-corp/payments:pom.xml",
			Title:    "Reachable remote-code-execution in a bundled dependency (Log4Shell)",
			Description: "The service bundles a log4j-core version affected by CVE-2021-44228, and " +
				"reachability analysis traced a call path from an HTTP handler to the vulnerable sink — " +
				"so the dependency is not merely present, it is callable.",
			ToolArgs:           map[string]string{"fixable": "true", "fixed_version": "2.17.1"},
			VerificationStatus: types.VerificationCorroborated, Confidence: 0.94,
			ThreatIntel: &types.ThreatIntel{
				CVSS: 10, CVSSVector: "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
				KEV: &types.KEVStatus{
					Listed: true, Vendor: "Apache", Product: "Log4j2", Ransomware: true,
					DateAdded: time.Date(2021, 12, 10, 0, 0, 0, 0, time.UTC),
					DueDate:   time.Date(2021, 12, 24, 0, 0, 0, 0, time.UTC),
				},
				EPSS:       &types.EPSSScore{Score: 0.944},
				SSVC:       &types.SSVC{Exploitation: "active", Automatable: "yes", TechnicalImpact: "total"},
				WeaponRank: "excellent",
				Exploits:   []string{"exploitdb:EDB-50592", "metasploit:exploit/multi/http/log4shell_header_injection"},
			},
			Compliance: &types.Compliance{
				SOC2: []string{"CC7.1", "CC8.1"}, PCI: []string{"6.3.3"}, CISv8: []string{"7.5"},
				NISTCSF: []string{"ID.RA-01"}, NIST80053: []string{"SI-2", "RA-5"},
			},
			DiscoveredAt: ago(50 * time.Hour),
		},
		{
			// CLOUD.
			ID: "s-003", RuleID: "prowler::s3-bucket-public-read", Tool: "prowler",
			Severity: types.SeverityHigh, CWE: []string{"CWE-284"},
			Endpoint: "arn:aws:s3:::example-corp-exports",
			Title:    "Storage bucket holding customer exports is publicly readable",
			Description: "A bucket holding nightly customer CSV exports grants read to everyone. Anyone " +
				"with the object URL can download the files, with no credential and no log of who did.",
			MITRETechniques:    []string{"T1530"},
			VerificationStatus: types.VerificationVerified, Confidence: 0.96,
			Compliance: &types.Compliance{
				SOC2: []string{"CC6.1", "CC6.6"}, PCI: []string{"1.2.1", "3.4"},
				CISv8: []string{"3.3"}, GDPR: []string{"Art. 32", "Art. 5(1)(f)"},
				CCPA: []string{"1798.150"}, NIST80053: []string{"SC-7", "SC-28"},
			},
			DiscoveredAt: ago(52 * time.Hour),
		},
		{
			// IDENTITY.
			ID: "s-004", RuleID: "operate::admin-without-mfa", Tool: "operate",
			Severity: types.SeverityMedium,
			Endpoint: "admin@example.com",
			Title:    "Two administrator accounts without multi-factor authentication",
			Description: "Two accounts holding administrative roles have no second factor enrolled. " +
				"Compromise of either is full-tenant takeover.",
			VerificationStatus: types.VerificationVerified, Confidence: 0.9,
			Compliance: &types.Compliance{
				SOC2: []string{"CC6.1"}, CISv8: []string{"6.5"}, GDPR: []string{"Art. 32"},
				NIST80053: []string{"IA-2", "AC-6"},
			},
			DiscoveredAt: ago(54 * time.Hour),
		},
		{
			// DOMAIN.
			ID: "s-005", RuleID: "operate::dmarc-missing", Tool: "operate",
			Severity: types.SeverityMedium,
			Endpoint: "_dmarc.example.com",
			Title:    "Domain publishes no DMARC policy",
			Description: "With no DMARC record, mail claiming to come from this domain cannot be " +
				"authenticated, so the domain can be spoofed in phishing against staff and customers.",
			VerificationStatus: types.VerificationVerified, Confidence: 0.85,
			Compliance: &types.Compliance{
				SOC2: []string{"CC6.7"}, PCI: []string{"5.4.1"}, CISv8: []string{"9.5"},
				NIST80053: []string{"SI-8"},
			},
			DiscoveredAt: ago(56 * time.Hour),
		},
		{
			// WEB. Deliberately UNCONFIRMED — the report must show that we distinguish what we
			// proved from what we merely matched. A sample where everything is verified would be
			// advertising a product that does not exist.
			ID: "s-006", RuleID: "nuclei::missing-security-headers", Tool: "nuclei",
			Severity: types.SeverityLow, CWE: []string{"CWE-693"},
			Endpoint: "https://app.example.com",
			Title:    "Security headers not set on the web application",
			Description: "Responses omit Content-Security-Policy and Strict-Transport-Security, " +
				"weakening defence against cross-site scripting and protocol downgrade.",
			VerificationStatus: types.VerificationPatternMatch, Confidence: 0.7,
			Compliance: &types.Compliance{
				SOC2: []string{"CC6.1", "CC6.7"}, PCI: []string{"4.2.1"}, NIST80053: []string{"SC-8"},
			},
			DiscoveredAt: ago(3 * time.Hour),
		},
	}
}

// Report builds the sample using the product's OWN report generator.
//
// Everything the reader sees — ordering, severity roll-up, the exploitation-proven tally, the
// KEV and ransomware counts, the remediation roadmap — is computed by grc, not written here.
// This function only supplies the inputs.
func Report(now time.Time) *grc.VAPTReport {
	f := Findings(now)
	// fixReady marks findings with a prepared remediation, exactly as the tenant path does.
	// The Log4Shell one has an upstream version to move to; the SQL injection needs a code
	// change, so it is honestly not marked ready.
	r := grc.ReportFromFindings(f, scope, Name, now, map[string]bool{"s-002": true, "s-003": true, "s-005": true})
	// The admissions. Set after generation for the same reason the tenant path does it: they
	// are facts about COVERAGE, which the findings themselves cannot carry — a target nothing
	// scanned produces no finding to attach them to, which is precisely why they must be
	// stated separately or vanish.
	r.Untested = untested
	r.PartiallyAssessed = partiallyAssessed
	return r
}
