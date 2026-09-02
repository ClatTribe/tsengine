// The public SAMPLE security assessment report (BoFu decision asset). A realistic, fully-anonymized
// example of the VAPT report a customer gets — so a founder evaluating sees exactly what they'd
// receive before connecting anything. Mirrors the real grc.VAPTReport structure (exec summary, scope,
// per-finding severity/CWE/CVSS/status/evidence/remediation, compliance mapping). Static content,
// clearly labelled a sample; no real customer data.

export interface SampleFinding {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low";
  status: string; // "Exploitation-proven" | "Verified" | "Confirmed"
  asset: string;
  cwe: string;
  cvss: number;
  description: string;
  evidence: string;
  remediation: string;
  controls: string[]; // compliance controls affected
}

// Identity MUST match internal/samplereport (the Go generator behind the downloadable report).
// A prospect who reads one company on this page and downloads another has caught us being
// careless on the single asset whose entire argument is that we are not — and the domains are
// RFC 2606 reserved names for the same reason the generator's are: a sample report listing
// exploitable vulnerabilities against a registerable domain is a fabricated assessment of
// whoever owns it. `acme-sample.com`, which this used, is registerable.
// TestPagePreviewMatchesTheGeneratedReport (Go) fails if the two drift.
export const SAMPLE_META = {
  org: "Example Corp (sample)",
  target: "example.com",
  engine: "tsengine (TensorShield)",
  riskRating: "Critical",
  scope: ["Web application", "REST API", "Source repository", "AWS cloud account", "Email domain", "Identity"],
};


export const SAMPLE_FINDINGS: SampleFinding[] = [
  {
    id: "f-001",
    title: "SQL injection in the product search API",
    severity: "critical",
    status: "Exploitation-proven",
    asset: "api · /v1/search?q=",
    cwe: "CWE-89",
    cvss: 9.1,
    description:
      "The q parameter is concatenated into a SQL query without parameterization. An attacker can read or modify any data in the application database.",
    evidence:
      "A benign boolean-differential probe (q=1' AND '1'='1 vs q=1' AND '1'='2) produced a true/false response split, confirming injection without extracting data.",
    remediation: "Use parameterized queries / an ORM binding for the q parameter. A patch is attached as a pull request.",
    controls: ["SOC 2 CC6.1", "SOC 2 CC7.1", "PCI-DSS 6.2.4", "NIST SI-10"],
  },
  {
    id: "f-002",
    title: "Public S3 bucket exposing customer data exports",
    severity: "high",
    status: "Verified",
    asset: "cloud · s3://example-corp-exports",
    cwe: "CWE-284",
    cvss: 7.5,
    description:
      "A bucket holding nightly customer CSV exports has a public-read ACL. Anyone with the URL can download the files.",
    evidence: "Bucket ACL grants READ to AllUsers; an unauthenticated HEAD returned 200 on a sampled object key.",
    remediation: "Enable S3 Block Public Access (all four flags) on the bucket. This change is staged for one-click approval.",
    controls: ["SOC 2 CC6.1", "GDPR Art. 32", "CCPA §1798.150"],
  },
  {
    id: "f-003",
    title: "Reachable remote-code-execution in a bundled dependency (Log4Shell)",
    severity: "critical",
    status: "Confirmed",
    asset: "repository · pom.xml (log4j-core)",
    cwe: "CWE-502",
    cvss: 10.0,
    description:
      "A bundled dependency has a known remote-code-execution CVE, and the vulnerable sink is reachable from your code — not merely present. CISA lists it as actively exploited and ransomware-linked.",
    evidence: "Reachability analysis traced a call path from an HTTP handler to the vulnerable sink; the CVE is on CISA KEV with an EPSS of 0.944.",
    remediation: "Upgrade to the patched version. A pull request is prepared.",
    controls: ["SOC 2 CC7.1", "SOC 2 CC8.1", "PCI-DSS 6.3.3"],
  },
  {
    id: "f-004",
    title: "No MFA on two administrator accounts",
    severity: "medium",
    status: "Verified",
    asset: "identity · 2 workspace admins",
    cwe: "—",
    cvss: 5.0,
    description: "Two accounts with admin privileges do not have multi-factor authentication enrolled.",
    evidence: "Directory API reports mfaEnrolled=false for two users holding admin roles.",
    remediation: "Enforce MFA org-wide and require it for admin roles. A runbook ticket names the two accounts.",
    controls: ["SOC 2 CC6.1", "CIS v8 6.5"],
  },
  {
    id: "f-005",
    title: "Domain has no DMARC enforcement",
    severity: "medium",
    status: "Verified",
    asset: "domain · example.com",
    cwe: "—",
    cvss: 4.3,
    description: "No DMARC record is published, so attackers can spoof email from your domain for phishing.",
    evidence: "No TXT record at _dmarc.example.com.",
    remediation: "Publish v=DMARC1; p=reject after a short p=none monitoring period. Exact record provided.",
    controls: ["SOC 2 CC6.6"],
  },
  {
    id: "f-006",
    title: "Missing security headers on the web app",
    severity: "low",
    status: "Unconfirmed",
    asset: "web · app.example.com",
    cwe: "CWE-693",
    cvss: 3.1,
    description: "Content-Security-Policy and HSTS are not set, weakening defenses against XSS and protocol downgrade.",
    evidence: "Response headers lack Content-Security-Policy and Strict-Transport-Security.",
    remediation: "Add the headers at your edge/proxy. Copy-paste config provided.",
    controls: ["SOC 2 CC6.1"],
  },
];

// DERIVED from SAMPLE_FINDINGS, never hand-maintained.
//
// The hand-written version declared `verified: 6` and the page rendered a stat reading "Verified 6"
// directly above a table in which only FOUR rows say Verified — the other two say
// Exploitation-proven and Confirmed. On the one page whose entire job is to show that every number
// is backed by evidence a reader can check, the headline number did not survive counting the rows.
// A security reviewer is exactly the person who counts the rows.
//
// The severity counts happened to be right, which is how it survived: four of six numbers matched,
// so nothing looked wrong. Deriving them removes the class of defect rather than this instance.
const tally = <T extends string>(vals: T[]) =>
  vals.reduce<Record<string, number>>((acc, v) => ({ ...acc, [v]: (acc[v] ?? 0) + 1 }), {});

const bySeverity = tally(SAMPLE_FINDINGS.map((f) => f.severity));
const byStatus = tally(SAMPLE_FINDINGS.map((f) => f.status));

export const SAMPLE_COUNTS = {
  critical: bySeverity.critical ?? 0,
  high: bySeverity.high ?? 0,
  medium: bySeverity.medium ?? 0,
  low: bySeverity.low ?? 0,
  // The three evidence tiers, reported separately. Collapsing them into one "verified" number is
  // what produced the mismatch, and it also undersold the work: exploitation-proven is a STRONGER
  // claim than verified, so folding it into the same bucket loses the distinction the product
  // exists to make.
  exploitProven: byStatus["Exploitation-proven"] ?? 0,
  verified: byStatus["Verified"] ?? 0,
  confirmed: byStatus["Confirmed"] ?? 0,
  // Unconfirmed is a tier, not an absence. The generated report labels a single-tool pattern
  // match inline and lists it after the confirmed findings of the same severity; a preview that
  // showed only the three strong tiers would promote a lead to a proven result — the exact
  // thing this page exists to demonstrate we do not do.
  unconfirmed: byStatus["Unconfirmed"] ?? 0,
  total: SAMPLE_FINDINGS.length,
};

export const SAMPLE_FRAMEWORKS = [
  { name: "SOC 2", met: 41, total: 48 },
  { name: "PCI-DSS v4.0", met: 28, total: 34 },
  { name: "GDPR", met: 19, total: 22 },
];
