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

export const SAMPLE_META = {
  org: "Acme (sample)",
  target: "acme-sample.com",
  date: "2026-06-18",
  engine: "tsengine 0.4.2",
  riskRating: "High",
  scope: ["Web application", "REST API", "Source repository", "AWS cloud account", "Identity (Google Workspace)"],
};

export const SAMPLE_COUNTS = { critical: 1, high: 2, medium: 2, low: 1, exploitProven: 1, verified: 6 };

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
    asset: "cloud · s3://acme-sample-exports",
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
    title: "Reachable RCE in an outdated dependency",
    severity: "high",
    status: "Verified",
    asset: "repository · requirements.txt (PyYAML 5.1)",
    cwe: "CWE-1104",
    cvss: 8.1,
    description:
      "A bundled dependency has a known remote-code-execution CVE, and the vulnerable function is reachable from your code (not just present).",
    evidence: "Reachability analysis traced a call path from an HTTP handler to the vulnerable yaml.load() sink.",
    remediation: "Upgrade to the patched version and switch to yaml.safe_load(). PR attached.",
    controls: ["SOC 2 CC7.1", "SOC 2 CC8.1"],
  },
  {
    id: "f-004",
    title: "No MFA on two administrator accounts",
    severity: "medium",
    status: "Verified",
    asset: "identity · 2 Google Workspace admins",
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
    asset: "domain · acme-sample.com",
    cwe: "—",
    cvss: 4.3,
    description: "No DMARC record is published, so attackers can spoof email from your domain for phishing.",
    evidence: "No TXT record at _dmarc.acme-sample.com.",
    remediation: "Publish v=DMARC1; p=reject after a short p=none monitoring period. Exact record provided.",
    controls: ["SOC 2 CC6.6"],
  },
  {
    id: "f-006",
    title: "Missing security headers on the web app",
    severity: "low",
    status: "Confirmed",
    asset: "web · acme-sample.com",
    cwe: "CWE-693",
    cvss: 3.1,
    description: "Content-Security-Policy and HSTS are not set, weakening defenses against XSS and protocol downgrade.",
    evidence: "Response headers lack Content-Security-Policy and Strict-Transport-Security.",
    remediation: "Add the headers at your edge/proxy. Copy-paste config provided.",
    controls: ["SOC 2 CC6.1"],
  },
];

export const SAMPLE_FRAMEWORKS = [
  { name: "SOC 2", met: 41, total: 48 },
  { name: "PCI-DSS v4.0", met: 28, total: 34 },
  { name: "GDPR", met: 19, total: 22 },
];
