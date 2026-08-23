// The asset surfaces TensorShield scans — the buyer-facing "what we cover"
// map. Single-sourced here so the marketing matrix never drifts from the
// engine's real asset coverage (CLAUDE.md §3: the 7-asset focus set + the
// identity/workspace surface served by the platform's operate engine).
//
// mobile_application is deliberately ABSENT. CLAUDE.md §3 descopes it, a user cannot
// add one, and the only mobile scanning that actually runs is mobsfscan firing as a
// REPOSITORY escalation on mobile source files — which this matrix already covers under
// the repository row. Listing it as its own surface promised a scan with no way to start it.
//
// `tools` lists the lead OSS scanners wrapped for that surface (illustrative,
// not exhaustive) — the grounded "best-in-class detection" claim.

export type AssetSurface = {
  key: string;
  label: string;
  scans: string; // what's assessed
  tools: string[]; // lead OSS tools wrapped
};

export const ASSET_SURFACES: AssetSurface[] = [
  { key: "web_application", label: "Web apps", scans: "DAST — injection, XSS, SSRF, auth, and WordPress/CMS-specific issues", tools: ["nuclei", "sqlmap", "dalfox", "wpscan"] },
  { key: "api", label: "APIs", scans: "REST / GraphQL / gRPC — spec-driven fuzzing and shadow-route discovery", tools: ["nuclei", "kiterunner", "schemathesis"] },
  { key: "repository", label: "Source code", scans: "SAST, dependency CVEs (SCA) with reachability, supply-chain malware, end-of-life & deprecated components, license risk, and hardcoded secrets", tools: ["semgrep", "trivy", "govulncheck", "malicious-packages", "eol", "gitleaks"] },
  { key: "container_image", label: "Containers", scans: "Image CVEs, misconfigurations, and SBOM", tools: ["trivy", "grype", "dockle"] },
  { key: "cloud_account", label: "Cloud accounts", scans: "AWS / GCP / Azure posture and IAM attack paths", tools: ["prowler", "scout-suite"] },
  { key: "ip_address", label: "Network / IPs", scans: "Port and service discovery with per-port vuln templates", tools: ["nmap", "naabu", "nuclei"] },
  { key: "domain", label: "Domains & DNS", scans: "Subdomain enumeration, takeover, and email-spoofing (DMARC/SPF/DKIM)", tools: ["subfinder", "amass", "checkdmarc"] },
  { key: "workspace", label: "Identity & SaaS", scans: "MFA gaps, risky OAuth grants, stale accounts across Google, M365 & Okta", tools: ["Google Workspace", "Microsoft 365", "Okta"] },
];
