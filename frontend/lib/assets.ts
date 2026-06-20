// The asset surfaces TensorShield scans — the buyer-facing "what we cover"
// map. Single-sourced here so the marketing matrix never drifts from the
// engine's real asset coverage (CLAUDE.md §3: 8 engine asset types + the
// identity/workspace surface served by the platform's operate engine).
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
  { key: "repository", label: "Source code", scans: "SAST, dependency CVEs (SCA) with reachability, supply-chain malware, and hardcoded secrets", tools: ["semgrep", "trivy", "govulncheck", "malicious-packages", "gitleaks"] },
  { key: "container_image", label: "Containers", scans: "Image CVEs, misconfigurations, and SBOM", tools: ["trivy", "grype", "dockle"] },
  { key: "cloud_account", label: "Cloud accounts", scans: "AWS / GCP / Azure posture and IAM attack paths", tools: ["prowler", "scout-suite"] },
  { key: "mobile_application", label: "Mobile apps", scans: "Android / iOS — insecure storage, weak crypto, hardcoded keys", tools: ["mobsfscan", "gitleaks"] },
  { key: "ip_address", label: "Network / IPs", scans: "Port and service discovery with per-port vuln templates", tools: ["nmap", "naabu", "nuclei"] },
  { key: "domain", label: "Domains & DNS", scans: "Subdomain enumeration, takeover, and email-spoofing (DMARC/SPF/DKIM)", tools: ["subfinder", "amass", "checkdmarc"] },
  { key: "workspace", label: "Identity & SaaS", scans: "MFA gaps, risky OAuth grants, stale accounts across Google, M365 & Okta", tools: ["Google Workspace", "Microsoft 365", "Okta"] },
];
