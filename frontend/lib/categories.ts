import type { Finding } from "@/lib/types";

// Security domains a user thinks in — the buckets used by the findings "By
// category" grouping and the dashboard risk-by-category breakdown. Shared so
// the client table and the server dashboard classify identically.

// CATEGORY_TOOLS maps a scanner/engine to its domain.
const CATEGORY_TOOLS: Record<string, string> = {
  // Supply chain (dependencies)
  trivy: "Supply chain", grype: "Supply chain", "osv-scanner": "Supply chain", syft: "Supply chain", govulncheck: "Supply chain",
  "malicious-packages": "Supply chain", eol: "Supply chain", "deprecated-packages": "Supply chain", license: "Supply chain",
  // Code (SAST · secrets · IaC)
  semgrep: "Code", gitleaks: "Code", trufflehog: "Code", codeql: "Code", mobsfscan: "Code", checkov: "Code", hadolint: "Code", bandit: "Code",
  // Web & API
  nuclei: "Web & API", sqlmap: "Web & API", dalfox: "Web & API", wpscan: "Web & API", ffuf: "Web & API", hydra: "Web & API", httpx: "Web & API", katana: "Web & API", kiterunner: "Web & API", inql: "Web & API", schemathesis: "Web & API",
  // Cloud
  prowler: "Cloud", scoutsuite: "Cloud", "scout-suite": "Cloud", cloudfox: "Cloud",
  // Network & domain
  nmap: "Network & domain", naabu: "Network & domain", subfinder: "Network & domain", amass: "Network & domain", checkdmarc: "Network & domain", dnstwist: "Network & domain", crtsh: "Network & domain",
  // Container
  dockle: "Container", cosign: "Container",
  // Identity & SaaS posture
  operate: "Identity & SaaS", sspm: "Identity & SaaS",
};

// The display order for category buckets (worst/most-relevant first).
export const CATEGORY_ORDER = [
  "Supply chain", "Identity & SaaS", "Code", "Web & API", "Cloud", "Network & domain", "Container", "Other",
] as const;

// categoryOf classifies a finding by its security domain. The dependency checks
// carry a distinctive rule_id namespace, so they map precisely regardless of how
// the finding's tool field is set.
export function categoryOf(f: Finding): string {
  const r = (f.rule_id ?? "").toLowerCase();
  if (/^(malicious-packages|eol|deprecated|license)::/.test(r)) return "Supply chain";
  if (r.startsWith("sspm::") || r.startsWith("operate")) return "Identity & SaaS";
  return CATEGORY_TOOLS[(f.tool ?? "").toLowerCase()] ?? "Other";
}

export type CategoryRow = {
  category: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
};

// categoryBreakdown rolls findings up per security domain, in CATEGORY_ORDER,
// dropping empty buckets.
export function categoryBreakdown(findings: Finding[]): CategoryRow[] {
  const m = new Map<string, CategoryRow>();
  for (const f of findings) {
    const c = categoryOf(f);
    const e = m.get(c) ?? { category: c, critical: 0, high: 0, medium: 0, low: 0, total: 0 };
    if (f.severity === "critical" || f.severity === "high" || f.severity === "medium" || f.severity === "low") {
      e[f.severity]++;
    }
    e.total++;
    m.set(c, e);
  }
  return CATEGORY_ORDER.filter((c) => m.has(c)).map((c) => m.get(c)!);
}
