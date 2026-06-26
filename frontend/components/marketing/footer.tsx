import Link from "next/link";
import { LogoMark } from "@/components/brand/logo";

const COLS: { title: string; links: { href: string; label: string }[] }[] = [
  {
    title: "Product",
    links: [
      { href: "/product", label: "How it works" },
      { href: "/vs-consulting", label: "vs. a consultant" },
      { href: "/cross-detection", label: "Unified platform" },
      { href: "/ai-security-engineer", label: "AI security engineer" },
      { href: "/ai-pentest", label: "AI pentesting" },
      { href: "/vapt", label: "VAPT reports" },
      { href: "/supply-chain", label: "Supply-chain security" },
      { href: "/saas-posture", label: "SaaS & identity posture" },
      { href: "/ci-cd", label: "CI/CD pipeline" },
      { href: "/integrations", label: "Integrations" },
      { href: "/frameworks", label: "Frameworks" },
      { href: "/pricing", label: "Pricing" },
      { href: "/security", label: "Security" },
    ],
  },
  {
    title: "By asset",
    links: [
      { href: "/cloud-security", label: "Cloud security" },
      { href: "/api-security", label: "API security" },
      { href: "/web-application-security", label: "Web app security" },
      { href: "/code-security", label: "Code security" },
      { href: "/container-security", label: "Container security" },
      { href: "/mobile-app-security", label: "Mobile app security" },
      { href: "/network-security", label: "Network & IP" },
      { href: "/dns-domain-security", label: "Domain & DNS" },
    ],
  },
  {
    title: "Free tools",
    links: [
      { href: "/scan", label: "Questionnaire scan" },
      { href: "/soc2-readiness", label: "SOC 2 self-assessment" },
      { href: "/resources", label: "Free resources" },
      { href: "/sample-report", label: "Sample report" },
      { href: "/blog", label: "Blog" },
    ],
  },
  {
    title: "Company",
    links: [
      { href: "/about", label: "About" },
      { href: "/managed", label: "Managed service" },
      { href: "/partners", label: "For MSPs & consultancies" },
      { href: "/demo", label: "Book a demo" },
      { href: "/login", label: "Sign in" },
    ],
  },
  {
    title: "Trust",
    links: [
      { href: "/security", label: "SOC 2 · ISO 27001" },
      { href: "/security", label: "Signed evidence" },
    ],
  },
];

export function MarketingFooter() {
  return (
    <footer className="border-t border-border bg-surface">
      <div className="mx-auto max-w-6xl px-5 py-14">
        <div className="grid gap-10 sm:grid-cols-2 lg:grid-cols-5">
          <div>
            <Link href="/" className="flex items-center gap-2.5">
              <span className="grid h-8 w-8 place-items-center rounded-lg bg-accent text-white shadow-sm">
                <LogoMark className="h-5 w-5" />
              </span>
              <span className="text-base font-semibold tracking-tight">TensorShield</span>
            </Link>
            <p className="mt-3 max-w-xs text-sm leading-relaxed text-muted">
              The fractional security team for SMBs — automated, with a human in the loop.
            </p>
          </div>
          {COLS.map((c) => (
            <div key={c.title}>
              <div className="text-xs font-semibold uppercase tracking-wider text-faint">{c.title}</div>
              <ul className="mt-3 space-y-2">
                {c.links.map((l) => (
                  <li key={l.label}>
                    <Link href={l.href} className="text-sm text-muted transition hover:text-ink">
                      {l.label}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
        <div className="mt-12 flex flex-col items-center justify-between gap-3 border-t border-border pt-6 text-xs text-faint sm:flex-row">
          <span>© {2026} TensorShield. All rights reserved.</span>
          <span className="inline-flex items-center gap-1.5">
            <span className="pulse-dot" /> All systems operational
          </span>
        </div>
      </div>
    </footer>
  );
}
