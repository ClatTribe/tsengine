import Link from "next/link";
import { ShieldCheck } from "lucide-react";

const COLS: { title: string; links: { href: string; label: string }[] }[] = [
  {
    title: "Product",
    links: [
      { href: "/product", label: "How it works" },
      { href: "/pricing", label: "Pricing" },
      { href: "/security", label: "Security" },
    ],
  },
  {
    title: "Company",
    links: [
      { href: "/about", label: "About" },
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
        <div className="grid gap-10 sm:grid-cols-2 lg:grid-cols-4">
          <div>
            <Link href="/" className="flex items-center gap-2.5">
              <span className="grid h-8 w-8 place-items-center rounded-lg bg-accent text-white shadow-sm">
                <ShieldCheck className="h-4 w-4" />
              </span>
              <span className="text-base font-semibold tracking-tight">Sentinel</span>
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
          <span>© {2026} Sentinel. All rights reserved.</span>
          <span className="inline-flex items-center gap-1.5">
            <span className="pulse-dot" /> All systems operational
          </span>
        </div>
      </div>
    </footer>
  );
}
