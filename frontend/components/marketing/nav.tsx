"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Menu, X, ChevronDown, Bot, Crosshair, FileCheck2, Boxes,
  AppWindow, GitBranch, Scale, Layers, Radar, ClipboardCheck, FileText, Sparkles, BookOpen, ShieldCheck,
  Cloud, KeyRound, UserCheck, ArrowRight, Building2, Users, Mail,
} from "lucide-react";
import { LogoMark } from "@/components/brand/logo";
import { ThemeToggle } from "@/components/theme-toggle";
import { FRAMEWORKS, FRAMEWORK_LABEL, FRAMEWORK_CATEGORY } from "@/lib/frameworks";
import { cn } from "@/lib/utils";

type Item = { href: string; label: string; desc: string; icon: typeof Bot };

// Frameworks grouped by category for the mega-menu (Sprinto-style). Sourced from the single framework
// registry, so it stays in lock-step with the 22 supported frameworks.
const FW_CATEGORY_ORDER = ["Security & trust", "Sector & payments", "Privacy", "Government", "AI governance"];
const FRAMEWORK_GROUPS = FW_CATEGORY_ORDER.map((cat) => ({
  cat,
  items: FRAMEWORKS.filter((f) => (FRAMEWORK_CATEGORY[f] ?? "Security & trust") === cat),
})).filter((g) => g.items.length > 0);

// The Solutions menu leads with the two OUTCOMES a founder actually buys — Security and Compliance — with
// the autonomous-team + human-in-the-loop as the cross-cutting spine (the footer). The technical categories
// are coverage pages filed under the outcome they serve, not co-equal pillars. (Runtime "Protect" is held
// off until the managed-Zen wrap, so we never advertise a pillar we don't fill.)
const SECURITY: Item[] = [
  { href: "/ai-security-engineer", label: "AI security engineer", desc: "Triages, fixes & explains — not just flags", icon: Bot },
  { href: "/ai-pentest", label: "AI pentesting", desc: "Continuous, exploitation-proven testing", icon: Crosshair },
  { href: "/cloud-security", label: "Cloud security", desc: "CSPM, attack paths & drift across AWS/GCP/Azure", icon: Cloud },
  { href: "/supply-chain", label: "Code & supply chain", desc: "SAST, deps, SBOM, malware, secrets", icon: Boxes },
  { href: "/identity", label: "Identity & SaaS posture", desc: "MFA, OAuth grants, stale access, SSPM", icon: KeyRound },
  { href: "/agent-controls", label: "AI agent controls", desc: "Kill-switch, isolation, human gate, signed log", icon: ShieldCheck },
];
const COMPLIANCE: Item[] = [
  { href: "/frameworks", label: "Frameworks", desc: "SOC 2, ISO, HIPAA, PCI + 18 more — auto-mapped", icon: FileCheck2 },
  { href: "/vapt", label: "VAPT & evidence", desc: "Always-current, signed reports", icon: FileText },
  { href: "/soc2-readiness", label: "SOC 2 readiness", desc: "Where you'd fail the questionnaire — free", icon: ClipboardCheck },
  { href: "/vs-consulting", label: "vs. a consultant", desc: "The vCISO outcome, without the retainer", icon: Scale },
];

// Free tools — the founder ICP's top-of-funnel hook. Lead with the questionnaire scan.
const TOOLS: Item[] = [
  { href: "/scan", label: "Free domain scan", desc: "Spoofable? DMARC/SPF/TLS/headers in seconds", icon: Radar },
  { href: "/soc2-readiness", label: "SOC 2 readiness check", desc: "Where you'd fail the questionnaire — free", icon: ClipboardCheck },
  { href: "/sample-report", label: "Sample VAPT report", desc: "See exactly what you'd hand a buyer", icon: FileText },
  { href: "/resources", label: "Free resources", desc: "SOC 2 checklist + questionnaire template", icon: BookOpen },
];

// Direct top-bar link: just Pricing. Everything else is either a solution (Solutions menu) or a
// delivery/company page (Company menu) — the bar stays uncluttered.
const DIRECT = [{ href: "/pricing", label: "Pricing" }];

// Company menu — about + ways to reach us + the two DELIVERY models (managed, MSP channel). These
// are company/delivery pages, NOT solutions (Solutions = what we provide), so they're grouped here
// instead of cluttering the top bar.
const COMPANY: Item[] = [
  { href: "/about", label: "About", desc: "Who we are and why we built this", icon: Building2 },
  { href: "/managed", label: "Managed service", desc: "We run it for you — done-for-you delivery", icon: UserCheck },
  { href: "/partners", label: "For MSPs & consultancies", desc: "Run TensorShield for your clients", icon: Users },
  { href: "/blog", label: "Blog", desc: "Notes on security, compliance & AI", icon: BookOpen },
  { href: "/demo", label: "Contact us", desc: "Book a demo or talk to the team", icon: Mail },
];

export function MarketingNav() {
  const [open, setOpen] = useState(false); // mobile sheet
  const [menu, setMenu] = useState<"solutions" | "frameworks" | "tools" | "company" | null>(null); // desktop dropdown
  const [acc, setAcc] = useState<"security" | "compliance" | "tools" | "company" | null>(null); // mobile accordion
  const path = usePathname();
  const closeTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Esc closes the desktop dropdown.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setMenu(null);
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const openMenu = (m: "solutions" | "frameworks" | "tools" | "company") => {
    if (closeTimer.current) clearTimeout(closeTimer.current);
    setMenu(m);
  };
  const scheduleClose = () => {
    if (closeTimer.current) clearTimeout(closeTimer.current);
    closeTimer.current = setTimeout(() => setMenu(null), 120); // grace period crossing the gap to the panel
  };

  return (
    <header className="sticky top-0 z-40 border-b border-border/70 bg-bg/80 backdrop-blur-md">
      <nav className="mx-auto flex h-16 max-w-6xl items-center gap-1 px-5">
        <Link href="/" className="mr-2 flex items-center gap-2.5" onClick={() => setOpen(false)}>
          <span className="grid h-8 w-8 place-items-center rounded-lg bg-[#0b1220] ring-1 ring-white/10 shadow-sm">
            <LogoMark className="h-5 w-5" />
          </span>
          <span className="text-base font-semibold tracking-tight">TensorShield</span>
        </Link>

        {/* Desktop nav */}
        <div className="hidden items-center gap-0.5 md:flex">
          <SolutionsMenu
            isOpen={menu === "solutions"}
            onEnter={() => openMenu("solutions")}
            onLeave={scheduleClose}
            path={path}
          />
          <FrameworksMenu
            isOpen={menu === "frameworks"}
            onEnter={() => openMenu("frameworks")}
            onLeave={scheduleClose}
            path={path}
          />
          <Dropdown
            label="Free tools"
            badge
            items={TOOLS}
            isOpen={menu === "tools"}
            onEnter={() => openMenu("tools")}
            onLeave={scheduleClose}
            path={path}
          />
          {DIRECT.map((l) => (
            <Link
              key={l.href}
              href={l.href}
              className={cn(
                "rounded-lg px-3 py-1.5 text-sm transition hover:bg-surface-2 hover:text-ink",
                path === l.href ? "text-ink" : "text-muted",
              )}
            >
              {l.label}
            </Link>
          ))}
          <Dropdown
            label="Company"
            items={COMPANY}
            isOpen={menu === "company"}
            onEnter={() => openMenu("company")}
            onLeave={scheduleClose}
            path={path}
          />
        </div>

        {/* Desktop CTAs */}
        <div className="ml-auto hidden items-center gap-2 md:flex">
          <ThemeToggle />
          <Link href="/login" className="rounded-lg px-3 py-1.5 text-sm font-medium text-muted transition hover:text-ink">
            Sign in
          </Link>
          <Link
            href="/signup"
            className="rounded-xl bg-accent px-3.5 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover active:translate-y-px"
          >
            Start free
          </Link>
        </div>

        {/* Mobile: primary CTA + menu toggle */}
        <div className="ml-auto flex items-center gap-2 md:hidden">
          <Link
            href="/scan"
            className="rounded-xl border border-accent/40 bg-accent-soft px-3 py-1.5 text-sm font-semibold text-accent transition active:translate-y-px"
          >
            Free scan
          </Link>
          <button
            onClick={() => setOpen((v) => !v)}
            aria-label={open ? "Close menu" : "Open menu"}
            aria-expanded={open}
            className="grid h-9 w-9 place-items-center rounded-lg border border-border bg-surface text-muted transition hover:border-border-strong hover:text-ink"
          >
            {open ? <X className="h-4 w-4" /> : <Menu className="h-4 w-4" />}
          </button>
        </div>
      </nav>

      {/* Mobile sheet */}
      {open && (
        <div className="max-h-[80vh] overflow-y-auto border-t border-border/70 bg-bg px-5 py-3 md:hidden animate-fade-rise">
          <MobileGroup
            label="Security"
            items={SECURITY}
            open={acc === "security"}
            onToggle={() => setAcc((a) => (a === "security" ? null : "security"))}
            onNavigate={() => setOpen(false)}
          />
          <MobileGroup
            label="Compliance"
            items={COMPLIANCE}
            open={acc === "compliance"}
            onToggle={() => setAcc((a) => (a === "compliance" ? null : "compliance"))}
            onNavigate={() => setOpen(false)}
          />
          <MobileGroup
            label="Free tools"
            items={TOOLS}
            open={acc === "tools"}
            onToggle={() => setAcc((a) => (a === "tools" ? null : "tools"))}
            onNavigate={() => setOpen(false)}
          />
          <MobileGroup
            label="Company"
            items={COMPANY}
            open={acc === "company"}
            onToggle={() => setAcc((a) => (a === "company" ? null : "company"))}
            onNavigate={() => setOpen(false)}
          />
          <div className="mt-1 flex flex-col gap-0.5 border-t border-border/60 pt-2">
            <Link href="/frameworks" onClick={() => setOpen(false)} className="rounded-lg px-3 py-2.5 text-sm text-muted transition hover:bg-surface-2 hover:text-ink">
              Frameworks ({FRAMEWORKS.length})
            </Link>
            {DIRECT.map((l) => (
              <Link
                key={l.href}
                href={l.href}
                onClick={() => setOpen(false)}
                className="rounded-lg px-3 py-2.5 text-sm text-muted transition hover:bg-surface-2 hover:text-ink"
              >
                {l.label}
              </Link>
            ))}
            <Link href="/login" onClick={() => setOpen(false)} className="rounded-lg px-3 py-2.5 text-sm font-medium text-muted transition hover:bg-surface-2 hover:text-ink">
              Sign in
            </Link>
            <Link href="/signup" onClick={() => setOpen(false)} className="mt-1 rounded-xl bg-accent px-3 py-2.5 text-center text-sm font-semibold text-white">
              Start free
            </Link>
          </div>
        </div>
      )}
    </header>
  );
}

function Dropdown({
  label, items, isOpen, onEnter, onLeave, path, badge,
}: {
  label: string;
  items: Item[];
  isOpen: boolean;
  onEnter: () => void;
  onLeave: () => void;
  path: string;
  badge?: boolean;
}) {
  const active = items.some((i) => path === i.href);
  return (
    <div className="relative" onMouseEnter={onEnter} onMouseLeave={onLeave}>
      <button
        className={cn(
          "flex items-center gap-1 rounded-lg px-3 py-1.5 text-sm transition hover:bg-surface-2 hover:text-ink",
          isOpen || active ? "text-ink" : "text-muted",
        )}
        aria-expanded={isOpen}
      >
        {badge && <Sparkles className="h-3.5 w-3.5 text-accent" />}
        {label}
        <ChevronDown className={cn("h-3.5 w-3.5 transition-transform", isOpen && "rotate-180")} />
      </button>
      {isOpen && (
        <div className="absolute left-0 top-full pt-2">
          <div className="w-[22rem] overflow-hidden rounded-xl border border-border bg-surface p-1.5 shadow-elevated animate-fade-rise">
            {items.map(({ href, label: l, desc, icon: Icon }) => (
              <Link
                key={href}
                href={href}
                className={cn(
                  "flex items-start gap-3 rounded-lg px-2.5 py-2 transition hover:bg-surface-2",
                  path === href && "bg-surface-2",
                )}
              >
                <span className="mt-0.5 grid h-7 w-7 shrink-0 place-items-center rounded-lg bg-accent-soft text-accent">
                  <Icon className="h-3.5 w-3.5" />
                </span>
                <span className="min-w-0">
                  <span className="block text-sm font-medium text-ink">{l}</span>
                  <span className="block text-xs leading-snug text-muted">{desc}</span>
                </span>
              </Link>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// SolutionsMenu — the two-outcome mega-menu. Security + Compliance as co-equal columns (matching the
// founder's "am I safe? am I audit-ready?" mental model), with the autonomous-team + human-in-the-loop as
// the cross-cutting spine in the footer — NOT buried in one column. The technical categories are coverage
// links filed under the outcome they serve, not co-equal pillars.
function SolutionsMenu({
  isOpen, onEnter, onLeave, path,
}: {
  isOpen: boolean;
  onEnter: () => void;
  onLeave: () => void;
  path: string;
}) {
  const active = [...SECURITY, ...COMPLIANCE].some((i) => path === i.href);
  const col = (heading: string, items: Item[]) => (
    <div>
      <div className="mb-1.5 px-2 text-[11px] font-semibold uppercase tracking-wider text-faint">{heading}</div>
      <div className="flex flex-col gap-0.5">
        {items.map(({ href, label: l, desc, icon: Icon }) => (
          <Link
            key={href}
            href={href}
            className={cn("flex items-start gap-3 rounded-lg px-2.5 py-2 transition hover:bg-surface-2", path === href && "bg-surface-2")}
          >
            <span className="mt-0.5 grid h-7 w-7 shrink-0 place-items-center rounded-lg bg-accent-soft text-accent">
              <Icon className="h-3.5 w-3.5" />
            </span>
            <span className="min-w-0">
              <span className="block text-sm font-medium text-ink">{l}</span>
              <span className="block text-xs leading-snug text-muted">{desc}</span>
            </span>
          </Link>
        ))}
      </div>
    </div>
  );
  return (
    <div className="relative" onMouseEnter={onEnter} onMouseLeave={onLeave}>
      <button
        className={cn(
          "flex items-center gap-1 rounded-lg px-3 py-1.5 text-sm transition hover:bg-surface-2 hover:text-ink",
          isOpen || active ? "text-ink" : "text-muted",
        )}
        aria-expanded={isOpen}
      >
        Solutions
        <ChevronDown className={cn("h-3.5 w-3.5 transition-transform", isOpen && "rotate-180")} />
      </button>
      {isOpen && (
        <div className="absolute left-0 top-full pt-2">
          <div className="w-[42rem] overflow-hidden rounded-xl border border-border bg-surface p-4 shadow-elevated animate-fade-rise">
            <div className="grid grid-cols-2 gap-x-6">
              {col("Security", SECURITY)}
              {col("Compliance", COMPLIANCE)}
            </div>
            {/* The spine: one team, a human where it matters — across BOTH outcomes (our AutoFix-slot). */}
            <Link
              href="/product"
              className="mt-3 flex items-center justify-between rounded-lg border border-border/60 bg-surface-2/60 px-3 py-2.5 transition hover:border-border-strong"
            >
              <span className="flex items-center gap-2.5">
                <span className="grid h-7 w-7 shrink-0 place-items-center rounded-lg bg-accent text-white">
                  <UserCheck className="h-3.5 w-3.5" />
                </span>
                <span>
                  <span className="block text-sm font-medium text-ink">One autonomous team — with a human in the loop</span>
                  <span className="block text-xs text-muted">The agent finds &amp; fixes; a named human makes the calls that matter. Across security and compliance.</span>
                </span>
              </span>
              <ArrowRight className="h-4 w-4 shrink-0 text-muted" />
            </Link>
          </div>
        </div>
      )}
    </div>
  );
}

// FrameworksMenu — a grouped mega-menu of every supported compliance framework (Sprinto-style), so a
// buyer can find the framework their customer asks for straight from the header.
function FrameworksMenu({
  isOpen, onEnter, onLeave, path,
}: {
  isOpen: boolean;
  onEnter: () => void;
  onLeave: () => void;
  path: string;
}) {
  const active = path.startsWith("/frameworks");
  return (
    <div className="relative" onMouseEnter={onEnter} onMouseLeave={onLeave}>
      <button
        className={cn(
          "flex items-center gap-1 rounded-lg px-3 py-1.5 text-sm transition hover:bg-surface-2 hover:text-ink",
          isOpen || active ? "text-ink" : "text-muted",
        )}
        aria-expanded={isOpen}
      >
        Frameworks
        <ChevronDown className={cn("h-3.5 w-3.5 transition-transform", isOpen && "rotate-180")} />
      </button>
      {isOpen && (
        <div className="absolute left-0 top-full pt-2">
          <div className="w-[44rem] overflow-hidden rounded-xl border border-border bg-surface p-4 shadow-elevated animate-fade-rise">
            <div className="grid grid-cols-3 gap-x-5 gap-y-4">
              {FRAMEWORK_GROUPS.map(({ cat, items }) => (
                <div key={cat}>
                  <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-faint">{cat}</div>
                  <div className="flex flex-col gap-0.5">
                    {items.map((f) => (
                      <Link
                        key={f}
                        href={`/frameworks/${f}`}
                        className={cn(
                          "rounded-md px-2 py-1 text-sm text-muted transition hover:bg-surface-2 hover:text-ink",
                          path === `/frameworks/${f}` && "bg-surface-2 text-ink",
                        )}
                      >
                        {FRAMEWORK_LABEL[f] ?? f}
                      </Link>
                    ))}
                  </div>
                </div>
              ))}
            </div>
            <div className="mt-3 flex items-center justify-between border-t border-border/60 pt-3">
              <span className="text-xs text-muted">{FRAMEWORKS.length} frameworks + bring your own — mapped to your live findings.</span>
              <Link href="/frameworks" className="text-xs font-medium text-accent hover:underline">View all frameworks →</Link>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function MobileGroup({
  label, items, open, onToggle, onNavigate,
}: {
  label: string;
  items: Item[];
  open: boolean;
  onToggle: () => void;
  onNavigate: () => void;
}) {
  return (
    <div className="border-b border-border/60 py-1">
      <button
        onClick={onToggle}
        className="flex w-full items-center justify-between rounded-lg px-3 py-2.5 text-sm font-medium text-ink"
        aria-expanded={open}
      >
        {label}
        <ChevronDown className={cn("h-4 w-4 text-muted transition-transform", open && "rotate-180")} />
      </button>
      {open && (
        <div className="flex flex-col gap-0.5 pb-1">
          {items.map(({ href, label: l, icon: Icon }) => (
            <Link
              key={href}
              href={href}
              onClick={onNavigate}
              className="flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm text-muted transition hover:bg-surface-2 hover:text-ink"
            >
              <Icon className="h-4 w-4 shrink-0 text-faint" />
              {l}
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
