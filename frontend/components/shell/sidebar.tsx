"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  Inbox,
  Activity,
  ShieldCheck,
  Boxes,
  ScrollText,
  FileText,
  FileCheck2,
  UserCheck,
  AppWindow,
  Spline,
  Cloud,
  Layers,
  Crosshair,
  Scale,
  History,
  Radar,
  ScanSearch,
  ChevronDown,
  Sparkles,
  Bug,
  Gauge,
  Users,
} from "lucide-react";
import { LogoMark } from "@/components/brand/logo";
import { cn } from "@/lib/utils";

type NavItem = { href: string; label: string; icon: typeof LayoutDashboard; badgeKey?: "pending" };

// Grouped IA — the nav mirrors the product's architecture so a founder reads the thesis from the
// sidebar: a deterministic POSTURE substrate, two AI teammates that reason over it (a defender and an
// attacker), Compliance, and the human-judgment (HITL) Governance layer. Two pinned items on top (the
// daily driver). Adding a route → drop it in the layer it belongs to, don't grow a flat list.
const NAV_GROUPS: { header?: string; items: NavItem[] }[] = [
  {
    items: [
      { href: "/dashboard", label: "Overview", icon: LayoutDashboard },
      { href: "/inbox", label: "Inbox", icon: Inbox, badgeKey: "pending" },
    ],
  },
  {
    // L1.7 — the deterministic security + compliance posture (scans · correlation · threat-intel),
    // the security-engineer/auditor deliverable that both AI products reason over.
    header: "Posture",
    items: [
      { href: "/issues", label: "Issues", icon: Layers },
      { href: "/findings", label: "Findings", icon: Bug },
      { href: "/incidents", label: "Incidents", icon: Activity },
      { href: "/attack-paths", label: "Attack paths", icon: Spline },
      { href: "/osint", label: "External exposure", icon: Radar },
      { href: "/coverage", label: "Coverage", icon: ScanSearch },
      { href: "/posture", label: "Asset posture", icon: Gauge },
      { href: "/saas-apps", label: "SaaS & identity", icon: AppWindow },
    ],
  },
  {
    // L2 defense — ONE persona that reasons OVER the whole estate (prioritizes, explains, remediates,
    // writes the brief) and DELEGATES cloud-graph depth to the cloud specialist as a tool (#727). The
    // brief is the deliverable; "Cloud depth" is that subordinate specialist, not a co-equal persona.
    // (Expert reviews moved to Governance — it's the human-in-the-loop, not the AI engineer.)
    header: "AI Security Engineer",
    items: [
      { href: "/brief", label: "Security brief", icon: Sparkles },
      { href: "/cloud-engineer", label: "Cloud depth", icon: Cloud },
    ],
  },
  {
    // L2 attack — exploitation-proven VAPT (the other AI teammate).
    header: "AI Pentester",
    items: [{ href: "/pentest", label: "Pentest", icon: Crosshair }],
  },
  {
    header: "Compliance",
    items: [
      { href: "/compliance", label: "Compliance", icon: ShieldCheck },
      { href: "/reports", label: "Reports", icon: FileText },
    ],
  },
  {
    // HITL — the human-judgment layer the AI can't own: vCISO risk acceptance, auditor attestation,
    // policy publication, and expert-review escalations (a human second opinion). Distinct for an
    // auditor, collapsible so a founder can ignore it.
    header: "Governance",
    items: [
      { href: "/risks", label: "Risks", icon: Scale },
      { href: "/audits", label: "Audits", icon: FileCheck2 },
      { href: "/program", label: "Program", icon: ScrollText },
      { href: "/reviews", label: "Expert reviews", icon: UserCheck },
    ],
  },
  {
    header: "Workspace",
    items: [
      { href: "/assets", label: "Assets", icon: Boxes },
      { href: "/security-team", label: "Your security team", icon: Users },
      { href: "/activity", label: "Activity", icon: History },
    ],
  },
];

const COLLAPSE_KEY = "ts.nav.collapsed";

// selfOwned (service-model): when the logged-in tenant OWNS the HITL acts (self_serve) the pending badge
// is an accent to-do; for managed/msp the expert owns them, so the badge is informational (muted) — not
// a nag. Defaults true so nothing changes when the flag isn't passed.
export function Sidebar({ pending, selfOwned = true }: { pending: number; selfOwned?: boolean }) {
  const path = usePathname();
  // which group headers are collapsed — persisted so a founder's tidied-up nav sticks across sessions.
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});
  const [ready, setReady] = useState(false);
  useEffect(() => {
    try {
      const raw = localStorage.getItem(COLLAPSE_KEY);
      if (raw) setCollapsed(JSON.parse(raw));
    } catch {
      /* ignore malformed/absent state */
    }
    setReady(true);
  }, []);
  const toggle = (header: string) =>
    setCollapsed((prev) => {
      const next = { ...prev, [header]: !prev[header] };
      try {
        localStorage.setItem(COLLAPSE_KEY, JSON.stringify(next));
      } catch {
        /* storage may be unavailable */
      }
      return next;
    });

  return (
    <aside className="flex w-56 shrink-0 flex-col border-r border-border bg-bg/60 px-3 py-4">
      <Link href="/dashboard" className="mb-6 flex items-center gap-2.5 px-2">
        <div className="grid h-8 w-8 place-items-center rounded-lg bg-[#0b1220] ring-1 ring-white/10">
          <LogoMark className="h-5 w-5" />
        </div>
        <span className="text-sm font-semibold">TensorShield</span>
      </Link>

      <nav className="flex flex-1 flex-col gap-3 overflow-y-auto">
        {NAV_GROUPS.map((group, gi) => {
          // an active route inside a collapsed group forces it open (never hide where you are)
          const hasActive = group.items.some((it) => path === it.href || path.startsWith(it.href + "/"));
          const isCollapsed = ready && !!group.header && !!collapsed[group.header] && !hasActive;
          return (
            <div key={group.header ?? `g${gi}`} className="flex flex-col gap-0.5">
              {group.header && (
                <button
                  type="button"
                  onClick={() => toggle(group.header!)}
                  className="group/header flex items-center gap-1 px-2.5 pb-1 pt-1 text-[10px] font-semibold uppercase tracking-wider text-faint transition hover:text-muted"
                  aria-expanded={!isCollapsed}
                >
                  <ChevronDown className={cn("h-3 w-3 transition-transform", isCollapsed && "-rotate-90")} />
                  <span className="flex-1 text-left">{group.header}</span>
                </button>
              )}
              {!isCollapsed &&
                group.items.map(({ href, label, icon: Icon, badgeKey }) => {
                  const active = path === href || path.startsWith(href + "/");
                  const badge = badgeKey === "pending" && pending > 0 ? pending : null;
                  return (
                    <Link
                      key={href}
                      href={href}
                      className={cn(
                        "group flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-sm transition",
                        active ? "bg-surface-2 text-ink" : "text-muted hover:bg-surface hover:text-ink",
                      )}
                    >
                      <Icon className={cn("h-4 w-4 transition", active ? "text-accent" : "text-faint group-hover:text-muted")} />
                      <span className="flex-1">{label}</span>
                      {badge != null && (
                        <span
                          className={cn(
                            "rounded-full px-1.5 py-px text-[10px] font-semibold",
                            selfOwned ? "bg-accent text-bg" : "bg-surface-2 text-muted",
                          )}
                        >
                          {badge}
                        </span>
                      )}
                    </Link>
                  );
                })}
            </div>
          );
        })}
      </nav>

      <div className="mt-4 px-2 pt-2 text-[11px] text-faint">
        <span className="pulse-dot mr-1.5 align-middle" /> agent online
      </div>
    </aside>
  );
}
