"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  Inbox,
  ShieldCheck,
  Boxes,
  ScrollText,
  FileText,
  FileCheck2,
  AppWindow,
  Spline,
  Cloud,
  Layers,
  Crosshair,
  Scale,
  ScanSearch,
  ChevronDown,
  Sparkles,
  Gauge,
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
    // SECURITY outcome — "Am I secure?". ONE problems list (Issues) the founder/dev acts on. We do NOT
    // make them learn issue vs finding vs incident: the raw per-tool detail is a tab INSIDE Issues,
    // "what's new / urgent" rides as badges on Issues + the Overview, and internet/external exposure (the
    // old "OSINT" page) already flows INTO Issues as a detection source — not a separate destination.
    // Only TWO surfaces hold information NOT already in Issues, so only they earn a slot beside it:
    // Attack paths (the graph/EDGES — Issues is just nodes) and What we test (the NEGATIVE space — tools
    // that ran clean). Raw findings / incidents / OSINT are the SAME findings re-sliced → filters on
    // Issues, not pages. Vendors & devices + Connected apps are INVENTORIES → moved to Connections.
    header: "Security",
    items: [
      { href: "/issues", label: "Issues", icon: Layers },
      { href: "/attack-paths", label: "Attack paths", icon: Spline },
      { href: "/coverage", label: "What we test", icon: ScanSearch },
    ],
  },
  {
    // COMPLIANCE outcome — the same substrate's control mapping + reachability + evidence. "Am I
    // audit-ready?" Adjacent to Security: the two outcomes are the spine; the AI consoles operate on them.
    header: "Compliance",
    items: [
      { href: "/compliance", label: "Compliance", icon: ShieldCheck },
      { href: "/reports", label: "Reports", icon: FileText },
    ],
  },
  {
    // L2 defense console — ONE persona reasoning OVER both outcomes (prioritize · explain · remediate ·
    // auto-fix), delegating cloud-graph depth to the cloud specialist as a tool (#727). Agentic ACTIONS,
    // not a chat (docs/product-restructure.md). (Expert reviews → "Your security team" hub: it's the HITL, not the AI.)
    header: "AI Security Engineer",
    items: [
      { href: "/brief", label: "Console", icon: Sparkles },
      { href: "/cloud-engineer", label: "Cloud depth", icon: Cloud },
    ],
  },
  {
    // L2 attack console — exploitation-proven VAPT (scope → launch → report).
    header: "AI Pentester",
    items: [{ href: "/pentest", label: "Pentest", icon: Crosshair }],
  },
  {
    // GRC outcome — the human-judgment layer the AI can't own: vCISO risk acceptance, auditor
    // attestation, policy publication. (Expert reviews — "get a human second opinion" — lives on the
    // "Your security team" hub, NOT here.) Renamed "Governance" → "GRC" (the customer's word).
    header: "GRC",
    items: [
      { href: "/risks", label: "Risks", icon: Scale },
      { href: "/audits", label: "Audits", icon: FileCheck2 },
      { href: "/program", label: "Program", icon: ScrollText },
    ],
  },
  {
    // INTEGRATION outcome — "what I've connected." The inventory: targets/repos/cloud (Assets) plus the
    // two surfaces that are INVENTORIES, not finding-views — Vendors & devices and Connected apps (their
    // risk findings already appear in Security via Issues; here you see WHAT you have, not what's wrong).
    header: "Connections",
    items: [
      { href: "/assets", label: "Assets", icon: Boxes },
      { href: "/posture", label: "Vendors & devices", icon: Gauge },
      { href: "/saas-apps", label: "Connected apps", icon: AppWindow },
    ],
  },
  // "Your security team" (who's accountable) + "Activity" (audit log) are ACCOUNT CONTEXT, not daily
  // destinations — they live under Settings now, reachable from there + the command palette, off the
  // daily sidebar.
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
