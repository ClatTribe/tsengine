"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  Inbox,
  Bug,
  Activity,
  ShieldCheck,
  Boxes,
  ScrollText,
  FileText,
  Sparkles,
  FileCheck2,
  UserCheck,
  AppWindow,
  Spline,
  Layers,
  Cloud,
  Crosshair,
  Scale,
  History,
  Radar,
  Building2,
  ScanSearch,
  ChevronDown,
} from "lucide-react";
import { LogoMark } from "@/components/brand/logo";
import { cn } from "@/lib/utils";

type NavItem = { href: string; label: string; icon: typeof LayoutDashboard; badgeKey?: "pending" };

// Grouped IA — a non-security founder (our ICP) drowns in a flat 16-item list. Competitors (Vanta,
// Aikido, Linear) bucket nav into a few scannable groups. Two pinned items on top (the daily driver),
// then three labelled groups matching the founder's mental model: Security (am I safe?), Compliance
// (am I audit-ready?), Workspace (what's connected + what happened). Adding a route → drop it in the
// right group, don't grow a flat list.
const NAV_GROUPS: { header?: string; items: NavItem[] }[] = [
  {
    items: [
      { href: "/dashboard", label: "Overview", icon: LayoutDashboard },
      { href: "/inbox", label: "Inbox", icon: Inbox, badgeKey: "pending" },
    ],
  },
  {
    header: "Security",
    items: [
      { href: "/issues", label: "Issues", icon: Layers },
      { href: "/findings", label: "Findings", icon: Bug },
      { href: "/brief", label: "Plain-English brief", icon: Sparkles },
      { href: "/pentest", label: "Pentest", icon: Crosshair },
      { href: "/cloud-engineer", label: "Cloud engineer", icon: Cloud },
      { href: "/attack-paths", label: "Attack paths", icon: Spline },
      { href: "/osint", label: "External exposure", icon: Radar },
      { href: "/posture", label: "Asset posture", icon: Building2 },
      { href: "/coverage", label: "Test coverage", icon: ScanSearch },
      { href: "/incidents", label: "Incidents", icon: Activity },
    ],
  },
  {
    header: "Compliance",
    items: [
      { href: "/compliance", label: "Compliance", icon: ShieldCheck },
      { href: "/risks", label: "Risks", icon: Scale },
      { href: "/audits", label: "Audits", icon: FileCheck2 },
      { href: "/program", label: "Program", icon: ScrollText },
      { href: "/reports", label: "Reports", icon: FileText },
    ],
  },
  {
    header: "Workspace",
    items: [
      { href: "/assets", label: "Assets", icon: Boxes },
      { href: "/saas-apps", label: "SaaS apps", icon: AppWindow },
      { href: "/reviews", label: "Reviews", icon: UserCheck },
      { href: "/activity", label: "Activity", icon: History },
    ],
  },
];

const COLLAPSE_KEY = "ts.nav.collapsed";

export function Sidebar({ pending }: { pending: number }) {
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
        <div className="grid h-8 w-8 place-items-center rounded-lg border border-accent/40 bg-accent-soft text-accent">
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
                        <span className="rounded-full bg-accent px-1.5 py-px text-[10px] font-semibold text-bg">{badge}</span>
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
