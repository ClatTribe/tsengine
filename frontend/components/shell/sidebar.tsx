"use client";

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
  FileCheck2,
  UserCheck,
  AppWindow,
  Spline,
  Layers,
  Crosshair,
  Scale,
  History,
} from "lucide-react";
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
      { href: "/pentest", label: "Pentest", icon: Crosshair },
      { href: "/attack-paths", label: "Attack paths", icon: Spline },
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

export function Sidebar({ pending }: { pending: number }) {
  const path = usePathname();
  return (
    <aside className="flex w-56 shrink-0 flex-col border-r border-border bg-bg/60 px-3 py-4">
      <Link href="/dashboard" className="mb-6 flex items-center gap-2.5 px-2">
        <div className="grid h-8 w-8 place-items-center rounded-lg border border-accent/40 bg-accent-soft text-accent">
          <ShieldCheck className="h-4 w-4" />
        </div>
        <span className="text-sm font-semibold">TensorShield</span>
      </Link>

      <nav className="flex flex-1 flex-col gap-4 overflow-y-auto">
        {NAV_GROUPS.map((group, gi) => (
          <div key={group.header ?? `g${gi}`} className="flex flex-col gap-0.5">
            {group.header && (
              <div className="px-2.5 pb-1 pt-1 text-[10px] font-semibold uppercase tracking-wider text-faint">
                {group.header}
              </div>
            )}
            {group.items.map(({ href, label, icon: Icon, badgeKey }) => {
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
        ))}
      </nav>

      <div className="mt-4 px-2 pt-2 text-[11px] text-faint">
        <span className="pulse-dot mr-1.5 align-middle" /> agent online
      </div>
    </aside>
  );
}
