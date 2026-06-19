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
  UserCheck,
} from "lucide-react";
import { cn } from "@/lib/utils";

const NAV = [
  { href: "/dashboard", label: "Overview", icon: LayoutDashboard },
  { href: "/inbox", label: "Inbox", icon: Inbox, badgeKey: "pending" as const },
  { href: "/reviews", label: "Reviews", icon: UserCheck },
  { href: "/findings", label: "Findings", icon: Bug },
  { href: "/incidents", label: "Incidents", icon: Activity },
  { href: "/compliance", label: "Compliance", icon: ShieldCheck },
  { href: "/reports", label: "Reports", icon: FileText },
  { href: "/assets", label: "Assets", icon: Boxes },
  { href: "/activity", label: "Activity", icon: ScrollText },
];

export function Sidebar({ pending }: { pending: number }) {
  const path = usePathname();
  return (
    <aside className="flex w-56 shrink-0 flex-col border-r border-border bg-bg/60 px-3 py-4">
      <Link href="/dashboard" className="mb-6 flex items-center gap-2.5 px-2">
        <div className="grid h-8 w-8 place-items-center rounded-lg border border-accent/40 bg-accent-soft text-accent">
          <ShieldCheck className="h-4 w-4" />
        </div>
        <span className="text-sm font-semibold">Sentinel</span>
      </Link>

      <nav className="flex flex-col gap-0.5">
        {NAV.map(({ href, label, icon: Icon, badgeKey }) => {
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
      </nav>

      <div className="mt-auto px-2 pt-4 text-[11px] text-faint">
        <span className="pulse-dot mr-1.5 align-middle" /> agent online
      </div>
    </aside>
  );
}
