"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";

// PageTabs — a segmented control of sibling routes, so two related pages read as one tabbed
// surface (e.g. Issues ↔ raw Findings) with a single sidebar entry. The active tab is matched
// by pathname.
export function PageTabs({ tabs }: { tabs: { href: string; label: string }[] }) {
  const path = usePathname();
  return (
    <div className="mb-5 inline-flex flex-wrap gap-0.5 rounded-xl border border-border bg-surface-2/50 p-0.5 text-sm">
      {tabs.map((t) => {
        const active = path === t.href || path.startsWith(t.href + "/");
        return (
          <Link
            key={t.href}
            href={t.href}
            className={cn(
              "rounded-lg px-3.5 py-1.5 font-medium transition",
              active ? "bg-surface text-ink shadow-sm" : "text-muted hover:text-ink",
            )}
          >
            {t.label}
          </Link>
        );
      })}
    </div>
  );
}
