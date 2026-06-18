"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { Search, Download, ChevronRight } from "lucide-react";
import type { Finding } from "@/lib/types";
import { sevRank } from "@/lib/utils";
import { SeverityBadge } from "@/components/ui/primitives";
import { cn } from "@/lib/utils";

const SEVS = ["critical", "high", "medium", "low"] as const;

export function FindingsTable({ findings }: { findings: Finding[] }) {
  const [q, setQ] = useState("");
  const [active, setActive] = useState<Set<string>>(new Set());

  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const f of findings) c[f.severity] = (c[f.severity] ?? 0) + 1;
    return c;
  }, [findings]);

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return findings
      .filter((f) => (active.size === 0 || active.has(f.severity)))
      .filter((f) => !needle || `${f.title} ${f.endpoint ?? ""} ${f.tool} ${f.rule_id}`.toLowerCase().includes(needle))
      .sort((a, b) => (sevRank[a.severity] ?? 9) - (sevRank[b.severity] ?? 9));
  }, [findings, q, active]);

  function toggle(s: string) {
    setActive((prev) => {
      const next = new Set(prev);
      next.has(s) ? next.delete(s) : next.add(s);
      return next;
    });
  }

  return (
    <div className="space-y-3">
      {/* Filter bar */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="flex items-center gap-1.5">
          {SEVS.map((s) => (
            <button
              key={s}
              onClick={() => toggle(s)}
              className={cn(
                "rounded-md border px-2 py-1 text-xs capitalize transition",
                active.has(s) ? "border-accent/50 bg-accent-soft text-accent" : "border-border bg-surface text-muted hover:border-border-strong",
              )}
            >
              {s} <span className="text-faint">{counts[s] ?? 0}</span>
            </button>
          ))}
        </div>

        <div className="relative ml-1 flex-1 sm:max-w-xs">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-faint" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search findings…"
            className="w-full rounded-lg border border-border bg-surface py-1.5 pl-8 pr-3 text-sm outline-none transition focus:border-accent"
          />
        </div>

        <div className="ml-auto flex items-center gap-1.5">
          <a href="/api/export?format=sarif" className="flex items-center gap-1.5 rounded-lg border border-border bg-surface px-2.5 py-1.5 text-xs text-muted transition hover:border-border-strong hover:text-ink">
            <Download className="h-3.5 w-3.5" /> SARIF
          </a>
          <a href="/api/export?format=csv" className="flex items-center gap-1.5 rounded-lg border border-border bg-surface px-2.5 py-1.5 text-xs text-muted transition hover:border-border-strong hover:text-ink">
            <Download className="h-3.5 w-3.5" /> CSV
          </a>
        </div>
      </div>

      {/* Table */}
      <div className="card p-0">
        {rows.length === 0 ? (
          <div className="px-5 py-10 text-center text-sm text-muted">
            {findings.length === 0 ? "No open findings." : "No findings match your filter."}
          </div>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="border-b border-border text-left text-[11px] uppercase tracking-wide text-faint">
                <th className="py-2.5 pl-5 pr-2 font-medium">Severity</th>
                <th className="px-2 py-2.5 font-medium">Finding</th>
                <th className="px-2 py-2.5 font-medium">Where</th>
                <th className="px-2 py-2.5 font-medium">Tool</th>
                <th className="py-2.5 pr-5 font-medium" />
              </tr>
            </thead>
            <tbody>
              {rows.map((f) => (
                <tr key={f.id} className="group border-b border-border last:border-0 transition hover:bg-surface-2">
                  <td className="py-2.5 pl-5 pr-2 align-top">
                    <SeverityBadge severity={f.severity} />
                  </td>
                  <td className="max-w-0 px-2 py-2.5 align-top">
                    <Link href={`/findings/${f.id}`} className="block truncate text-sm hover:text-accent">
                      {f.title}
                    </Link>
                  </td>
                  <td className="max-w-[16rem] px-2 py-2.5 align-top">
                    <span className="mono block truncate text-xs text-faint">{f.endpoint || "—"}</span>
                  </td>
                  <td className="px-2 py-2.5 align-top">
                    <span className="mono text-xs text-muted">{f.tool}</span>
                  </td>
                  <td className="py-2.5 pr-5 align-top text-right">
                    <Link href={`/findings/${f.id}`} className="inline-block text-faint transition group-hover:text-accent">
                      <ChevronRight className="h-4 w-4" />
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      <p className="text-[11px] text-faint">
        {rows.length} of {findings.length} findings
      </p>
    </div>
  );
}
