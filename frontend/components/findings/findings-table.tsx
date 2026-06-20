"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { Search, Download, ChevronRight, ShieldCheck, BadgeCheck, Wrench, FileCheck2 } from "lucide-react";
import type { Finding } from "@/lib/types";
import { sevRank } from "@/lib/utils";
import { categoryOf } from "@/lib/categories";
import { SeverityBadge } from "@/components/ui/primitives";
import { cn } from "@/lib/utils";

const SEVS = ["critical", "high", "medium", "low"] as const;
const GROUPS = [
  { key: "none", label: "Flat" },
  { key: "category", label: "By category" },
  { key: "asset", label: "By asset" },
  { key: "tool", label: "By tool" },
] as const;
type GroupKey = (typeof GROUPS)[number]["key"];

// assetKey reduces a finding's endpoint to the thing a human thinks of as "the asset" — a
// URL's host, or the raw endpoint/tool when it isn't a URL (repo path, image, IP).
function assetKey(f: Finding): string {
  const ep = f.endpoint?.trim();
  if (!ep) return "(no location)";
  try {
    return new URL(ep).host;
  } catch {
    return ep.split(/[?#]/)[0].split("/").slice(0, 3).join("/") || ep;
  }
}

function frameworkCount(f: Finding): number {
  return f.compliance ? Object.keys(f.compliance).length : 0;
}

export function FindingsTable({ findings, pendingFindingIds = [] }: { findings: Finding[]; pendingFindingIds?: string[] }) {
  const [q, setQ] = useState("");
  const [active, setActive] = useState<Set<string>>(new Set());
  const [group, setGroup] = useState<GroupKey>("none");
  const [verifiedOnly, setVerifiedOnly] = useState(false);
  const pending = useMemo(() => new Set(pendingFindingIds), [pendingFindingIds]);

  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const f of findings) c[f.severity] = (c[f.severity] ?? 0) + 1;
    return c;
  }, [findings]);

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return findings
      .filter((f) => active.size === 0 || active.has(f.severity))
      .filter((f) => !verifiedOnly || f.verification_status === "verified")
      .filter((f) => !needle || `${f.title} ${f.endpoint ?? ""} ${f.tool} ${f.rule_id}`.toLowerCase().includes(needle))
      .sort((a, b) => (sevRank[a.severity] ?? 9) - (sevRank[b.severity] ?? 9));
  }, [findings, q, active, verifiedOnly]);

  // group the filtered rows; "none" → a single unlabeled group preserving severity order.
  const grouped = useMemo(() => {
    if (group === "none") return [{ key: "", rows }] as { key: string; rows: Finding[] }[];
    const m = new Map<string, Finding[]>();
    for (const f of rows) {
      const k = group === "asset" ? assetKey(f) : group === "category" ? categoryOf(f) : f.tool;
      (m.get(k) ?? m.set(k, []).get(k)!).push(f);
    }
    return [...m.entries()]
      .sort((a, b) => b[1].length - a[1].length)
      .map(([key, rs]) => ({ key, rows: rs }));
  }, [rows, group]);

  function toggle(s: string) {
    setActive((prev) => {
      const next = new Set(prev);
      next.has(s) ? next.delete(s) : next.add(s);
      return next;
    });
  }

  const pendingShown = rows.filter((f) => pending.has(f.id)).length;

  return (
    <div className="space-y-3">
      {/* Agent callout — ties the findings list to the human-in-the-loop gate */}
      {pendingShown > 0 && (
        <Link
          href="/inbox"
          className="flex items-center gap-2.5 rounded-lg border border-accent/30 bg-accent-soft/40 px-3.5 py-2.5 text-sm transition hover:border-accent/50"
        >
          <Wrench className="h-4 w-4 shrink-0 text-accent" />
          <span className="text-ink">
            The agent has prepared a fix for <strong>{pendingShown}</strong> of these — awaiting your approval.
          </span>
          <ChevronRight className="ml-auto h-4 w-4 text-accent" />
        </Link>
      )}

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

        {/* Verified-only toggle — surfaces the grounding/confidence signal as a filter */}
        <button
          onClick={() => setVerifiedOnly((v) => !v)}
          className={cn(
            "flex items-center gap-1 rounded-md border px-2 py-1 text-xs transition",
            verifiedOnly ? "border-pulse/50 bg-pulse/10 text-pulse" : "border-border bg-surface text-muted hover:border-border-strong",
          )}
          title="Show only findings actively confirmed by a tool (not pattern-match only)"
        >
          <BadgeCheck className="h-3.5 w-3.5" /> Verified
        </button>

        <div className="relative ml-1 flex-1 sm:max-w-[14rem]">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-faint" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search findings…"
            className="w-full rounded-lg border border-border bg-surface py-1.5 pl-8 pr-3 text-sm outline-none transition focus:border-accent"
          />
        </div>

        {/* Group-by segmented control */}
        <div className="flex items-center rounded-lg border border-border bg-surface p-0.5">
          {GROUPS.map((g) => (
            <button
              key={g.key}
              onClick={() => setGroup(g.key)}
              className={cn(
                "rounded-md px-2 py-1 text-xs transition",
                group === g.key ? "bg-accent-soft text-accent" : "text-muted hover:text-ink",
              )}
            >
              {g.label}
            </button>
          ))}
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

      {/* Table(s) */}
      {rows.length === 0 ? (
        <div className="card px-5 py-10 text-center text-sm text-muted">
          {findings.length === 0 ? "No open findings." : "No findings match your filter."}
        </div>
      ) : (
        <div className="space-y-3">
          {grouped.map((grp) => (
            <div key={grp.key || "all"} className="card p-0">
              {grp.key && (
                <div className="flex items-center gap-2 border-b border-border px-5 py-2.5">
                  <span className="mono truncate text-xs font-medium text-ink">{grp.key}</span>
                  <span className="rounded-full bg-surface-2 px-2 py-0.5 text-[11px] text-faint">{grp.rows.length}</span>
                </div>
              )}
              <table className="w-full">
                <thead>
                  <tr className="border-b border-border text-left text-[11px] uppercase tracking-wide text-faint">
                    <th className="py-2.5 pl-5 pr-2 font-medium">Severity</th>
                    <th className="px-2 py-2.5 font-medium">Finding</th>
                    {group !== "asset" && <th className="px-2 py-2.5 font-medium">Where</th>}
                    <th className="px-2 py-2.5 font-medium">Status</th>
                    <th className="py-2.5 pr-5 font-medium" />
                  </tr>
                </thead>
                <tbody>
                  {grp.rows.map((f) => (
                    <tr key={f.id} className="group border-b border-border last:border-0 transition hover:bg-surface-2">
                      <td className="py-2.5 pl-5 pr-2 align-top">
                        <SeverityBadge severity={f.severity} />
                      </td>
                      <td className="max-w-0 px-2 py-2.5 align-top">
                        <Link href={`/findings/${f.id}`} className="block truncate text-sm hover:text-accent">
                          {f.title}
                        </Link>
                        <div className="mt-1 flex flex-wrap items-center gap-1.5">
                          <span className="mono text-[11px] text-faint">{f.tool}</span>
                          {frameworkCount(f) > 0 && (
                            <span className="inline-flex items-center gap-1 rounded bg-surface-2 px-1.5 py-0.5 text-[10px] text-muted">
                              <FileCheck2 className="h-3 w-3" /> {frameworkCount(f)} frameworks
                            </span>
                          )}
                        </div>
                      </td>
                      {group !== "asset" && (
                        <td className="max-w-[14rem] px-2 py-2.5 align-top">
                          <span className="mono block truncate text-xs text-faint">{f.endpoint || "—"}</span>
                        </td>
                      )}
                      <td className="px-2 py-2.5 align-top">
                        <StatusCell f={f} pending={pending.has(f.id)} />
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
            </div>
          ))}
        </div>
      )}

      <p className="text-[11px] text-faint">
        {rows.length} of {findings.length} findings{verifiedOnly ? " · verified only" : ""}
        {group !== "none" ? ` · ${grouped.length} groups` : ""}
      </p>
    </div>
  );
}

// StatusCell shows, in priority order: a queued fix awaiting approval (the agentic signal),
// then the grounding/verification state. Both are real fields — never invented.
function StatusCell({ f, pending }: { f: Finding; pending: boolean }) {
  if (pending) {
    return (
      <Link href="/inbox" className="inline-flex items-center gap-1 rounded-full bg-accent-soft px-2 py-0.5 text-[11px] font-medium text-accent ring-1 ring-accent/30 transition hover:ring-accent/50">
        <Wrench className="h-3 w-3" /> Fix ready
      </Link>
    );
  }
  const vs = f.verification_status;
  if (vs === "verified") {
    return (
      <span className="inline-flex items-center gap-1 text-[11px] font-medium text-pulse">
        <BadgeCheck className="h-3.5 w-3.5" /> Verified
      </span>
    );
  }
  if (vs === "corroborated") {
    return (
      <span className="inline-flex items-center gap-1 text-[11px] text-muted">
        <ShieldCheck className="h-3.5 w-3.5" /> Corroborated
      </span>
    );
  }
  return <span className="text-[11px] text-faint">{typeof f.confidence === "number" ? `${Math.round(f.confidence * 100)}% conf.` : "Detected"}</span>;
}
