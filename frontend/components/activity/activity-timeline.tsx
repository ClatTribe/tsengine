"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { ShieldAlert, Wrench, ScanLine, Inbox, Search, CheckCircle2, AlertTriangle } from "lucide-react";
import { SeverityBadge } from "@/components/ui/primitives";
import { timeAgo, cn } from "@/lib/utils";

export type ActivityKind = "detected" | "resolved" | "scanned" | "queued" | "verified" | "regressed";

export interface ActivityEvent {
  id: string;
  at: string;
  day: string; // server-computed bucket label (Today / Yesterday / Jun 16)
  kind: ActivityKind;
  title: string;
  meta?: string;
  severity?: string;
  href?: string;
}

const KINDS: { key: ActivityKind; label: string }[] = [
  { key: "detected", label: "Detected" },
  { key: "queued", label: "Queued" },
  { key: "verified", label: "Fix verified" },
  { key: "regressed", label: "Fix failed" },
  { key: "resolved", label: "Resolved" },
  { key: "scanned", label: "Scanned" },
];

const ICON: Record<ActivityKind, { Icon: typeof ShieldAlert; cls: string }> = {
  detected: { Icon: ShieldAlert, cls: "text-high bg-high/10 border-high/30" },
  queued: { Icon: Inbox, cls: "text-accent bg-accent-soft border-accent/30" },
  verified: { Icon: CheckCircle2, cls: "text-pulse bg-pulse/10 border-pulse/30" },
  regressed: { Icon: AlertTriangle, cls: "text-high bg-high/10 border-high/30" },
  resolved: { Icon: Wrench, cls: "text-pulse bg-pulse/10 border-pulse/30" },
  scanned: { Icon: ScanLine, cls: "text-muted bg-surface-2 border-border" },
};

// The full agent-activity timeline: everything the agent did, newest first, grouped by
// day, filterable by kind. The page is server-rendered (force-dynamic) and the topbar's
// live SSE connection calls router.refresh() on change — so this updates in real time.
export function ActivityTimeline({ events }: { events: ActivityEvent[] }) {
  const [active, setActive] = useState<Set<ActivityKind>>(new Set());
  const [query, setQuery] = useState("");

  const counts = useMemo(() => {
    const c = {} as Record<ActivityKind, number>;
    for (const e of events) c[e.kind] = (c[e.kind] ?? 0) + 1;
    return c;
  }, [events]);

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    return events.filter(
      (e) =>
        (active.size === 0 || active.has(e.kind)) &&
        (q === "" || e.title.toLowerCase().includes(q) || (e.meta ?? "").toLowerCase().includes(q)),
    );
  }, [events, active, query]);

  // preserve order, group by the server-computed day label
  const groups = useMemo(() => {
    const out: { day: string; items: ActivityEvent[] }[] = [];
    for (const e of visible) {
      const last = out[out.length - 1];
      if (last && last.day === e.day) last.items.push(e);
      else out.push({ day: e.day, items: [e] });
    }
    return out;
  }, [visible]);

  function toggle(k: ActivityKind) {
    setActive((prev) => {
      const next = new Set(prev);
      next.has(k) ? next.delete(k) : next.add(k);
      return next;
    });
  }

  return (
    <div className="space-y-5">
      {/* Filter chips + free-text search (so a growing log stays scannable) */}
      <div className="flex flex-wrap items-center gap-1.5">
        {KINDS.map(({ key, label }) => (
          <button
            key={key}
            onClick={() => toggle(key)}
            className={cn(
              "rounded-md border px-2 py-1 text-xs transition",
              active.has(key)
                ? "border-accent/50 bg-accent-soft text-accent"
                : "border-border bg-surface text-muted hover:border-border-strong",
            )}
          >
            {label} <span className="text-faint">{counts[key] ?? 0}</span>
          </button>
        ))}
        <div className="relative ml-auto">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-faint" />
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search activity…"
            aria-label="Search activity"
            className="w-44 rounded-md border border-border bg-surface py-1 pl-8 pr-2 text-xs text-ink outline-none transition focus:border-accent focus:w-56"
          />
        </div>
      </div>

      {visible.length === 0 ? (
        <div className="rounded-lg border border-dashed border-border px-4 py-10 text-center text-sm text-muted">
          {events.length === 0 ? "No activity yet — connect a system to put the agent to work." : "Nothing matches your filter or search."}
        </div>
      ) : (
        <div className="space-y-6">
          {groups.map((g) => (
            <section key={g.day}>
              <h2 className="mb-3 text-[11px] font-medium uppercase tracking-wider text-faint">{g.day}</h2>
              <ol className="relative space-y-2 border-l border-border pl-5">
                {g.items.map((e) => (
                  <Node key={e.id} event={e} />
                ))}
              </ol>
            </section>
          ))}
        </div>
      )}
    </div>
  );
}

function Node({ event: e }: { event: ActivityEvent }) {
  const { Icon, cls } = ICON[e.kind];
  const body = (
    <div className="card flex items-center gap-3 px-4 py-3 transition group-hover:border-border-strong">
      <span className={cn("grid h-7 w-7 shrink-0 place-items-center rounded-lg border", cls)}>
        <Icon className="h-3.5 w-3.5" />
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          {e.severity && <SeverityBadge severity={e.severity} className="scale-90" />}
          <span className="truncate text-sm">{e.title}</span>
        </div>
        {e.meta && <div className="mono mt-0.5 truncate text-[11px] text-faint">{e.meta}</div>}
      </div>
      <span className="shrink-0 text-xs text-faint">{timeAgo(e.at)}</span>
    </div>
  );
  return (
    <li className="group animate-fade-rise">
      <span className={cn("absolute -left-[5px] mt-4 h-2 w-2 rounded-full border-2 border-bg", DOT[e.kind])} />
      {e.href ? <Link href={e.href} className="block">{body}</Link> : body}
    </li>
  );
}

const DOT: Record<ActivityKind, string> = {
  detected: "bg-high",
  queued: "bg-accent",
  verified: "bg-pulse",
  regressed: "bg-high",
  resolved: "bg-pulse",
  scanned: "bg-muted",
};
