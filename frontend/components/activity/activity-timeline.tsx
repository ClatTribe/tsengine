"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { ShieldAlert, Wrench, ScanLine, Inbox } from "lucide-react";
import { SeverityBadge } from "@/components/ui/primitives";
import { timeAgo, cn } from "@/lib/utils";

export type ActivityKind = "detected" | "resolved" | "scanned" | "queued";

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
  { key: "resolved", label: "Resolved" },
  { key: "scanned", label: "Scanned" },
];

const ICON: Record<ActivityKind, { Icon: typeof ShieldAlert; cls: string }> = {
  detected: { Icon: ShieldAlert, cls: "text-high bg-high/10 border-high/30" },
  queued: { Icon: Inbox, cls: "text-accent bg-accent-soft border-accent/30" },
  resolved: { Icon: Wrench, cls: "text-pulse bg-pulse/10 border-pulse/30" },
  scanned: { Icon: ScanLine, cls: "text-muted bg-surface-2 border-border" },
};

// The full agent-activity timeline: everything the agent did, newest first, grouped by
// day, filterable by kind. The page is server-rendered (force-dynamic) and the topbar's
// live SSE connection calls router.refresh() on change — so this updates in real time.
export function ActivityTimeline({ events }: { events: ActivityEvent[] }) {
  const [active, setActive] = useState<Set<ActivityKind>>(new Set());

  const counts = useMemo(() => {
    const c = {} as Record<ActivityKind, number>;
    for (const e of events) c[e.kind] = (c[e.kind] ?? 0) + 1;
    return c;
  }, [events]);

  const visible = useMemo(
    () => (active.size === 0 ? events : events.filter((e) => active.has(e.kind))),
    [events, active],
  );

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
      {/* Filter chips */}
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
      </div>

      {visible.length === 0 ? (
        <div className="rounded-lg border border-dashed border-border px-4 py-10 text-center text-sm text-muted">
          {events.length === 0 ? "No activity yet — connect a system to put the agent to work." : "Nothing matches that filter."}
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
  resolved: "bg-pulse",
  scanned: "bg-muted",
};
