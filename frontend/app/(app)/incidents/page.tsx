import { ShieldAlert, CheckCircle2 } from "lucide-react";
import { api } from "@/lib/api";
import type { Incident } from "@/lib/types";
import { SeverityBadge, Empty } from "@/components/ui/primitives";
import { timeAgo, duration } from "@/lib/utils";

export const dynamic = "force-dynamic";

export default async function IncidentsPage() {
  const all = await api.incidents("all");
  const open = all.filter((i) => i.status === "open").sort(byTime("opened_at"));
  const resolved = all.filter((i) => i.status === "resolved").sort(byTime("resolved_at"));

  return (
    <div className="space-y-6">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-lg font-semibold">Incidents</h1>
          <p className="text-xs text-muted">The agent watches continuously — here&apos;s what changed.</p>
        </div>
        <div className="flex gap-4 text-sm">
          <Stat n={open.length} label="open" tone="text-high" />
          <Stat n={resolved.length} label="resolved" tone="text-pulse" />
        </div>
      </div>

      <section>
        <SubHead>Open · needs attention</SubHead>
        {open.length === 0 ? (
          <Empty>No open incidents — nothing has broken since the last pass.</Empty>
        ) : (
          <Timeline>
            {open.map((i) => (
              <Node key={i.id} incident={i} resolved={false} />
            ))}
          </Timeline>
        )}
      </section>

      <section>
        <SubHead>Resolved · the agent&apos;s wins</SubHead>
        {resolved.length === 0 ? (
          <Empty>No resolved incidents yet.</Empty>
        ) : (
          <Timeline>
            {resolved.slice(0, 25).map((i) => (
              <Node key={i.id} incident={i} resolved />
            ))}
          </Timeline>
        )}
      </section>
    </div>
  );
}

function byTime(field: "opened_at" | "resolved_at") {
  return (a: Incident, b: Incident) => new Date(b[field] ?? 0).getTime() - new Date(a[field] ?? 0).getTime();
}

function SubHead({ children }: { children: React.ReactNode }) {
  return <h2 className="mb-3 text-xs font-medium uppercase tracking-wider text-muted">{children}</h2>;
}

function Stat({ n, label, tone }: { n: number; label: string; tone: string }) {
  return (
    <div className="text-right">
      <span className={`text-xl font-semibold ${tone}`}>{n}</span> <span className="text-xs text-faint">{label}</span>
    </div>
  );
}

function Timeline({ children }: { children: React.ReactNode }) {
  return <ol className="relative space-y-2 border-l border-border pl-5">{children}</ol>;
}

function Node({ incident: i, resolved }: { incident: Incident; resolved: boolean }) {
  const Icon = resolved ? CheckCircle2 : ShieldAlert;
  return (
    <li className="animate-fade-rise">
      <span
        className={`absolute -left-[9px] grid h-4 w-4 place-items-center rounded-full border-2 border-bg ${
          resolved ? "bg-pulse" : "bg-high"
        }`}
      />
      <div className="card flex items-center gap-3 px-4 py-3">
        <Icon className={`h-4 w-4 shrink-0 ${resolved ? "text-pulse" : "text-high"}`} />
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <SeverityBadge severity={i.severity} className="scale-90" />
            <span className="truncate text-sm">{i.title}</span>
          </div>
          <div className="mono mt-0.5 truncate text-[11px] text-faint">{i.rule_id}</div>
        </div>
        <div className="shrink-0 text-right text-xs">
          {resolved ? (
            <>
              <div className="text-pulse">fixed {timeAgo(i.resolved_at)}</div>
              <div className="text-faint">open for {duration(i.opened_at, i.resolved_at)}</div>
            </>
          ) : (
            <div className="text-muted">detected {timeAgo(i.opened_at)}</div>
          )}
        </div>
      </div>
    </li>
  );
}
