import { Gauge, Timer, CheckCircle2, Hourglass } from "lucide-react";
import type { SOCMetrics } from "@/lib/types";

// SOC-performance scorecard — the "how is the SOC performing" view (SLA compliance %, MTTA/MTTR,
// open-incident aging). Grounded entirely in incident timestamps. Hidden on a tenant with no
// incident history (nothing meaningful to score yet).
export function SOCScorecard({ m }: { m: SOCMetrics }) {
  if (m.open_incidents + m.resolved_incidents === 0) return null;

  const fmtH = (h: number) => (h <= 0 ? "—" : h < 1 ? `${Math.round(h * 60)}m` : h < 24 ? `${h}h` : `${(h / 24).toFixed(1)}d`);
  const complianceTone = m.sla_tracked === 0 ? "text-muted" : m.sla_compliance_pct >= 90 ? "text-pulse" : m.sla_compliance_pct >= 70 ? "text-medium" : "text-critical";

  return (
    <div className="card p-4">
      <div className="mb-3 flex items-center gap-2 text-xs font-medium uppercase tracking-wider text-muted">
        <Gauge className="h-3.5 w-3.5" /> SOC performance
      </div>
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Tile
          icon={CheckCircle2}
          label="SLA compliance"
          value={m.sla_tracked === 0 ? "n/a" : `${m.sla_compliance_pct}%`}
          tone={complianceTone}
          sub={m.sla_tracked === 0 ? "no SLA set" : `${m.sla_compliant}/${m.sla_tracked} in SLA`}
        />
        <Tile icon={Timer} label="Mean time to ack" value={fmtH(m.mtta_hours)} tone="text-ink" sub={`${m.acknowledged} acknowledged`} />
        <Tile icon={Timer} label="Mean time to resolve" value={fmtH(m.mttr_hours)} tone="text-ink" sub={`${m.resolved_incidents} resolved`} />
        <Tile
          icon={Hourglass}
          label="Open / breached"
          value={`${m.open_incidents}`}
          tone={m.sla_breached > 0 ? "text-critical" : "text-ink"}
          sub={m.sla_breached > 0 ? `${m.sla_breached} breaching SLA` : "none breaching"}
        />
      </div>
      {m.open_incidents > 0 && (
        <div className="mt-3 flex items-center gap-4 border-t border-border pt-3 text-[11px] text-muted">
          <span className="font-medium text-faint">Open incident age:</span>
          <Age label="< 1 day" n={m.aging_under_1d} tone="text-pulse" />
          <Age label="1–7 days" n={m.aging_1_7d} tone="text-medium" />
          <Age label="> 7 days" n={m.aging_over_7d} tone="text-critical" />
        </div>
      )}
    </div>
  );
}

function Tile({ icon: Icon, label, value, tone, sub }: { icon: typeof Gauge; label: string; value: string; tone: string; sub: string }) {
  return (
    <div className="rounded-lg border border-border bg-surface-2 px-3 py-2.5">
      <div className="flex items-center gap-1.5 text-[11px] text-faint">
        <Icon className="h-3 w-3" /> {label}
      </div>
      <div className={`mt-1 text-xl font-semibold ${tone}`}>{value}</div>
      <div className="text-[11px] text-muted">{sub}</div>
    </div>
  );
}

function Age({ label, n, tone }: { label: string; n: number; tone: string }) {
  return (
    <span className="inline-flex items-center gap-1">
      <span className={`font-semibold ${n > 0 ? tone : "text-faint"}`}>{n}</span>
      <span>{label}</span>
    </span>
  );
}
