import { Filter } from "lucide-react";

type Funnel = {
  raw_findings: number;
  excluded: number;
  deduped: number;
  suppressed: number;
  actionable_issues: number;
  auto_triaged: number;
  auto_triage_rate: number;
};

// TriageFunnel is the quantified "how much noise the engine removed automatically" card — the
// deterministic analogue of the funnel a scaling security team publishes ("71% auto-triaged").
// Of all raw findings: excluded by rules + collapsed as duplicates + suppressed → the rest are
// the actionable issues a human triages.
export function TriageFunnel({ f }: { f: Funnel }) {
  if (f.raw_findings === 0) return null;
  const pct = Math.round(f.auto_triage_rate * 100);

  // The stacked bar segments (as % of raw findings).
  const seg = (n: number) => (n / f.raw_findings) * 100;
  const segments = [
    { label: "Excluded by rules", n: f.excluded, cls: "bg-faint/50" },
    { label: "Duplicates merged", n: f.deduped, cls: "bg-accent/50" },
    { label: "Suppressed", n: f.suppressed, cls: "bg-medium/50" },
  ].filter((s) => s.n > 0);
  // The raw findings behind the actionable issues a human still triages.
  const actionableRaw = f.raw_findings - f.auto_triaged;

  return (
    <div className="card p-5">
      <div className="flex items-start justify-between gap-4">
        <div className="flex items-start gap-3">
          <span className="mt-0.5 grid h-9 w-9 shrink-0 place-items-center rounded-xl bg-accent-soft text-accent">
            <Filter className="h-4 w-4" />
          </span>
          <div>
            <div className="text-sm font-semibold">Auto-triage</div>
            <p className="mt-0.5 max-w-md text-xs text-muted">
              The engine handled <span className="text-ink">{f.auto_triaged}</span> of{" "}
              <span className="text-ink">{f.raw_findings}</span> raw findings automatically — so you only triage what's real.
            </p>
          </div>
        </div>
        <div className="shrink-0 text-right">
          <div className="text-2xl font-semibold text-pulse">{pct}%</div>
          <div className="text-[11px] text-faint">auto-triaged</div>
        </div>
      </div>

      {/* Stacked funnel bar: auto-handled segments + the actionable remainder. */}
      <div className="mt-4 flex h-2.5 w-full overflow-hidden rounded-full bg-surface-2">
        {segments.map((s) => (
          <div key={s.label} className={s.cls} style={{ width: `${seg(s.n)}%` }} title={`${s.label}: ${s.n}`} />
        ))}
        <div className="bg-high/60" style={{ width: `${seg(actionableRaw)}%` }} title={`Actionable: ${actionableRaw}`} />
      </div>

      {/* Legend / breakdown. */}
      <div className="mt-3 flex flex-wrap gap-x-5 gap-y-1.5 text-xs">
        {f.excluded > 0 && <Leg dot="bg-faint/60" label="Excluded by rules" n={f.excluded} />}
        {f.deduped > 0 && <Leg dot="bg-accent/60" label="Duplicates merged" n={f.deduped} />}
        {f.suppressed > 0 && <Leg dot="bg-medium/60" label="Suppressed" n={f.suppressed} />}
        <Leg dot="bg-high/70" label="Actionable issues" n={f.actionable_issues} strong />
      </div>
    </div>
  );
}

function Leg({ dot, label, n, strong }: { dot: string; label: string; n: number; strong?: boolean }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className={`h-2 w-2 rounded-full ${dot}`} />
      <span className={strong ? "text-ink" : "text-muted"}>
        {label} <span className="font-medium">{n}</span>
      </span>
    </span>
  );
}
