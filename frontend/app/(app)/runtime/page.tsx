import { Shield, ShieldCheck, Eye } from "lucide-react";
import { api } from "@/lib/api";
import { Empty } from "@/components/ui/primitives";
import { PageIntro } from "@/components/ui/page-intro";

export const dynamic = "force-dynamic";

export default async function ProtectPage() {
  const p = await api.protect();
  const kinds = p.by_attack_kind ?? [];
  const endpoints = p.top_endpoints ?? [];
  const pct = Math.round(p.block_rate * 100);

  return (
    <div className="space-y-5">
      <PageIntro
        icon={Shield}
        title="Runtime protection"
        description="What your in-app firewall (Zen) is stopping in production, in real time — attacks blocked at the sink, before they reach a database or a sensitive action. We surface and correlate the sensor's signal; the sensor does the blocking."
      />

      {!p.active ? (
        <Empty>
          No runtime signal yet — install the Zen in-app firewall in your app and its blocked/monitored attacks
          show up here, folded into your incidents.
        </Empty>
      ) : (
        <>
          {/* posture stat row */}
          <div className="grid gap-3 sm:grid-cols-4">
            <Stat label="Attacks blocked" value={p.blocked} tone="pulse" icon={ShieldCheck} />
            <Stat label="Block rate" value={`${pct}%`} tone={pct > 0 ? "pulse" : "muted"} icon={ShieldCheck} />
            <Stat label="Monitor-only" value={p.monitor_only} tone={p.monitor_only > 0 ? "high" : "muted"} icon={Eye} />
            <Stat label="Apps protected" value={p.apps.length} tone="ink" icon={Shield} />
          </div>
          {pct === 0 && p.total_attacks > 0 && (
            <div className="card flex items-center gap-3 px-4 py-3 text-sm">
              <Eye className="h-4 w-4 shrink-0 text-high" />
              <span className="text-muted">
                The sensor is in <span className="font-medium text-ink">monitor mode</span> — it&apos;s observing attacks
                but not blocking them. Switch it to blocking mode to stop these at runtime.
              </span>
            </div>
          )}

          <div className="grid gap-4 lg:grid-cols-2">
            {/* by attack kind */}
            <div className="card p-5">
              <h3 className="text-sm font-semibold">Attacks by type</h3>
              <div className="mt-3 space-y-2">
                {kinds.length === 0 ? (
                  <p className="text-sm text-muted">No attacks observed.</p>
                ) : (
                  kinds.map((k) => (
                    <div key={k.kind} className="flex items-center justify-between text-sm">
                      <span className="mono text-ink">{k.kind}</span>
                      <span className="text-muted">
                        <span className="font-medium text-pulse">{k.blocked}</span> blocked
                        {k.count - k.blocked > 0 && <span className="text-high"> · {k.count - k.blocked} monitored</span>}
                      </span>
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* top targeted endpoints */}
            <div className="card p-5">
              <h3 className="text-sm font-semibold">Most-targeted endpoints</h3>
              <div className="mt-3 space-y-2">
                {endpoints.length === 0 ? (
                  <p className="text-sm text-muted">No targeted endpoints.</p>
                ) : (
                  endpoints.map((e) => (
                    <div key={e.endpoint} className="flex items-center justify-between gap-3 text-sm">
                      <span className="mono truncate text-ink">{e.endpoint}</span>
                      <span className="shrink-0 text-muted">
                        {e.count} hit{e.count === 1 ? "" : "s"} · <span className="text-pulse">{e.blocked} blocked</span>
                      </span>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>

          <p className="text-xs text-faint">
            Sensor{p.sensors.length === 1 ? "" : "s"}: {p.sensors.join(", ") || "—"}. Blocking happens in your app; we
            surface and correlate it into incidents.
          </p>
        </>
      )}
    </div>
  );
}

function Stat({ label, value, tone, icon: Icon }: { label: string; value: number | string; tone: "pulse" | "high" | "ink" | "muted"; icon: typeof Shield }) {
  const color = tone === "pulse" ? "text-pulse" : tone === "high" ? "text-high" : tone === "muted" ? "text-muted" : "text-ink";
  return (
    <div className="card p-4">
      <div className="flex items-center gap-2 text-xs text-faint">
        <Icon className={`h-3.5 w-3.5 ${color}`} /> {label}
      </div>
      <div className={`mt-1 text-2xl font-semibold ${color}`}>{value}</div>
    </div>
  );
}
