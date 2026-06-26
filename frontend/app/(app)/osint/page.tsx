import { Radar, ShieldAlert } from "lucide-react";
import { api } from "@/lib/api";
import { SeverityBadge, Empty } from "@/components/ui/primitives";
import { PageIntro } from "@/components/ui/page-intro";
import { FeatureIcon } from "@/components/brand/feature-icon";
import { ConfidencePill } from "@/components/findings/confidence-pill";
import { RunOsintScan } from "@/components/osint/run-scan";

export const dynamic = "force-dynamic";

// Maps an OSINT rule to a duotone class icon + a one-line "what it means".
const CLASS_META: Record<string, { icon: string; about: string }> = {
  "osint::stealer-log": { icon: "key", about: "Dark web: a corporate credential harvested by infostealer malware from an infected host — rotate it, revoke sessions, re-image the device." },
  "osint::breached-credential": { icon: "key", about: "A team email appears in a known breach — reset + confirm MFA." },
  "osint::leaked-secret": { icon: "lock", about: "A secret leaked in a public repo or paste — rotate immediately." },
  "osint::exposed-host": { icon: "network", about: "Internet-reachable infra that isn't monitored — add it or take it down." },
  "osint::data-exposure": { icon: "watch", about: "Org data found exposed publicly — confirm scope + breach duties." },
  "osint::typosquat-domain": { icon: "shield", about: "A look-alike domain imitating your brand — consider a takedown." },
  "osint::advisory": { icon: "alert", about: "A security advisory relevant to your stack — check if you're affected." },
};

export default async function OSINTPage() {
  const { total, summary, findings } = await api.osint();
  const order = ["critical", "high", "medium", "low", "info"];
  const sorted = [...findings].sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));

  return (
    <div className="space-y-8">
      <PageIntro
        icon={Radar}
        title="External exposure (OSINT)"
        description="The attacker's-eye view of your organization, pulled from open-source intelligence — leaked credentials, public secret leaks, forgotten internet-exposed hosts, look-alike phishing domains, and exposed data. Everything here feeds the same issues, attack paths, and compliance posture as your internal scans — and any exposed host we discover on your own domains is added to monitoring automatically, so the engine scans it next pass."
        right={<RunOsintScan />}
      />

      {total === 0 ? (
        <Empty>
          <div className="space-y-4">
            <p>
              No external exposure detected yet. Click <span className="font-medium text-ink">Run scan</span> above to
              sweep your domains right now (free, keyless Certificate-Transparency discovery — no setup) — breaches,
              leaks, exposed hosts, and look-alike domains will appear here and flow into your issues + compliance
              posture.
            </p>
            <RunOsintScan />
          </div>
        </Empty>
      ) : (
        <>
          <section className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
            {summary.map((s) => {
              const rule = Object.keys(CLASS_META).find((k) => labelFor(k) === s.label);
              const icon = rule ? CLASS_META[rule].icon : "shield";
              return (
                <div key={s.label} className="rounded-xl border border-border bg-surface p-4">
                  <span className="grid h-9 w-9 place-items-center rounded-lg bg-accent-soft text-accent">
                    <FeatureIcon name={icon} className="h-[18px] w-[18px]" />
                  </span>
                  <div className="mt-3 text-2xl font-semibold tracking-tight text-ink">{s.count}</div>
                  <div className="mt-0.5 text-xs text-muted">{s.label}</div>
                </div>
              );
            })}
          </section>

          <section className="card divide-y divide-border">
            {sorted.map((f) => {
              const meta = CLASS_META[f.rule_id];
              return (
                <div key={f.id} className="flex items-start gap-3 px-5 py-3.5">
                  <span className="mt-0.5 grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-accent-soft text-accent">
                    <FeatureIcon name={meta?.icon ?? "shield"} className="h-4 w-4" />
                  </span>
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-sm font-medium text-ink">{f.title}</span>
                      <SeverityBadge severity={f.severity} />
                      <ConfidencePill verification={f.verification_status} confidence={f.confidence} />
                    </div>
                    {f.description && <p className="mt-1 text-sm leading-relaxed text-muted">{f.description}</p>}
                    {f.endpoint && <div className="mono mt-1 truncate text-[11px] text-faint">{f.endpoint}</div>}
                  </div>
                </div>
              );
            })}
          </section>

          <p className="flex items-center gap-1.5 text-xs text-faint">
            <ShieldAlert className="h-3.5 w-3.5" /> Sourced from open-source intelligence (theHarvester, SpiderFoot,
            dnstwist, breach feeds, taranis-ai). Live collectors are credential-gated; a posted snapshot works today.
          </p>
        </>
      )}
    </div>
  );
}

function labelFor(rule: string): string {
  return (
    {
      "osint::breached-credential": "Breached credentials",
      "osint::leaked-secret": "Leaked secrets",
      "osint::exposed-host": "Exposed hosts",
      "osint::data-exposure": "Public data exposure",
      "osint::typosquat-domain": "Look-alike domains",
      "osint::advisory": "Relevant advisories",
    } as Record<string, string>
  )[rule] ?? "Other";
}
