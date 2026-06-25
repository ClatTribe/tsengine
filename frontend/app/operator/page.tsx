import { redirect } from "next/navigation";
import { UserCog, Scale, FileCheck2, Crosshair, ScrollText, LogOut } from "lucide-react";
import { getOperatorToken, operatorMe, operatorQueue, type QueueItem } from "@/lib/operator";
import { operatorLogout } from "./actions";
import { DecideRiskInline } from "@/components/operator/decide-risk-inline";

export const dynamic = "force-dynamic";
export const metadata = { title: "Practitioner console | TensorShield" };

const KIND_ICON: Record<string, typeof Scale> = { risk: Scale, audit: FileCheck2, pentest: Crosshair, policy: ScrollText };
const KIND_LABEL: Record<string, string> = { risk: "Risk decision", audit: "Control attestation", pentest: "Report sign-off", policy: "Policy publish" };

export default async function OperatorConsole() {
  if (!(await getOperatorToken())) redirect("/operator/login");
  const [me, queue] = await Promise.all([operatorMe(), operatorQueue()]);
  if (!me || !queue) redirect("/operator/login");

  // group the cross-tenant items by client tenant
  const byTenant = new Map<string, QueueItem[]>();
  for (const it of queue.items) {
    byTenant.set(it.tenant_name, [...(byTenant.get(it.tenant_name) ?? []), it]);
  }
  const tenants = [...byTenant.keys()].sort();

  return (
    <main className="mx-auto min-h-screen max-w-4xl px-5 py-10">
      <header className="mb-8 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <span className="grid h-10 w-10 place-items-center rounded-xl border border-accent/40 bg-accent-soft text-accent">
            <UserCog className="h-5 w-5" />
          </span>
          <div>
            <h1 className="text-lg font-semibold tracking-tight">Practitioner console</h1>
            <p className="text-xs text-muted">
              {me.name || me.email}
              {me.firm ? ` · ${me.firm}` : ""}
            </p>
          </div>
        </div>
        <form action={operatorLogout}>
          <button className="inline-flex items-center gap-1.5 rounded-lg border border-border px-3 py-1.5 text-xs text-muted transition hover:text-ink">
            <LogOut className="h-3.5 w-3.5" /> Sign out
          </button>
        </form>
      </header>

      {/* summary */}
      <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Stat n={queue.count} label="items awaiting you" tone="text-high" />
        <Stat n={queue.tenants_served} label="client tenants" />
        <Stat n={queue.by_kind.risk ?? 0} label="risk decisions" />
        <Stat n={(queue.by_kind.pentest ?? 0) + (queue.by_kind.audit ?? 0)} label="attest / sign-off" />
      </div>

      {queue.items.length === 0 ? (
        <div className="card p-8 text-center text-sm text-muted">
          Nothing awaiting your judgment right now. Items appear here when a client&apos;s risk needs a decision, a
          control needs attestation, a pentest report needs sign-off, or a policy needs publishing.
        </div>
      ) : (
        <div className="space-y-5">
          {tenants.map((tn) => (
            <section key={tn}>
              <h2 className="mb-2 text-xs font-medium uppercase tracking-wider text-muted">{tn}</h2>
              <div className="space-y-2">
                {byTenant.get(tn)!.map((it, i) => {
                  const Icon = KIND_ICON[it.kind] ?? Scale;
                  return (
                    <div key={`${it.tenant_id}-${i}`} className="card px-4 py-3">
                      <div className="flex items-center gap-3">
                        <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-surface-2 text-accent">
                          <Icon className="h-4 w-4" />
                        </span>
                        <div className="min-w-0 flex-1">
                          <div className="text-sm font-medium">{it.title}</div>
                          <div className="text-[11px] text-faint">
                            {KIND_LABEL[it.kind] ?? it.kind}
                            {it.detail ? ` · ${it.detail}` : ""}
                          </div>
                        </div>
                      </div>
                      {/* act-on-behalf: decide a risk right here. Other HITL kinds open in the client workspace. */}
                      {it.kind === "risk" && it.item_id ? (
                        <DecideRiskInline tenant={it.tenant_id} risk={it.item_id} />
                      ) : null}
                    </div>
                  );
                })}
              </div>
            </section>
          ))}
          <p className="pt-2 text-center text-[11px] text-faint">
            Decide risks right here — your decision is recorded with your name + capacity and signed into the ledger.
            Attestations, sign-offs, and policy publishing open in the client&apos;s workspace. You only ever see the
            clients who named you a practitioner of record.
          </p>
        </div>
      )}
    </main>
  );
}

function Stat({ n, label, tone }: { n: number; label: string; tone?: string }) {
  return (
    <div className="card px-4 py-3 text-center">
      <div className={`text-xl font-semibold ${tone ?? "text-ink"}`}>{n}</div>
      <div className="text-[11px] text-faint">{label}</div>
    </div>
  );
}
