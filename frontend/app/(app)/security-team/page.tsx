import Link from "next/link";
import { Users, Scale, FileCheck2, ScrollText, Crosshair, Inbox, ArrowRight, Mail, BadgeCheck } from "lucide-react";
import { api } from "@/lib/api";
import { Card, Empty } from "@/components/ui/primitives";
import { PageIntro } from "@/components/ui/page-intro";
import { CapacityBadge } from "@/components/ui/capacity-badge";
import { hitlOwner, capitalize, SERVICE_MODEL_LABEL } from "@/lib/service-model";

export const dynamic = "force-dynamic";

// The HITL surfaces where this team's signed work actually shows up. Grounded links to real pages —
// NOT a fabricated activity feed (we don't invent acts the ledger doesn't hold).
const HANDLES = [
  { href: "/inbox", icon: Inbox, label: "Fix approvals", desc: "Reviews + approves each remediation before it applies" },
  { href: "/risks", icon: Scale, label: "Risk decisions", desc: "Accepts, mitigates, transfers, or avoids each risk" },
  { href: "/program", icon: ScrollText, label: "Policies", desc: "Publishes the policy set; your team acknowledges" },
  { href: "/audits", icon: FileCheck2, label: "Audit attestations", desc: "Renders each control verdict for the auditor" },
  { href: "/pentest", icon: Crosshair, label: "Pentest sign-off", desc: "Signs the exploitation-proven VAPT report" },
];

export default async function SecurityTeamPage() {
  const [{ service_model, practitioners }, team] = await Promise.all([api.practitioners(), api.team()]);
  const experts = practitioners ?? [];
  const { selfOwned, actor } = hitlOwner(service_model, experts[0]);

  const description = selfOwned
    ? "Your own team owns the human-in-the-loop. The agent does the work; the people below make the calls that matter — every decision signed to a tamper-evident ledger."
    : `${capitalize(actor)} runs your security & compliance — a named expert handles the human-in-the-loop judgment on your behalf, every decision signed and accountable. Here's who, and what they handle.`;

  return (
    <div className="space-y-6">
      <PageIntro icon={Users} title="Your security team" description={description} />

      {/* Managed / MSP — the named expert(s) of record. */}
      {!selfOwned &&
        (experts.length > 0 ? (
          <section>
            <div className="mb-2 text-xs font-semibold uppercase tracking-wider text-faint">Expert of record</div>
            <div className="grid gap-3 sm:grid-cols-2">
              {experts.map((p) => (
                <Card key={p.id} className="p-5">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-semibold text-ink">{p.name}</span>
                        <CapacityBadge capacity={p.capacity} firm={p.firm} />
                      </div>
                      {p.credential && <div className="mt-0.5 text-xs text-muted">{p.credential}</div>}
                      {p.firm && <div className="mt-0.5 text-xs text-muted">{p.firm}</div>}
                    </div>
                    <BadgeCheck className="h-5 w-5 shrink-0 text-pulse" />
                  </div>
                  {p.scope && p.scope.length > 0 && (
                    <div className="mt-3 flex flex-wrap gap-1.5">
                      {p.scope.map((s) => (
                        <span key={s} className="rounded-full border border-border bg-surface-2 px-2 py-0.5 text-[11px] text-muted">
                          {s}
                        </span>
                      ))}
                    </div>
                  )}
                  {p.email && (
                    <a href={`mailto:${p.email}`} className="mt-3 inline-flex items-center gap-1.5 text-xs font-medium text-accent hover:underline">
                      <Mail className="h-3.5 w-3.5" /> {p.email}
                    </a>
                  )}
                </Card>
              ))}
            </div>
          </section>
        ) : (
          // model is managed/msp but no named expert is on file yet — say so honestly, never invent one.
          <Card className="border-medium/40 bg-medium/5 p-5 text-sm">
            <div className="font-medium text-ink">No expert of record yet</div>
            <p className="mt-1 text-muted">
              Your service model is set to <strong>{SERVICE_MODEL_LABEL[service_model] ?? service_model}</strong>, but no named
              practitioner is on file. Add your expert in{" "}
              <Link href="/settings" className="text-accent hover:underline">Settings → Service model</Link> so every decision
              they make is attributed and signed.
            </p>
          </Card>
        ))}

      {/* Self-serve — the tenant's own people own the HITL. */}
      {selfOwned && (
        <section>
          <div className="mb-2 text-xs font-semibold uppercase tracking-wider text-faint">Your people</div>
          {team.length > 0 ? (
            <div className="grid gap-3 sm:grid-cols-2">
              {team.map((u) => (
                <Card key={u.id} className="flex items-center gap-3 p-4">
                  <span className="grid h-9 w-9 shrink-0 place-items-center rounded-full bg-accent-soft text-sm font-semibold text-accent">
                    {(u.name ?? u.email ?? "?").slice(0, 1).toUpperCase()}
                  </span>
                  <div className="min-w-0">
                    <div className="truncate text-sm font-medium text-ink">{u.name ?? u.email}</div>
                    <div className="truncate text-xs capitalize text-muted">
                      {u.role}
                      {u.name && u.email ? ` · ${u.email}` : ""}
                    </div>
                  </div>
                </Card>
              ))}
            </div>
          ) : (
            <Empty>Invite your team in Settings → Team so they can review and approve.</Empty>
          )}
          <div className="mt-4 rounded-xl border border-border bg-surface p-4 text-sm text-muted">
            No security hire?{" "}
            <Link href="/settings" className="font-medium text-accent hover:underline">Switch to a managed or MSP service model</Link>{" "}
            and a named expert handles the judgment calls for you.
          </div>
        </section>
      )}

      {/* What this team handles — grounded links to the HITL surfaces (not an invented activity feed). */}
      <section>
        <div className="mb-2 text-xs font-semibold uppercase tracking-wider text-faint">
          {selfOwned ? "What your team handles" : `What ${actor} handles for you`}
        </div>
        <div className="grid gap-2.5 sm:grid-cols-2">
          {HANDLES.map(({ href, icon: Icon, label, desc }) => (
            <Link key={href} href={href} className="card flex items-center gap-3 p-4 transition hover:border-accent/40">
              <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-accent-soft text-accent">
                <Icon className="h-4 w-4" />
              </span>
              <div className="min-w-0 flex-1">
                <div className="text-sm font-medium text-ink">{label}</div>
                <div className="text-xs text-muted">{desc}</div>
              </div>
              <ArrowRight className="h-4 w-4 shrink-0 text-faint" />
            </Link>
          ))}
        </div>
      </section>
    </div>
  );
}
