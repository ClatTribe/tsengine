import { Scale, Sparkles, ShieldCheck } from "lucide-react";
import { api } from "@/lib/api";
import type { Risk } from "@/lib/types";
import { Empty } from "@/components/ui/primitives";
import { PageIntro } from "@/components/ui/page-intro";
import { DecideRisk } from "@/components/risks/decide-risk";
import { CapacityBadge } from "@/components/ui/capacity-badge";
import { hitlOwner, capitalize } from "@/lib/service-model";
import { seedRisks } from "./actions";

export const dynamic = "force-dynamic";

const LEVEL_TONE: Record<string, string> = {
  critical: "text-critical bg-critical/10 border-critical/30",
  high: "text-high bg-high/10 border-high/30",
  medium: "text-medium bg-medium/10 border-medium/30",
  low: "text-muted bg-surface-2 border-border",
};
const STATUS_TONE: Record<string, string> = {
  accepted: "text-pulse", treating: "text-accent", closed: "text-faint", open: "text-high",
};

function level(r: Risk): string {
  const s = clamp(r.likelihood) * clamp(r.impact);
  if (s >= 20) return "critical";
  if (s >= 12) return "high";
  if (s >= 6) return "medium";
  return "low";
}
function clamp(n: number) {
  return Math.max(1, Math.min(5, n || 1));
}
function score(r: Risk) {
  return clamp(r.likelihood) * clamp(r.impact);
}

export default async function RisksPage() {
  const [{ risks, summary }, practitioners] = await Promise.all([api.risks(), api.practitioners()]);
  const { selfOwned, actor } = hitlOwner(practitioners?.service_model, practitioners?.practitioners?.[0]);
  const proposed = risks.filter((r) => r.proposed);
  const decided = risks.filter((r) => !r.proposed);

  // Service model: the vCISO judgment (accept/mitigate/transfer/avoid) is a HITL act. self_serve owns it;
  // managed/msp = the named expert owns it (via /operator), so this page reads informationally for them.
  const description = selfOwned
    ? "The judgment layer a vCISO owns. The agent proposes candidate risks from what it found; you — a named person — decide how to treat each one (accept, mitigate, transfer, or avoid). Every decision is signed into a tamper-evident ledger."
    : `The judgment layer your vCISO owns. The agent proposes candidate risks from what it found; ${actor} — a named person — decides how to treat each one (accept, mitigate, transfer, or avoid). Every decision is signed into a tamper-evident ledger. You can follow the calls here.`;

  return (
    <div className="space-y-6">
      <PageIntro
        icon={Scale}
        title="Risk register"
        description={description}
        right={
          <div className="flex gap-4 text-sm">
            <Stat n={summary.accepted} label="accepted" tone="text-pulse" />
            <Stat n={summary.treating} label="treating" tone="text-accent" />
            <Stat n={summary.proposed} label="to triage" tone="text-high" />
          </div>
        }
      />

      {/* Propose from findings — the grounded, agent-side half. self_serve drives it; for managed/msp the
          expert seeds + decides via the operator console, so this reads as an informational note instead. */}
      {selfOwned ? (
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-border bg-surface px-4 py-3">
          <div className="flex items-center gap-2.5 text-sm text-muted">
            <Sparkles className="h-4 w-4 text-accent" />
            Let the agent propose candidate risks from your current high-severity findings — grounded in real evidence, never invented.
          </div>
          <form action={seedRisks}>
            <button className="inline-flex items-center gap-1.5 rounded-lg border border-accent/40 px-3 py-1.5 text-sm font-medium text-accent transition hover:bg-accent-soft">
              Propose from findings
            </button>
          </form>
        </div>
      ) : (
        <div className="flex items-center gap-2.5 rounded-xl border border-border bg-surface px-4 py-3 text-sm text-muted">
          <Sparkles className="h-4 w-4 text-accent" />
          {capitalize(actor)} proposes and triages these risks for you. You can review every call below.
        </div>
      )}

      <section>
        <SubHead>Awaiting your decision · {proposed.length}</SubHead>
        {proposed.length === 0 ? (
          <Empty>No candidate risks to triage. Click &ldquo;Propose from findings&rdquo; to seed from your latest scan.</Empty>
        ) : (
          <div className="space-y-2">
            {proposed.map((r) => (
              <RiskRow key={r.id} r={r} />
            ))}
          </div>
        )}
      </section>

      <section>
        <SubHead>Decided · {decided.length}</SubHead>
        {decided.length === 0 ? (
          <Empty>No decisions recorded yet. A decided risk shows its treatment, owner, and ledger reference.</Empty>
        ) : (
          <div className="space-y-2">
            {decided.map((r) => (
              <RiskRow key={r.id} r={r} />
            ))}
          </div>
        )}
      </section>
    </div>
  );
}

function RiskRow({ r }: { r: Risk }) {
  const lv = level(r);
  return (
    <div className="card px-4 py-3">
      <div className="flex flex-wrap items-center gap-2.5">
        <span className={`inline-flex items-center rounded-md border px-1.5 py-0.5 text-[11px] font-semibold capitalize ${LEVEL_TONE[lv]}`}>
          {lv} · {score(r)}
        </span>
        <span className="text-sm font-semibold">{r.title}</span>
        {r.category && <span className="rounded bg-surface-2 px-1.5 py-0.5 text-[10px] text-faint">{r.category}</span>}
        <span className="mono ml-auto text-[11px] text-faint">L{clamp(r.likelihood)} × I{clamp(r.impact)}</span>
      </div>
      {r.description && <p className="mt-1.5 text-xs text-muted">{r.description}</p>}

      <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-faint">
        {r.finding_ids && r.finding_ids.length > 0 && <span>cites {r.finding_ids.length} finding{r.finding_ids.length === 1 ? "" : "s"}</span>}
        {!r.proposed && (
          <>
            <span className={`font-medium capitalize ${STATUS_TONE[r.status] ?? "text-muted"}`}>{r.status}</span>
            {r.treatment && <span className="capitalize">treatment: {r.treatment}</span>}
            {r.owner && <span>owner: {r.owner}</span>}
            <CapacityBadge capacity={r.capacity} firm={r.firm} />
            {r.ledger_ref && (
              <span className="inline-flex items-center gap-1 text-pulse">
                <ShieldCheck className="h-3 w-3" /> signed
              </span>
            )}
          </>
        )}
      </div>
      {r.rationale && <p className="mt-1.5 rounded-lg bg-surface-2/60 px-2.5 py-1.5 text-xs text-muted">&ldquo;{r.rationale}&rdquo;</p>}

      <div className="mt-2">
        <DecideRisk id={r.id} decided={!r.proposed} />
      </div>
    </div>
  );
}

function SubHead({ children }: { children: React.ReactNode }) {
  return <h2 className="mb-3 text-xs font-medium uppercase tracking-wider text-muted">{children}</h2>;
}

function Stat({ n, label, tone }: { n: number | string; label: string; tone: string }) {
  return (
    <div className="text-right">
      <span className={`text-xl font-semibold ${tone}`}>{n}</span> <span className="text-xs text-faint">{label}</span>
    </div>
  );
}
