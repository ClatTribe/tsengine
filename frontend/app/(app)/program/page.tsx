import { ScrollText, Sparkles, ShieldCheck, FileText } from "lucide-react";
import { api } from "@/lib/api";
import type { Policy } from "@/lib/types";
import { Empty } from "@/components/ui/primitives";
import { PageIntro } from "@/components/ui/page-intro";
import { PublishButton, AckButton } from "@/components/program/policy-actions";
import { seedProgram } from "./actions";

export const dynamic = "force-dynamic";

export default async function ProgramPage() {
  const [{ policies, summary }, me] = await Promise.all([api.program(), api.me()]);
  const myEmail = me?.email ?? "";

  // group by category for the register view
  const byCategory = new Map<string, Policy[]>();
  for (const p of policies) {
    const c = p.category || "Other";
    byCategory.set(c, [...(byCategory.get(c) ?? []), p]);
  }
  const categories = [...byCategory.keys()].sort();

  return (
    <div className="space-y-6">
      <PageIntro
        icon={ScrollText}
        title="Security program"
        description="The policy set a vCISO maintains. The agent seeds the standard SOC 2 policy set; a named owner publishes each one, and your team acknowledges them — the read-and-accept evidence an auditor asks for. Published policies + acknowledgments are program evidence."
        right={
          <div className="flex items-center gap-4">
            <div className="text-right text-sm">
              <span className="text-xl font-semibold text-pulse">{summary.published}</span> <span className="text-xs text-faint">published</span>
            </div>
            <div className="text-right text-sm">
              <span className="text-xl font-semibold text-ink">{summary.ack_coverage_pct}%</span> <span className="text-xs text-faint">acknowledged</span>
            </div>
          </div>
        }
      />

      {policies.length === 0 ? (
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-border bg-surface px-4 py-3">
          <div className="flex items-center gap-2.5 text-sm text-muted">
            <Sparkles className="h-4 w-4 text-accent" />
            Start with the standard SOC 2 policy set — the agent seeds the drafts; you adopt, edit, and publish each.
          </div>
          <form action={seedProgram}>
            <button className="inline-flex items-center gap-1.5 rounded-lg bg-accent px-3.5 py-2 text-sm font-semibold text-white transition hover:bg-accent-hover">
              Seed the standard policy set
            </button>
          </form>
        </div>
      ) : (
        <>
          {/* board summary */}
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <Stat n={summary.total} label="policies" />
            <Stat n={summary.published} label="published" tone="text-pulse" />
            <Stat n={summary.draft} label="draft" tone="text-medium" />
            <Stat n={`${summary.fully_acked}/${summary.published}`} label="fully acknowledged" />
          </div>

          {categories.map((cat) => (
            <section key={cat}>
              <h2 className="mb-2 text-xs font-medium uppercase tracking-wider text-muted">{cat}</h2>
              <div className="space-y-2">
                {byCategory.get(cat)!.map((p) => (
                  <PolicyRow key={p.id} p={p} teamSize={summary.team_size} acked={!!p.acks?.some((a) => a.user === myEmail)} />
                ))}
              </div>
            </section>
          ))}
          {summary.draft === 0 && (
            <Empty>Every policy is published. Re-seed if you&apos;ve added frameworks that need new policies.</Empty>
          )}
        </>
      )}
    </div>
  );
}

function PolicyRow({ p, teamSize, acked }: { p: Policy; teamSize: number; acked: boolean }) {
  const published = p.status === "published";
  const ackCount = p.acks?.length ?? 0;
  return (
    <div className="card px-4 py-3">
      <div className="flex flex-wrap items-center gap-2.5">
        <FileText className="h-4 w-4 text-accent" />
        <span className="text-sm font-semibold">{p.name}</span>
        {published ? (
          <span className="inline-flex items-center gap-1 text-[11px] font-medium text-pulse">
            <ShieldCheck className="h-3 w-3" /> published
          </span>
        ) : (
          <span className="text-[11px] text-faint">draft</span>
        )}
        <div className="ml-auto flex items-center gap-3">
          {published ? <AckButton id={p.id} acked={acked} /> : <PublishButton id={p.id} />}
        </div>
      </div>
      {p.summary && <p className="mt-1.5 text-xs text-muted">{p.summary}</p>}
      <div className="mt-1.5 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-faint">
        {p.owner && <span>owner: {p.owner}</span>}
        {published && (
          <span>
            {ackCount}
            {teamSize > 0 ? `/${teamSize}` : ""} acknowledged
          </span>
        )}
        {p.ledger_ref && (
          <span className="inline-flex items-center gap-1 text-pulse">
            <ShieldCheck className="h-3 w-3" /> signed
          </span>
        )}
      </div>
    </div>
  );
}

function Stat({ n, label, tone }: { n: number | string; label: string; tone?: string }) {
  return (
    <div className="card px-4 py-3 text-center">
      <div className={`text-xl font-semibold ${tone ?? "text-ink"}`}>{n}</div>
      <div className="text-[11px] text-faint">{label}</div>
    </div>
  );
}
