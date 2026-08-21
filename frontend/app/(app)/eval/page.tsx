import { Target, AlertTriangle } from "lucide-react";
import { ModelArm } from "./ModelArm";
import { EpisodeCorpus } from "@/components/eval/episode-corpus";
import { api } from "@/lib/api";
import { Empty } from "@/components/ui/primitives";
import { PageIntro } from "@/components/ui/page-intro";
import { PageTabs } from "@/components/ui/page-tabs";
import { SECURITY_TABS } from "@/lib/tabs";

export const dynamic = "force-dynamic";

const SOURCE_LABEL: Record<string, string> = {
  reinstated: "You reinstated it",
  ignored: "You called it noise",
  confirmed_fix: "A re-scan proved the fix",
};

// Proof you generate yourself.
//
// Every other score in security tooling is a vendor's number about a vendor's corpus, which is
// precisely the claim practitioners have stopped believing. This one is graded entirely from
// decisions THIS customer already made on THEIR estate, and it can be re-derived from their own
// data at any time. That is what makes it worth anything.
export default async function EvalPage() {
  const [ev, eps] = await Promise.all([api.tenantEval(), api.episodes()]);
  const pct = ev.agreement != null ? Math.round(ev.agreement * 100) : null;
  const reinstatedFailures = ev.by_source?.reinstated ?? 0;

  return (
    <div className="space-y-6">
      <PageTabs tabs={SECURITY_TABS} />
      <PageIntro
        icon={Target}
        title="Your evals"
        description="How often the current setup agrees with your own experts, graded on findings from your estate — every case is a decision you already made. Not our benchmark: yours, re-derivable from your data."
      />

      {/* What the agent runs DID, above the agreement score. The score says whether the
          setup matches this customer's judgement; this says whether the runs moved anything.
          A workspace can score well on the first and nothing on the second. */}
      <EpisodeCorpus stats={eps.stats} />

      {/* Rendered in BOTH states on purpose. A workspace with no graded cases is exactly the one
          that has never heard of this, and hiding the capability until it is usable means nobody
          discovers it exists — the component says for itself why it cannot run yet. */}
      {ev.cases === 0 ? (
        <Empty>{ev.note ?? "No graded cases yet."}</Empty>
      ) : (
        <>
          <div className="grid grid-cols-3 gap-3">
            <div className="rounded-xl border border-border bg-surface px-4 py-3">
              <div className="text-2xl font-semibold text-ink">{pct}%</div>
              <div className="text-sm font-medium">Agreement</div>
              <div className="mt-0.5 text-xs text-muted">
                {ev.passed} of {ev.cases} cases matched your judgement
              </div>
            </div>
            <div className="rounded-xl border border-border bg-surface px-4 py-3">
              <div className="text-2xl font-semibold text-ink">{ev.failures.length}</div>
              <div className="text-sm font-medium">Disagreements</div>
              <div className="mt-0.5 text-xs text-muted">where the setup and your expert differ</div>
            </div>
            <div
              className={
                reinstatedFailures > 0
                  ? "rounded-xl border border-critical/30 bg-critical/5 px-4 py-3"
                  : "rounded-xl border border-border bg-surface px-4 py-3"
              }
            >
              <div className="text-2xl font-semibold text-ink">{reinstatedFailures}</div>
              <div className="text-sm font-medium">Overruled twice</div>
              <div className="mt-0.5 text-xs text-muted">
                findings you put back that it would drop again — the worst kind
              </div>
            </div>
          </div>

          {ev.note ? <p className="text-xs text-muted">{ev.note}</p> : null}

          {/* Regression over time — the claim no public benchmark can make. It refuses to draw a
              line more often than it draws one, because the graded set grows whenever someone
              grades something, and two scores over different sets are not the same measurement. */}
          {ev.trend ? (
            <section
              className={
                ev.trend.direction === "regressed"
                  ? "rounded-2xl border border-critical/30 bg-critical/5 px-5 py-4"
                  : "rounded-2xl border border-border bg-surface px-5 py-4"
              }
            >
              <div className="flex items-center gap-2">
                <h2 className="font-semibold">Since last time</h2>
                {ev.trend.comparable && ev.trend.delta_points != null && ev.trend.delta_points !== 0 ? (
                  <span
                    className={
                      ev.trend.direction === "regressed"
                        ? "rounded px-1.5 py-0.5 text-[11px] font-medium text-critical ring-1 ring-critical/30"
                        : "rounded px-1.5 py-0.5 text-[11px] font-medium text-pulse ring-1 ring-pulse/30"
                    }
                  >
                    {ev.trend.delta_points > 0 ? "+" : ""}
                    {ev.trend.delta_points} points
                  </span>
                ) : null}
              </div>
              <p className="mt-1 text-sm text-muted">{ev.trend.note}</p>
              <p className="mt-1 text-xs text-faint">{ev.trend.runs} evaluation(s) recorded.</p>
            </section>
          ) : null}

          <section className="rounded-2xl border border-border bg-surface">
            <header className="border-b border-border px-5 py-4">
              <h2 className="font-semibold">Where it disagrees with you</h2>
              <p className="mt-0.5 text-sm text-muted">
                Each row is a case you graded. &ldquo;Kept&rdquo; means the setup would surface it;
                &ldquo;suppressed&rdquo; means it would hide it.
              </p>
            </header>
            {ev.failures.length === 0 ? (
              <p className="px-5 py-4 text-sm text-muted">
                No disagreements — the current setup matched every case you graded.
              </p>
            ) : (
              <ul className="divide-y divide-border">
                {ev.failures.map((f) => (
                  <li key={f.finding_id} className="px-5 py-3">
                    <div className="flex items-start justify-between gap-4">
                      <div className="min-w-0 flex-1">
                        <p className="mono truncate text-xs">{f.rule_id}</p>
                        <p className="mt-1 text-sm text-muted">
                          {SOURCE_LABEL[f.source] ?? f.source} → expected{" "}
                          <span className="text-ink">{f.expect === "keep" ? "kept" : "suppressed"}</span>, the
                          setup would <span className="text-ink">{f.got === "keep" ? "keep" : "suppress"}</span> it
                          {f.by ? ` · graded by ${f.by}` : ""}
                        </p>
                        {f.reason ? <p className="mt-0.5 text-xs text-faint">{f.reason}</p> : null}
                      </div>
                      {f.source === "reinstated" && (
                        <span className="shrink-0 rounded px-1.5 py-0.5 text-[11px] font-medium text-critical ring-1 ring-critical/30">
                          overruled twice
                        </span>
                      )}
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </>
      )}

      <ModelArm hasCases={ev.cases > 0} />

      <p className="flex items-start gap-2 text-xs text-muted">
        <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-500" />
        <span>
          This score reports; it does not change anything. Nothing here feeds back into how findings are
          filtered — a disagreement is information for you, not an automatic correction. And the
          comparison above only appears when two runs graded the same set: the suite grows every time
          you grade something, and two scores over different sets are not the same measurement.
        </span>
      </p>
    </div>
  );
}
