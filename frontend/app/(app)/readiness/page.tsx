import { ClipboardCheck } from "lucide-react";
import { api } from "@/lib/api";
import { PageIntro } from "@/components/ui/page-intro";
import { StagePicker, ReadinessList } from "@/components/readiness/readiness-client";

export const dynamic = "force-dynamic";

const STAGE_LABEL: Record<string, string> = {
  seed: "Seed", series_a: "Series A", series_b: "Series B", series_c: "Series C+",
};

// The security practices a company at this stage is expected to have, and which of them we can
// actually answer.
//
// The counts are shown as five separate numbers rather than one percentage, on purpose. A single
// score would have to fold "we never looked" in with "we looked and it was clean" — and it would then
// RISE for a customer who connects nothing, which is the precise opposite of what a readiness number
// is for.

export default async function ReadinessPage({
  searchParams,
}: {
  searchParams: Promise<{ stage?: string }>;
}) {
  const { stage } = await searchParams;
  const [data, me] = await Promise.all([api.readiness(stage), api.me()]);
  const s = data.summary;

  return (
    <div className="space-y-6">
      <PageIntro
        icon={ClipboardCheck}
        title="Security readiness"
        description="What a company at your stage is expected to have in place, checked against your real estate. Every measured row names the open-source scanner that answers it, so a tick is something you can verify rather than take on trust."
      />

      {!data.stage_set ? (
        <StagePicker stages={data.stages} />
      ) : (
        <>
          <div className="card flex flex-wrap items-center gap-x-6 gap-y-3 px-5 py-4">
            <div>
              <div className="text-[11px] uppercase tracking-wide text-muted">Measured as</div>
              <div className="text-sm font-medium text-ink">{STAGE_LABEL[data.stage] ?? data.stage}</div>
            </div>
            <Stat n={s.pass} label="In place" cls="text-pulse" />
            <Stat n={s.gap} label="Gaps" cls="text-high" />
            <Stat n={s.not_checked} label="Not checked" cls="text-muted" />
            <Stat n={s.needs_you} label="Needs you" cls="text-accent" />
            <Stat n={s.not_covered} label="Not covered" cls="text-faint" />
          </div>

          {s.not_checked > 0 && (
            <p className="text-xs text-muted">
              {s.not_checked} {s.not_checked === 1 ? "practice is" : "practices are"} unchecked because
              nothing is connected yet. They are not passing — we simply have not looked.
            </p>
          )}

          <ReadinessList data={data} me={me?.email || "you"} />
        </>
      )}
    </div>
  );
}

function Stat({ n, label, cls }: { n: number; label: string; cls: string }) {
  return (
    <div>
      <div className={`text-xl font-semibold tabular-nums ${cls}`}>{n}</div>
      <div className="text-[11px] text-muted">{label}</div>
    </div>
  );
}
