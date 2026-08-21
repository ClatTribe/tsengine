import { Activity } from "lucide-react";
import type { EpisodeStats } from "@/lib/types";

// What the AI engineers' runs actually DID to this estate.
//
// The rest of the product reports what a run FOUND — its own account of itself. This
// reports the posture before and after, which is the only number that can disagree with
// that account. An agent that reports six findings and moves nothing is a fact worth
// having, and it is invisible everywhere else.
//
// Three things this panel refuses to do, each because the flattering version is one line
// shorter:
//
//   1. It shows `scored` next to `episodes`. Every number below is derived from the
//      scored subset, and a cost-per-outcome computed over half a corpus, presented
//      without saying so, is more confident than the data supports.
//   2. It prints no cost-per-verified when nothing was verified. Zero would rank the
//      agent that finds nothing as the most efficient one in the fleet.
//   3. It says "stopped appearing", never "fixed". A failed scan, a timed-out tool and an
//      offline target all close an issue on this measure. Whether a fix closed it is a
//      different claim resting on different evidence.
export function EpisodeCorpus({ stats }: { stats: EpisodeStats }) {
  if (stats.episodes === 0) {
    return (
      <div className="rounded-xl border border-border bg-surface p-5">
        <SectionHead />
        <p className="mt-2 text-sm text-muted">
          No agent runs recorded yet. Each time the AI cloud or code engineer investigates, the
          posture is measured before and after, so you can see what the run changed rather than
          only what it reported.
        </p>
      </div>
    );
  }

  const unscored = stats.episodes - stats.scored;

  return (
    <div className="rounded-xl border border-border bg-surface p-5">
      <SectionHead />

      <div className="mt-3 grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Stat value={stats.episodes} label="Agent runs" hint={`${stats.scored} measurable`} />
        <Stat value={stats.opened} label="Issues opened" hint="not on the books before the run" />
        <Stat value={stats.closed} label="Stopped appearing" hint="not the same as fixed" />
        <Stat
          value={stats.has_cost_per_verified ? `$${stats.cost_per_verified!.toFixed(2)}` : "—"}
          label="Per verified finding"
          hint={
            stats.has_cost_per_verified
              ? `$${stats.cost_usd.toFixed(2)} over ${stats.verified} verified`
              : "nothing verified yet — no ratio to report"
          }
        />
      </div>

      {/* The denominator, stated. Every number above comes from the scored subset. */}
      {unscored > 0 && (
        <p className="mt-3 rounded-lg bg-amber-500/5 px-3 py-2 text-xs text-muted">
          {unscored} of {stats.episodes} runs could not be measured — the posture was not readable
          on both sides of the run, so those are excluded from the figures above rather than
          counted as having changed nothing.
        </p>
      )}

      <p className="mt-3 text-xs text-muted">
        {stats.trainable === 0 ? (
          <>
            None of these runs may be used to improve tsengine. Turn that on in{" "}
            <span className="text-ink">Settings → Improving tsengine</span> if you want them to.
          </>
        ) : (
          <>
            {stats.trainable} of {stats.episodes} may be used to improve tsengine, under the consent
            recorded in Settings.
          </>
        )}
      </p>
    </div>
  );
}

function SectionHead() {
  return (
    <div className="flex items-center gap-2">
      <Activity className="h-4 w-4 text-accent" />
      <h2 className="text-sm font-semibold text-ink">What the agent runs changed</h2>
    </div>
  );
}

function Stat({ value, label, hint }: { value: number | string; label: string; hint: string }) {
  return (
    <div>
      <div className="text-2xl font-semibold text-ink">{value}</div>
      <div className="text-sm font-medium">{label}</div>
      <div className="mt-0.5 text-xs text-muted">{hint}</div>
    </div>
  );
}
