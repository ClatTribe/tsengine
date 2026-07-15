"use client";

import { useState, useTransition } from "react";
import { GitPullRequest, Loader2, CircleAlert, CheckCircle2, Info } from "lucide-react";
import { openFixPR, type FixPRResult } from "@/app/(app)/findings/[id]/actions";

// "Fix it" — the real fix, as opposed to the advice next to it. The engineer reads the ACTUAL file
// from your repo, writes the patch, and queues it as a pull request for you to review.
//
// Nothing is applied here: the patch becomes a PROPOSED action at the approval desk, and approving it
// is what pushes the commit and opens the PR. So the strongest thing this button can do is put a diff
// in front of a human.
export function FixPRButton({ id }: { id: string }) {
  const [pending, start] = useTransition();
  const [res, setRes] = useState<FixPRResult | null>(null);

  function run() {
    setRes(null);
    start(async () => setRes(await openFixPR(id)));
  }

  return (
    <div className="space-y-3">
      <button
        onClick={run}
        disabled={pending}
        className="inline-flex items-center gap-2 rounded-lg bg-accent px-3 py-1.5 text-xs font-semibold text-white shadow-sm transition hover:opacity-90 disabled:opacity-50"
      >
        {pending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <GitPullRequest className="h-3.5 w-3.5" />}
        {pending ? "Reading your code and writing the fix…" : "Fix it — open a pull request"}
      </button>

      {res?.ok === false && (
        <div className="flex items-start gap-2 rounded-lg border border-critical/40 bg-critical/10 px-3 py-2 text-xs text-critical">
          <CircleAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" /> {res.error}
        </div>
      )}

      {/* The engineer declining to patch is an honest outcome, not a failure — say so plainly. */}
      {res?.ok && res.patched === false && (
        <div className="flex items-start gap-2 rounded-lg border border-border bg-surface px-3 py-2 text-xs text-muted">
          <Info className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <span>{res.reason ?? "No safe patch was produced for this finding — review it manually."}</span>
        </div>
      )}

      {res?.ok && res.patched && (
        <div className="rounded-xl border border-success/40 bg-success/5 p-4">
          <div className="flex items-center gap-2 text-sm font-semibold text-ink">
            <CheckCircle2 className="h-4 w-4 text-success" /> Fix ready for your review
          </div>
          <p className="mt-1.5 text-xs leading-relaxed text-muted">
            {res.repo ? <>Patched <span className="mono">{res.repo}</span>. </> : null}
            {res.filesChanged?.length ? (
              <>
                Changed {res.filesChanged.length === 1 ? "file" : "files"}:{" "}
                {res.filesChanged.map((f) => (
                  <span key={f} className="mono mr-1 rounded bg-bg px-1 py-0.5">
                    {f}
                  </span>
                ))}
              </>
            ) : null}
          </p>
          <p className="mt-2 text-[11px] text-faint">
            Waiting for your approval — approving opens the pull request. Nothing is pushed to your default branch.
          </p>
        </div>
      )}
    </div>
  );
}
