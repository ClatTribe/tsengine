import Link from "next/link";
import { Sparkles, ArrowUpRight } from "lucide-react";

// EngineStatus says whether the AI engineer is ACTUALLY RUNNING for this workspace.
//
// THE SILENCE THIS REPLACES. AutoReviewAfterScan — the hook that runs the engineer unattended after a
// scan — returns early when no model resolves, and the economic gate means a workspace with no key of
// its own and no AI entitlement never gets one. Nothing said so. The console described an agent that
// triages, localizes and proposes fixes, and for those tenants none of that was happening. Scanning
// still ran, findings still appeared, so the product looked like it was working.
//
// Measuring autonomy is what surfaced it: the job is 94% unattended with a model and 69% without,
// because the model-dependent tasks are not weaker without one — they are absent.
//
// WHAT IT DOES NOT DO. It does not nag, and it does not imply the workspace is unprotected. The
// deterministic half is genuinely most of the detection: scanning, cross-surface correlation,
// fix-verification, evidence capture and reporting all run unattended regardless. Saying "you have
// nothing" would be as false as the silence was.
export function EngineStatus({ hasKey, aiEnabled }: { hasKey: boolean; aiEnabled: boolean }) {
  if (hasKey || aiEnabled) return null;
  return (
    <div className="rounded-xl border border-medium/30 bg-medium/5 p-4">
      <div className="flex items-center gap-2 text-sm font-semibold text-ink">
        <Sparkles className="h-4 w-4 text-medium" /> The AI engineer is not running for this workspace
      </div>
      <p className="mt-1.5 max-w-3xl text-xs leading-relaxed text-muted">
        No model is configured, so the reasoning half of the engineer is idle: nothing is being
        triaged, localized, or turned into a proposed fix. That is not a statement about your estate —
        it means those steps are not happening at all.
      </p>
      <p className="mt-2 max-w-3xl text-xs leading-relaxed text-muted">
        <span className="font-medium text-ink">Still running, unattended:</span> scanning on every pass,
        cross-surface correlation, fix-verification on re-scan, evidence capture and reporting. Those are
        deterministic and need no model.
      </p>
      <Link
        href="/settings"
        className="mt-3 inline-flex items-center gap-1.5 text-xs font-medium text-accent hover:underline"
      >
        Add your own model key — works on any plan <ArrowUpRight className="h-3.5 w-3.5" />
      </Link>
    </div>
  );
}
