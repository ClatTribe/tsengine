"use client";

import { useState, useTransition } from "react";
import { FileSearch, Loader2 } from "lucide-react";
import { localizeFinding, type LocalizeResult } from "@/app/(app)/findings/[id]/actions";

// LocalizeFinding — "where in the code does this actually live?"
//
// A scanner tells you a rule fired; it frequently cannot tell you which file to open. A dependency
// finding points at a lockfile, a cloud finding at an ARN, and a repo finding's file:line is often
// approximate or missing. The localizer answers that from the repository's real contents.
//
// The platform has scored this capability and never delivered it: it existed only as an agent tool, so
// no human had ever seen its output. This is that output, on the finding it is about.
//
// The negatives are ANSWERS and are shown verbatim rather than being flattened into an error — "no
// repository connected" is explicitly not a verdict on the finding, and "no file carries sink evidence
// for this class" usually means the finding is a configuration or dependency issue rather than a code
// one. Both are useful; neither means "nothing found".
export function LocalizeFinding({ findingID }: { findingID: string }) {
  const [pending, start] = useTransition();
  const [res, setRes] = useState<LocalizeResult | null>(null);

  return (
    <section className="rounded-xl border border-border bg-surface p-4">
      <div className="flex items-center justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2 text-sm font-semibold text-ink">
            <FileSearch className="h-4 w-4 text-accent" /> Where is the fix?
          </div>
          <p className="mt-1 text-xs leading-relaxed text-muted">
            Ranks the files in your connected repository that carry the sink for this weakness class —
            grounded in the repo&apos;s real contents, so it can only cite files that exist.
          </p>
        </div>
        <button
          type="button"
          disabled={pending}
          onClick={() => {
            setRes(null);
            start(async () => setRes(await localizeFinding(findingID)));
          }}
          className="inline-flex shrink-0 items-center gap-1.5 rounded-lg border border-border px-3 py-1.5 text-xs font-medium text-ink transition hover:border-accent/40 disabled:opacity-50"
        >
          {pending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <FileSearch className="h-3.5 w-3.5" />}
          Locate
        </button>
      </div>

      {res && (
        <div className="mt-3">
          {res.ok ? (
            <pre className="max-h-80 overflow-auto whitespace-pre-wrap rounded-lg border border-border bg-bg p-3 text-xs leading-relaxed text-muted">
              {res.answer?.trim() || "No answer returned."}
            </pre>
          ) : (
            <p className="rounded-lg border border-danger/30 bg-danger/5 px-3 py-2 text-xs text-danger">{res.error}</p>
          )}
        </div>
      )}
    </section>
  );
}
