"use client";

import { useState, useTransition } from "react";
import { BookText, Loader2 } from "lucide-react";
import { researchAdvisory, type ResearchResult } from "@/app/(app)/findings/[id]/actions";

// ResearchAdvisory — bounded, cited fetch of THIS finding's own advisory URLs (internal/research).
//
// The pinned threat-intel corpus refreshes out of band, so a CVE catalogued since the last refresh can
// carry an advisory link the product shows but whose CONTENTS no one here has read. This reads them,
// on demand, from the finding's OWN cited URLs only — never an open search — and shows each with the
// time it was fetched and a content hash, so the citation is checkable.
//
// Context, NEVER evidence: this is reference material to understand a fresh CVE, not proof of the
// finding, which still rests on the tool that detected it. Shown beside the evidence, not inside it.
export function ResearchAdvisory({ findingID }: { findingID: string }) {
  const [pending, start] = useTransition();
  const [res, setRes] = useState<ResearchResult | null>(null);

  return (
    <section className="rounded-xl border border-border bg-surface p-4">
      <div className="flex items-center justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2 text-sm font-semibold text-ink">
            <BookText className="h-4 w-4 text-accent" /> Research the advisory
          </div>
          <p className="mt-1 text-xs leading-relaxed text-muted">
            Fetches this finding&apos;s own cited advisory pages — context for a CVE newer than the last
            threat-feed refresh. Each is pinned with its fetch time and a content hash. Reference only;
            it never changes the finding.
          </p>
        </div>
        <button
          type="button"
          disabled={pending}
          onClick={() => {
            setRes(null);
            start(async () => setRes(await researchAdvisory(findingID)));
          }}
          className="inline-flex shrink-0 items-center gap-1.5 rounded-lg border border-border px-3 py-1.5 text-xs font-medium text-ink transition hover:border-accent/40 disabled:opacity-50"
        >
          {pending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <BookText className="h-3.5 w-3.5" />}
          Research
        </button>
      </div>

      {res && (
        <div className="mt-3 space-y-2">
          {!res.ok ? (
            <p className="rounded-lg border border-danger/30 bg-danger/5 px-3 py-2 text-xs text-danger">{res.error}</p>
          ) : (
            <>
              {res.note && <p className="text-xs text-muted">{res.note}</p>}
              {res.documents.map((d) => (
                <div key={d.sha256} className="rounded-lg border border-border bg-bg p-3">
                  <a href={d.url} target="_blank" rel="noopener noreferrer nofollow" className="mono break-all text-[11px] text-accent underline decoration-dotted underline-offset-2">
                    {d.title || d.url}
                  </a>
                  <div className="mt-0.5 text-[10px] text-faint">
                    fetched {d.fetched_at.slice(0, 19).replace("T", " ")} UTC · sha256 {d.sha256.slice(0, 12)}
                    {d.truncated && " · truncated"}
                  </div>
                  <pre className="mt-2 max-h-72 overflow-auto whitespace-pre-wrap text-xs leading-relaxed text-muted">{d.text.trim()}</pre>
                </div>
              ))}
              {res.unavailable.map((u) => (
                <p key={u.url} className="text-[11px] text-medium">
                  Could not read <span className="mono break-all">{u.url}</span> — {u.reason}
                </p>
              ))}
              {res.rejected.map((u) => (
                <p key={u.url} className="text-[11px] text-faint">
                  Not fetched: <span className="mono break-all">{u.url}</span> — {u.reason}
                </p>
              ))}
            </>
          )}
        </div>
      )}
    </section>
  );
}
