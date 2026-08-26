"use client";

import { useState, useTransition } from "react";
import { Loader2, Check, X } from "lucide-react";
import { attestQuestion } from "@/app/(app)/compliance/questionnaire/actions";

// The answer control for a question no scan can reach.
//
// It offers BOTH answers. A questionnaire that could only say yes would be a form with one
// possible outcome, and a vendor honestly reporting "we do not carry cyber insurance" is giving
// the buyer exactly what they asked for — so "No" is a first-class button, not an omission.
//
// It appears only on attested rows. The API refuses an evidenced question outright (a typed
// answer would replace an observation with an opinion in a document a buyer relies on); not
// rendering the control means nobody is invited to try.
export function AttestAnswer({ id, who }: { id: string; who: string }) {
  const [pending, start] = useTransition();
  const [note, setNote] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState<"" | "yes" | "no">("");

  function answer(inPlace: boolean) {
    setErr("");
    setBusy(inPlace ? "yes" : "no");
    start(async () => {
      try {
        await attestQuestion(id, inPlace, who, note);
      } catch (e) {
        setErr(e instanceof Error ? e.message : "Could not record the answer");
      } finally {
        setBusy("");
      }
    });
  }

  return (
    <div className="mt-2">
      <div className="flex flex-wrap items-center gap-1.5">
        <button
          onClick={() => answer(true)}
          disabled={pending}
          className="inline-flex items-center gap-1 rounded-lg border border-pulse/30 bg-pulse/10 px-2 py-1 text-[11px] font-medium text-pulse transition hover:bg-pulse/20 disabled:opacity-60"
        >
          {busy === "yes" && pending ? <Loader2 className="h-3 w-3 animate-spin" /> : <Check className="h-3 w-3" />}
          Yes, in place
        </button>
        <button
          onClick={() => answer(false)}
          disabled={pending}
          className="inline-flex items-center gap-1 rounded-lg border border-border px-2 py-1 text-[11px] font-medium text-muted transition hover:border-medium/40 hover:text-medium disabled:opacity-60"
        >
          {busy === "no" && pending ? <Loader2 className="h-3 w-3 animate-spin" /> : <X className="h-3 w-3" />}
          No, not yet
        </button>
        <input
          value={note}
          onChange={(e) => setNote(e.target.value)}
          placeholder="Add context (optional)"
          className="min-w-0 flex-1 rounded-lg border border-border bg-surface-2 px-2 py-1 text-[11px] outline-none focus:border-accent"
        />
      </div>
      {/* Said plainly, because the answer is published to a stranger under this person's name. */}
      <p className="mt-1 text-[10px] text-faint">
        Your name and the date are recorded and shown with the answer — a buyer sees who stated it.
      </p>
      {err && <p className="mt-1 text-[11px] text-high">{err}</p>}
    </div>
  );
}
