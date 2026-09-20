"use client";

import { useState } from "react";
import { BookOpen, Check, ChevronDown, Loader2 } from "lucide-react";
import type { TrainingModule, TrainingStatus } from "@/lib/types";
import { confirmRead } from "@/app/(app)/training/actions";

// The reader is what makes the "delivered" tier mean anything. If the content were a link to
// somewhere else, or a title with a tick beside it, a completion would assert that somebody was
// trained on the strength of a click — which is the audit record without the training.
//
// So: the confirm button only appears once the module is OPEN. It is a low bar and an honest one —
// we can say the content was on their screen, and we say exactly that rather than "passed".
export function ModuleReader({ m, status }: { m: TrainingModule; status?: TrainingStatus }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const state = status?.state ?? "outstanding";
  const done = state === "complete";

  async function confirm() {
    setBusy(true);
    setErr("");
    const res = await confirmRead(m.id);
    setBusy(false);
    if (!res.ok) setErr(res.error ?? "Could not record that.");
  }

  return (
    <section className="card overflow-hidden">
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-start gap-3 px-5 py-4 text-left transition hover:bg-surface-2"
      >
        <div className="mt-0.5 rounded-lg border border-border bg-surface-muted p-2">
          <BookOpen className="h-4 w-4 text-muted" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="font-medium text-ink">{m.title}</h3>
            <StateChip state={state} tier={status?.tier} />
          </div>
          <p className="mt-0.5 text-sm text-muted">{m.why}</p>
          {status?.at && (
            <p className="mt-1 text-xs text-faint">
              {done ? "Completed" : "Last completed"} {new Date(status.at).toLocaleDateString()}
              {status.provider ? ` · ${status.provider}` : ""}
              {status.expires_at ? ` · ${done ? "due again" : "was due"} ${new Date(status.expires_at).toLocaleDateString()}` : ""}
            </p>
          )}
        </div>
        <ChevronDown className={`mt-1 h-4 w-4 shrink-0 text-muted transition ${open ? "rotate-180" : ""}`} />
      </button>

      {open && (
        <div className="border-t border-border px-5 py-4">
          <div className="space-y-3 text-sm leading-relaxed text-muted">
            {m.body.map((p, i) => (
              <p key={i}>{p}</p>
            ))}
          </div>
          <div className="mt-4 flex flex-wrap items-center gap-3 border-t border-border pt-4">
            <button
              onClick={confirm}
              disabled={busy}
              className="inline-flex items-center gap-1.5 rounded-lg bg-accent px-3 py-1.5 text-xs font-semibold text-white transition hover:bg-accent-hover disabled:opacity-50"
            >
              {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Check className="h-3.5 w-3.5" />}
              {done ? "Confirm again" : "I have read this"}
            </button>
            {/* Says what the record actually claims. "Completed" here means the text above was on
                your screen and you said so — it is not a test and we do not pretend it is one. */}
            <p className="text-[11px] text-muted">
              This records that you read it, on today&apos;s date, under your name. It is not a test.
            </p>
          </div>
          {err && <p className="mt-2 text-xs text-high">{err}</p>}
        </div>
      )}
    </section>
  );
}

function StateChip({ state, tier }: { state: string; tier?: string }) {
  if (state === "complete") {
    // The TIER is on the chip, not just the tick. "We showed you this" and "somebody says you did
    // this elsewhere" are different evidence and the page never lets them look identical.
    const attested = tier === "attested_external";
    return (
      <span
        className={`rounded-full border px-2 py-0.5 text-[11px] ${
          attested ? "border-border text-muted" : "border-pulse/40 text-pulse"
        }`}
      >
        {attested ? "recorded from elsewhere" : "read here"}
      </span>
    );
  }
  if (state === "expired") {
    return (
      <span className="rounded-full border border-high/40 px-2 py-0.5 text-[11px] text-high">
        due again
      </span>
    );
  }
  return (
    <span className="rounded-full border border-border px-2 py-0.5 text-[11px] text-muted">
      not started
    </span>
  );
}
