"use client";

import { useState } from "react";
import { useFormStatus } from "react-dom";
import { ClipboardPlus, Check } from "lucide-react";
import type { TrainingModule } from "@/lib/types";
import { recordExternal } from "@/app/(app)/training/actions";

// Recording training that happened somewhere else — a vendor course, an internal session, an
// induction deck. It is a SECOND-HAND claim, so the form asks for the two things that make it
// checkable: who delivered it, and when it really happened.
//
// The date matters more than it looks. Currency is measured from the completion date, so recording
// a two-year-old course as if it were today would silently restart a clock that has already run out.
export function RecordExternal({ modules }: { modules: TrainingModule[] }) {
  const [open, setOpen] = useState(false);

  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        className="inline-flex items-center gap-1.5 rounded-lg border border-border px-2.5 py-1 text-xs font-medium text-muted transition hover:border-accent/40 hover:text-accent"
      >
        <ClipboardPlus className="h-3.5 w-3.5" /> Record training done elsewhere
      </button>
    );
  }

  return (
    <form action={recordExternal} className="card space-y-2 p-4">
      <div className="text-[11px] font-semibold uppercase tracking-wide text-accent">
        Training completed elsewhere
      </div>
      <div className="grid gap-2 sm:grid-cols-2">
        <input
          name="subject"
          required
          placeholder="Who completed it (work email)"
          className="rounded-lg border border-border bg-surface px-2.5 py-1.5 text-sm"
        />
        <select name="module_id" required defaultValue="" className="rounded-lg border border-border bg-surface px-2.5 py-1.5 text-sm">
          <option value="" disabled>
            Which module…
          </option>
          {modules.map((m) => (
            <option key={m.id} value={m.id}>
              {m.title}
            </option>
          ))}
        </select>
        <input
          name="provider"
          required
          placeholder="Who delivered it (e.g. KnowBe4, internal session)"
          className="rounded-lg border border-border bg-surface px-2.5 py-1.5 text-sm"
        />
        <input
          name="on"
          type="date"
          className="rounded-lg border border-border bg-surface px-2.5 py-1.5 text-sm"
          aria-label="Date completed"
        />
      </div>
      <input
        name="note"
        placeholder="Note (optional) — kept with the record"
        className="w-full rounded-lg border border-border bg-surface px-2.5 py-1.5 text-sm"
      />
      <div className="flex flex-wrap items-center gap-2">
        <Submit />
        <button type="button" onClick={() => setOpen(false)} className="text-xs text-muted transition hover:text-ink">
          Cancel
        </button>
      </div>
      {/* The honest label on the weaker tier. It is recorded as your statement that this happened,
          under your name, and shown that way everywhere it appears. */}
      <p className="text-[11px] text-muted">
        This is recorded as second-hand evidence, in your name, naming the provider — it is counted
        separately from training completed here, never merged with it. Leave the date blank only if
        it happened today; currency is measured from the date it actually happened.
      </p>
    </form>
  );
}

function Submit() {
  const { pending } = useFormStatus();
  return (
    <button
      type="submit"
      disabled={pending}
      className="inline-flex items-center gap-1.5 rounded-lg bg-accent px-3 py-1.5 text-xs font-semibold text-white transition hover:bg-accent-hover disabled:opacity-50"
    >
      <Check className="h-3.5 w-3.5" /> {pending ? "Recording…" : "Record it"}
    </button>
  );
}
