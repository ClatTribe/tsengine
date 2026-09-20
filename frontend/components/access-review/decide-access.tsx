"use client";

import { useState } from "react";
import { useFormStatus } from "react-dom";
import { Check, ShieldMinus, Undo2 } from "lucide-react";
import { decideAccess } from "@/app/(app)/access-review/actions";

// The reviewer's two answers, and the caveat that goes with one of them.
//
// "Remove" is deliberately not called "Revoke": the verdict is recorded, and the removal itself is a
// separate change that the approval desk still has to approve. A button labelled Revoke would tell a
// reviewer they had just cut someone's access — see the note rendered beside the form.
export function DecideAccess({
  subject,
  decision,
  reviewer,
}: {
  subject: string;
  decision: "" | "keep" | "revoke";
  /** The signed-in user — the default name on the record, overridable when someone reviews on paper. */
  reviewer: string;
}) {
  const [open, setOpen] = useState(false);

  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        className="inline-flex items-center gap-1.5 rounded-lg border border-border px-2.5 py-1 text-xs font-medium text-muted transition hover:border-accent/40 hover:text-accent"
      >
        {decision ? (
          <>
            <Undo2 className="h-3.5 w-3.5" /> Change answer
          </>
        ) : (
          <>
            <Check className="h-3.5 w-3.5" /> Review
          </>
        )}
      </button>
    );
  }

  return (
    <form
      action={decideAccess}
      className="mt-2 w-full space-y-2 rounded-xl border border-accent/30 bg-accent-soft/20 p-3"
    >
      <input type="hidden" name="subject" value={subject} />
      <div className="text-[11px] font-semibold uppercase tracking-wide text-accent">
        Does {subject} still need this access?
      </div>
      <input
        name="by"
        defaultValue={reviewer}
        placeholder="Reviewer (name) — recorded with the decision"
        className="w-full rounded-lg border border-border bg-surface px-2.5 py-1.5 text-sm"
      />
      <textarea
        name="note"
        rows={2}
        placeholder="Note (why) — optional, kept with the decision as evidence"
        className="w-full rounded-lg border border-border bg-surface px-2.5 py-1.5 text-sm"
      />
      <div className="flex flex-wrap items-center gap-2">
        <Submit value="keep" label="Keep access" icon="keep" />
        <Submit value="revoke" label="Mark for removal" icon="revoke" />
        <button
          type="button"
          onClick={() => setOpen(false)}
          className="text-xs text-muted transition hover:text-ink"
        >
          Cancel
        </button>
      </div>
      <p className="text-[11px] leading-relaxed text-muted">
        Recording a removal does not remove the access. The decision is signed into the ledger; the
        change itself is proposed separately and still has to be approved in the Inbox.
      </p>
    </form>
  );
}

function Submit({ value, label, icon }: { value: string; label: string; icon: "keep" | "revoke" }) {
  const { pending } = useFormStatus();
  const revoke = icon === "revoke";
  return (
    <button
      type="submit"
      name="decision"
      value={value}
      disabled={pending}
      className={
        "inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold transition disabled:opacity-50 " +
        (revoke
          ? "border border-high/40 text-high hover:bg-high/10"
          : "bg-accent text-white hover:bg-accent-hover")
      }
    >
      {revoke ? <ShieldMinus className="h-3.5 w-3.5" /> : <Check className="h-3.5 w-3.5" />}
      {pending ? "Recording…" : label}
    </button>
  );
}
