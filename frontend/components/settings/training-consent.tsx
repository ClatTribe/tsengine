"use client";

import { useState, useTransition } from "react";
import { Loader2, Check, GraduationCap } from "lucide-react";
import { setTrainingConsent } from "@/app/(app)/settings/actions";
import type { TrainingSettings } from "@/lib/types";

// The customer end of the improvement loop (ADR 0018 §4): whether this workspace's agent
// runs may be used to make the product better.
//
// Three things this panel deliberately does, each because the honest version and the
// convenient version differ:
//
//   1. It shows the actual STATEMENT the backend stores, not a checkbox label written
//      here. A label maintained separately from the recorded text drifts, and then the
//      thing the customer read is not the thing the audit trail says they agreed to.
//   2. It says plainly that turning this off applies to FUTURE runs. That is the thing a
//      reasonable person assumes works the other way, and quietly letting them assume it
//      is how a consent record becomes indefensible.
//   3. It states that declining changes nothing about the security work. A consent prompt
//      that leaves any doubt about that is not really a choice.
export function TrainingConsentPanel({ initial, who }: { initial: TrainingSettings; who: string }) {
  const [consented, setConsented] = useState(initial.consented);
  const [saved, setSaved] = useState(false);
  const [err, setErr] = useState("");
  const [pending, start] = useTransition();

  function save(next: boolean) {
    setErr("");
    setSaved(false);
    setConsented(next);
    start(async () => {
      try {
        await setTrainingConsent(next, who);
        setSaved(true);
      } catch (e) {
        setConsented(!next); // put the control back where it was; the decision did not land
        setErr(e instanceof Error ? e.message : "could not save the decision");
      }
    });
  }

  return (
    <div className="space-y-3">
      <p className="text-xs text-muted">
        Agent runs on this workspace are recorded: the steps the agent took, what it found, and
        whether a fix closed it. You decide whether we may use that to improve tsengine.
      </p>

      <label className="flex items-start gap-2 text-sm">
        <input
          type="checkbox"
          checked={consented}
          disabled={pending}
          onChange={(e) => save(e.target.checked)}
          className="mt-0.5 h-4 w-4 rounded border-border accent-accent"
        />
        <span>
          Use our agent runs to improve tsengine
          {pending && <Loader2 className="ml-2 inline h-3.5 w-3.5 animate-spin text-muted" />}
          {saved && !pending && <Check className="ml-2 inline h-3.5 w-3.5 text-low" />}
        </span>
      </label>

      <blockquote className="rounded-lg border-l-2 border-accent/50 bg-surface-2/40 px-3 py-2 text-xs leading-relaxed text-muted">
        {initial.current_statement}
      </blockquote>

      {consented && initial.by && (
        <p className="text-xs text-muted">
          Agreed by <span className="text-ink">{initial.by}</span>
          {initial.at ? ` on ${new Date(initial.at).toLocaleDateString()}` : ""}.
        </p>
      )}

      <p className="text-xs text-muted">{initial.note}</p>

      <p className="flex items-start gap-2 text-xs text-muted">
        <GraduationCap className="mt-0.5 h-3.5 w-3.5 shrink-0 text-accent" />
        Declining changes nothing about the security work we do for this workspace. It only
        affects whether these runs help improve the product for everyone.
      </p>

      {err && <div className="rounded-lg bg-critical/10 px-3 py-2 text-xs text-critical">{err}</div>}
    </div>
  );
}
