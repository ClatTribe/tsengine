"use client";

import { useState } from "react";
import { useFormStatus } from "react-dom";
import { Check, XCircle, ArrowUpDown, Loader2 } from "lucide-react";
import type { AuditItem } from "@/lib/types";
import { decideFinding } from "@/app/(app)/audit-signoff/actions";

const SEVERITIES = ["critical", "high", "medium", "low", "info"];

// The reviewer's three answers.
//
// INCLUDE needs nothing — the engine's evidence is the reason, and demanding a justification for the
// common case would make the expensive path the default. EXCLUDE and RECLASSIFY both demand a
// reason, because each is the reviewer's OWN claim replacing the engine's: an exclusion with no
// reason is indistinguishable from an oversight, and if the application is later compromised through
// an excluded finding, that sentence is what stands between the auditor and negligence.
export function DecideFinding({ target, item }: { target: string; item: AuditItem }) {
  const [mode, setMode] = useState<"" | "exclude" | "reclassify">("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(verdict: string, severity: string, reason: string) {
    setBusy(true);
    setErr("");
    const res = await decideFinding(target, item.key, verdict, severity, reason);
    setBusy(false);
    if (!res.ok) setErr(res.error ?? "Could not record that decision.");
    else setMode("");
  }

  if (mode === "") {
    return (
      <div className="flex flex-wrap items-center gap-2">
        <button
          onClick={() => submit("include", "", "")}
          disabled={busy}
          className="inline-flex items-center gap-1.5 rounded-lg bg-accent px-2.5 py-1 text-xs font-semibold text-white transition hover:bg-accent-hover disabled:opacity-50"
        >
          {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Check className="h-3.5 w-3.5" />}
          Include
        </button>
        <button
          onClick={() => setMode("exclude")}
          className="inline-flex items-center gap-1.5 rounded-lg border border-border px-2.5 py-1 text-xs text-muted transition hover:border-high/40 hover:text-high"
        >
          <XCircle className="h-3.5 w-3.5" /> Exclude
        </button>
        <button
          onClick={() => setMode("reclassify")}
          className="inline-flex items-center gap-1.5 rounded-lg border border-border px-2.5 py-1 text-xs text-muted transition hover:border-accent/40 hover:text-accent"
        >
          <ArrowUpDown className="h-3.5 w-3.5" /> Reclassify
        </button>
        {err && <span className="text-xs text-high">{err}</span>}
      </div>
    );
  }

  return (
    <form
      action={async (fd: FormData) => {
        await submit(mode, String(fd.get("severity") ?? ""), String(fd.get("reason") ?? ""));
      }}
      className="w-full space-y-2 rounded-xl border border-accent/30 bg-accent-soft/20 p-3"
    >
      <div className="text-[11px] font-semibold uppercase tracking-wide text-accent">
        {mode === "exclude" ? "Keep this out of the report" : "Change the severity in the report"}
      </div>
      {mode === "reclassify" && (
        <select
          name="severity"
          required
          defaultValue=""
          className="w-full rounded-lg border border-border bg-surface px-2.5 py-1.5 text-sm"
        >
          <option value="" disabled>
            Severity in the report…
          </option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {s} {s !== item.severity ? `(engine said ${item.severity})` : ""}
            </option>
          ))}
        </select>
      )}
      <textarea
        name="reason"
        required
        rows={2}
        placeholder={
          mode === "exclude"
            ? "Why this is not a finding for this application — recorded with your name"
            : "Why the report should carry a different severity — recorded with your name"
        }
        className="w-full rounded-lg border border-border bg-surface px-2.5 py-1.5 text-sm"
      />
      <div className="flex flex-wrap items-center gap-2">
        <Submit />
        <button type="button" onClick={() => setMode("")} className="text-xs text-muted transition hover:text-ink">
          Cancel
        </button>
      </div>
      {/* An exclusion is not a deletion, and saying so is what stops a reviewer using it to tidy the
          report. The finding stays in the record with this reason and their name on it. */}
      <p className="text-[11px] leading-relaxed text-muted">
        {mode === "exclude"
          ? "This does not delete the finding. It stays in the audit record with your name and this reason, and the certificate states that findings were excluded."
          : "The report carries your severity, and records that a reviewer changed it."}
      </p>
      {err && <p className="text-xs text-high">{err}</p>}
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
      <Check className="h-3.5 w-3.5" /> {pending ? "Recording…" : "Record decision"}
    </button>
  );
}
