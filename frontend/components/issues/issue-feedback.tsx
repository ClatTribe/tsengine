"use client";

import { useState } from "react";
import { ThumbsUp, ThumbsDown, HelpCircle, Check, Loader2 } from "lucide-react";
import { sendIssueFeedback } from "@/app/(app)/issues/actions";

// IssueFeedback asks the two questions nothing else in the product asks.
//
// Every other control here is an ACTION — ignore it, fix it, investigate it — and each
// one makes the issue move or disappear. So the only way a customer could tell us we
// were wrong was to hide the finding, and the only way to tell us we were RIGHT was to
// do nothing, which is indistinguishable from not having looked.
//
// This records an opinion and changes nothing: the row stays exactly where it was, and
// the copy says so. That is deliberate. Feedback a person suspects will hide their
// finding is feedback they will not give honestly, and a control that quietly suppresses
// what you just disagreed with teaches people to stop disagreeing.
//
// The second question is the one with no equivalent anywhere: was our PROOF good enough.
// It is asked ONLY after someone says the finding is real, because "I believe you and
// you did not show me why" is the sentence we most need and cannot infer from any click.
// Asking it of someone who thinks the finding is wrong would just be asking them to
// explain a disagreement twice.
type Verdict = "real" | "false_positive" | "unclear";

const VERDICTS: { value: Verdict; label: string; icon: typeof ThumbsUp; hint: string }[] = [
  { value: "real", label: "Looks right", icon: ThumbsUp, hint: "This is a genuine issue" },
  { value: "false_positive", label: "Not an issue", icon: ThumbsDown, hint: "This is a false positive" },
  { value: "unclear", label: "Unclear", icon: HelpCircle, hint: "I could not tell from this write-up" },
];

export function IssueFeedback({ issueKey }: { issueKey: string }) {
  const [verdict, setVerdict] = useState<Verdict | null>(null);
  const [pending, setPending] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState("");

  async function submit(v: Verdict, evidence: string) {
    setPending(true);
    setError("");
    const res = await sendIssueFeedback(issueKey, v, evidence, "");
    setPending(false);
    if (res.ok) setDone(true);
    else setError(res.error);
  }

  if (done) {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs text-muted">
        <Check className="h-3.5 w-3.5 text-accent" /> Thanks — recorded. Nothing changed on your list.
      </span>
    );
  }

  // Second question, asked only of someone who believes the finding.
  if (verdict === "real") {
    return (
      <span className="inline-flex flex-wrap items-center gap-1.5 text-xs">
        <span className="text-muted">Did the evidence show you why?</span>
        <button
          onClick={() => submit("real", "sufficient")}
          disabled={pending}
          className="rounded-lg border border-border bg-surface px-2 py-1 text-xs text-muted transition hover:border-accent/40 hover:text-ink disabled:opacity-50"
        >
          Yes
        </button>
        <button
          onClick={() => submit("real", "insufficient")}
          disabled={pending}
          className="rounded-lg border border-border bg-surface px-2 py-1 text-xs text-muted transition hover:border-accent/40 hover:text-ink disabled:opacity-50"
        >
          Not really
        </button>
        {pending && <Loader2 className="h-3.5 w-3.5 animate-spin text-faint" />}
        {error && <span className="text-danger">{error}</span>}
      </span>
    );
  }

  return (
    <span className="inline-flex flex-wrap items-center gap-1.5">
      <span className="text-xs text-faint">Was this useful?</span>
      {VERDICTS.map((v) => {
        const Icon = v.icon;
        return (
          <button
            key={v.value}
            title={v.hint}
            disabled={pending}
            onClick={() => (v.value === "real" ? setVerdict("real") : submit(v.value, ""))}
            className="inline-flex items-center gap-1 rounded-lg border border-border bg-surface px-2 py-1 text-xs text-muted transition hover:border-border-strong hover:text-ink disabled:opacity-50"
          >
            <Icon className="h-3.5 w-3.5" /> {v.label}
          </button>
        );
      })}
      {pending && <Loader2 className="h-3.5 w-3.5 animate-spin text-faint" />}
      {error && <span className="text-xs text-danger">{error}</span>}
    </span>
  );
}
