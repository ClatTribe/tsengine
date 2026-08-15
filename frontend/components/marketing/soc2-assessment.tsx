"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { ShieldCheck, ArrowRight, RotateCcw, Check, X, MinusCircle } from "lucide-react";
import { QUESTIONS, AREAS, scoreAssessment, type Answer } from "@/lib/soc2";

const GRADE_TONE: Record<string, string> = {
  A: "text-pulse", B: "text-pulse", C: "text-medium", D: "text-high", F: "text-critical",
};
const OPTIONS: { value: Answer; label: string; icon: typeof Check }[] = [
  { value: "yes", label: "Yes", icon: Check },
  { value: "partial", label: "Partly", icon: MinusCircle },
  { value: "no", label: "No", icon: X },
];

export function SOC2Assessment() {
  const [answers, setAnswers] = useState<Record<string, Answer>>({});
  const [submitted, setSubmitted] = useState(false);

  const result = useMemo(() => scoreAssessment(answers), [answers]);
  const allAnswered = result.answered === result.total;

  function reset() {
    setAnswers({});
    setSubmitted(false);
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  if (submitted) {
    const good = result.grade === "A" || result.grade === "B";
    return (
      <div className="mx-auto max-w-2xl animate-fade-rise space-y-5">
        <div className="card flex items-center gap-5 p-6">
          <div className={`grid h-20 w-20 shrink-0 place-items-center rounded-2xl border-2 ${good ? "border-pulse/40 bg-pulse-soft" : "border-high/40 bg-high/10"}`}>
            <span className={`text-4xl font-bold ${GRADE_TONE[result.grade]}`}>{result.grade}</span>
          </div>
          <div className="min-w-0">
            <div className="text-2xl font-semibold tracking-tight">
              SOC 2 readiness: <span className={GRADE_TONE[result.grade]}>{result.score}%</span>
            </div>
            <p className="mt-1 text-sm text-muted">
              {result.gaps.length === 0
                ? "You're in strong shape on the basics auditors check first."
                : `${result.gaps.length} gap${result.gaps.length === 1 ? "" : "s"} to close before a Type I — prioritized below.`}
            </p>
          </div>
        </div>

        {result.gaps.length > 0 && (
          <div className="card p-0">
            <div className="border-b border-border px-5 py-3 text-sm font-semibold">Close these first</div>
            <ul className="divide-y divide-border">
              {result.gaps.map((q) => (
                <li key={q.id} className="px-5 py-3">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium">{q.text}</span>
                    <span className="mono shrink-0 rounded bg-surface-2 px-1.5 py-0.5 text-[10px] text-faint">{q.cc}</span>
                  </div>
                  <p className="mt-1 text-xs text-muted">{q.tip}</p>
                </li>
              ))}
            </ul>
          </div>
        )}

        <div className="rounded-2xl border border-accent/30 bg-accent-soft/30 p-5 text-center">
          <div className="flex items-center justify-center gap-2 text-sm font-semibold">
            <ShieldCheck className="h-4 w-4 text-accent" /> Close these automatically.
          </div>
          <p className="mx-auto mt-1.5 max-w-md text-sm text-muted">
            TensorShield connects to your code, cloud, and identity, finds these gaps for real, maps each to its SOC 2
            control, and writes the fix — with you approving anything that matters.
          </p>
          <div className="mt-4 flex flex-wrap items-center justify-center gap-2">
            <Link href="/signup" className="inline-flex items-center gap-2 rounded-xl bg-accent px-5 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover active:translate-y-px">
              See your full posture — free <ArrowRight className="h-4 w-4" />
            </Link>
            <Link href="/scan" className="inline-flex items-center gap-2 rounded-xl border border-border px-5 py-2.5 text-sm font-medium transition hover:border-accent/40 hover:text-accent">
              Or run the 30-second external scan
            </Link>
          </div>
        </div>

        <SOC2LeadCapture grade={result.grade} score={result.score} gaps={result.gaps.length} />

        <button onClick={reset} className="mx-auto flex items-center gap-1.5 text-xs text-muted transition hover:text-accent">
          <RotateCcw className="h-3.5 w-3.5" /> Start over
        </button>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      {AREAS.map((area) => (
        <div key={area}>
          <h2 className="mb-2 text-sm font-semibold uppercase tracking-wider text-ink">{area}</h2>
          <div className="card divide-y divide-border p-0">
            {QUESTIONS.filter((q) => q.area === area).map((q) => (
              <div key={q.id} className="flex flex-col gap-2 px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
                <span className="text-sm">{q.text}</span>
                <div className="flex shrink-0 gap-1.5">
                  {OPTIONS.map((o) => {
                    const active = answers[q.id] === o.value;
                    const Icon = o.icon;
                    return (
                      <button
                        key={o.value}
                        onClick={() => setAnswers((a) => ({ ...a, [q.id]: o.value }))}
                        className={`inline-flex items-center gap-1 rounded-md border px-2.5 py-1 text-xs font-medium transition ${
                          active
                            ? o.value === "yes"
                              ? "border-pulse/40 bg-pulse-soft text-pulse"
                              : o.value === "no"
                                ? "border-critical/40 bg-critical/10 text-critical"
                                : "border-medium/40 bg-medium/10 text-medium"
                            : "border-border text-muted hover:border-accent/40"
                        }`}
                      >
                        <Icon className="h-3 w-3" /> {o.label}
                      </button>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        </div>
      ))}

      <div className="sticky bottom-4 z-10 flex items-center justify-between rounded-xl border border-border bg-surface/95 px-4 py-3 shadow-lg backdrop-blur">
        <span className="text-xs text-muted">{result.answered}/{result.total} answered</span>
        <button
          onClick={() => {
            setSubmitted(true);
            window.scrollTo({ top: 0, behavior: "smooth" });
          }}
          disabled={result.answered === 0}
          className="inline-flex items-center gap-2 rounded-xl bg-accent px-5 py-2 text-sm font-semibold text-white transition hover:bg-accent-hover disabled:opacity-50"
        >
          {allAnswered ? "See my readiness score" : "See my score so far"} <ArrowRight className="h-4 w-4" />
        </button>
      </div>
    </div>
  );
}

// SOC2LeadCapture closes the other half of the inbound funnel. /scan captures a lead once the
// visitor has their grade; this page — a fifteen-question assessment somebody has just finished,
// which makes them far more engaged than a drive-by scanner — captured nothing at all. They saw
// their score, saw their prioritised gaps, and left anonymous.
//
// The same two rules the /scan capture follows:
//
//  1. It renders AFTER the result. Everything the visitor came for is already on screen and free.
//     Gating a self-assessment behind an email would be the fastest way to kill the thing that
//     makes it worth linking to.
//  2. The offer is only what we actually do. Not "email me my results" — nothing sends a results
//     email, and promising one on the page that is meant to demonstrate rigour would be exactly
//     the kind of unbacked claim this product sells against. We help people close the gaps, so
//     that is what it says.
//
// Posts to the same public /api/lead as the demo form and the scan, with source
// "soc2-readiness:<grade>" and the score and gap count in the message, so a reply can open on the
// person's real result instead of a generic pitch.
function SOC2LeadCapture({ grade, score, gaps }: { grade: string; score: number; gaps: number }) {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [state, setState] = useState<"idle" | "sending" | "done" | "error">("idle");

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!name.trim() || !email.trim()) return;
    setState("sending");
    try {
      const res = await fetch("/api/lead", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          // /v1/lead requires a name, so it is asked for rather than guessed from the email.
          name: name.trim(),
          email: email.trim(),
          company: "",
          source: `soc2-readiness:${grade}`,
          message:
            gaps > 0
              ? `Completed the SOC 2 self-assessment — grade ${grade}, ${score}%, ${gaps} gap(s) to close. Asked for help closing them.`
              : `Completed the SOC 2 self-assessment — grade ${grade}, ${score}%, no gaps flagged. Asked to talk.`,
        }),
      });
      setState(res.ok ? "done" : "error");
    } catch {
      setState("error");
    }
  }

  if (state === "done") {
    return (
      <div className="card flex items-start gap-3 p-5">
        <Check className="mt-0.5 h-4 w-4 shrink-0 text-pulse" />
        <p className="text-sm text-muted">
          Got it — we&apos;ll be in touch about closing these. Nothing else happens to your address.
        </p>
      </div>
    );
  }

  return (
    <form onSubmit={submit} className="card p-5">
      <div className="text-sm font-medium text-ink">
        {gaps > 0 ? "Want a hand closing these gaps?" : "Want to check the parts a self-assessment can't?"}
      </div>
      <p className="mt-1 text-xs leading-relaxed text-muted">
        {gaps > 0
          ? "Leave your email and we'll get in touch. Your results above are yours either way — no signup needed."
          : "This is your own answers scored. Leave your email and we'll talk about verifying them against your real code, cloud and identity."}
      </p>
      <div className="mt-3 flex flex-col gap-2 sm:flex-row">
        <input
          type="text"
          required
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Your name"
          className="min-w-0 rounded-lg border border-border bg-surface px-3 py-2 text-sm text-ink outline-none transition focus:border-accent/60 sm:w-36"
        />
        <input
          type="email"
          required
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="you@company.com"
          className="min-w-0 flex-1 rounded-lg border border-border bg-surface px-3 py-2 text-sm text-ink outline-none transition focus:border-accent/60"
        />
        <button
          type="submit"
          disabled={state === "sending"}
          className="inline-flex shrink-0 items-center justify-center gap-2 rounded-lg bg-accent px-4 py-2 text-sm font-semibold text-white transition hover:bg-accent-hover disabled:opacity-60"
        >
          {state === "sending" ? "Sending…" : "Get in touch"}
        </button>
      </div>
      {state === "error" && <p className="mt-2 text-xs text-high">Couldn&apos;t send that — try again.</p>}
    </form>
  );
}
