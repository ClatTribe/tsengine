"use client";

import { useState, useTransition } from "react";
import { Search, Loader2 } from "lucide-react";
import { askEstate, type AskResult } from "@/app/(app)/engineer/actions";

// AskEstate is the answer to the question a security engineer asks most: "are we exposed to X?"
//
// The AI Security Engineer has had this capability the whole time (its search_estate tool) and no human
// could reach it — the person paying for the product had to browse a list and hope. This is the same
// query, exposed.
//
// It answers from STORED FINDINGS with no model in the loop, so it returns instantly and cannot invent
// an exposure. That matters more here than anywhere else in the product: this is the one question where
// a wrong answer is worse than no answer, because an engineer acts on it and a silently-missed match
// reads exactly like a clean estate.
const SUGGESTIONS = [
  "anything mentioning log4j",
  "critical unproven findings",
  "unproven injection",
  "leaked secrets",
];

export function AskEstate() {
  const [q, setQ] = useState("");
  const [pending, start] = useTransition();
  const [res, setRes] = useState<AskResult | null>(null);

  function run(question?: string) {
    const text = (question ?? q).trim();
    if (!text) return;
    setQ(text);
    setRes(null);
    start(async () => setRes(await askEstate(text)));
  }

  return (
    <div className="rounded-xl border border-border bg-surface p-5">
      <div className="flex items-center gap-2 text-sm font-semibold text-ink">
        <Search className="h-4 w-4 text-accent" /> Ask your estate
      </div>
      <p className="mt-1 text-xs leading-relaxed text-muted">
        Answered from your own findings — no model, so it can&apos;t invent an exposure. An empty answer
        means nothing matched.
      </p>

      <form
        className="mt-3 flex gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          run();
        }}
      >
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Are we exposed to log4j?"
          aria-label="Ask a question about your estate"
          className="flex-1 rounded-lg border border-border bg-bg px-3 py-2 text-sm text-ink placeholder:text-muted/70 focus:border-accent focus:outline-none"
        />
        <button
          type="submit"
          disabled={pending || !q.trim()}
          className="inline-flex items-center gap-1.5 rounded-lg bg-accent px-3.5 py-2 text-sm font-medium text-accent-ink disabled:opacity-50"
        >
          {pending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Search className="h-3.5 w-3.5" />}
          Ask
        </button>
      </form>

      <div className="mt-2.5 flex flex-wrap gap-1.5">
        {SUGGESTIONS.map((s) => (
          <button
            key={s}
            type="button"
            onClick={() => run(s)}
            disabled={pending}
            className="rounded-full border border-border px-2.5 py-1 text-xs text-muted hover:border-accent/40 hover:text-ink disabled:opacity-50"
          >
            {s}
          </button>
        ))}
      </div>

      {res && (
        <div className="mt-4">
          {res.ok ? (
            <pre className="max-h-96 overflow-auto whitespace-pre-wrap rounded-lg border border-border bg-bg p-3 text-xs leading-relaxed text-muted">
              {res.answer?.trim() || "Nothing in your estate matches that."}
            </pre>
          ) : (
            <p className="rounded-lg border border-danger/30 bg-danger/5 px-3 py-2 text-xs text-danger">{res.error}</p>
          )}
        </div>
      )}
    </div>
  );
}
