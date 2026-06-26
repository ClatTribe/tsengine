"use client";

import { useState, useTransition } from "react";
import { Play, Loader2, Check, ChevronDown } from "lucide-react";
import { runCloudInvestigation } from "@/app/(app)/cloud-engineer/actions";
import { cn } from "@/lib/utils";

// RunInvestigation is the in-product trigger for the AI Cloud Engineer (the page previously only described
// the API/CLI path). The user pastes a cloud inventory snapshot + optional prowler findings and runs the
// agent; its proven attack paths flow into the page + issues + the vCISO risk desk. The agent is LLM-gated,
// so a missing-model run surfaces the server's clear configuration message rather than failing silently.
export function RunInvestigation() {
  const [open, setOpen] = useState(false);
  const [inventory, setInventory] = useState("");
  const [prowler, setProwler] = useState("");
  const [pending, start] = useTransition();
  const [error, setError] = useState("");
  const [done, setDone] = useState<{ pathsFound?: number; risksProposed?: number; summary?: string } | null>(null);

  function run() {
    setError("");
    setDone(null);
    start(async () => {
      const r = await runCloudInvestigation(inventory, prowler);
      if (!r.ok) setError(r.error ?? "Failed");
      else setDone({ pathsFound: r.pathsFound, risksProposed: r.risksProposed, summary: r.summary });
    });
  }

  return (
    <div className="rounded-xl border border-border bg-surface">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center justify-between px-5 py-3 text-left"
      >
        <span className="flex items-center gap-2 text-sm font-semibold text-ink">
          <Play className="h-4 w-4 text-accent" /> Run an investigation
        </span>
        <ChevronDown className={cn("h-4 w-4 text-faint transition", open && "rotate-180")} />
      </button>

      {open && (
        <div className="space-y-3 border-t border-border px-5 py-4">
          <p className="text-xs leading-relaxed text-muted">
            Paste a cloud inventory snapshot (a CloudQuery / Cartography export of your account&apos;s resources,
            identities, and IAM) and the agent investigates it — resolving effective permissions, tracing
            reachability, and proving the attack paths that reach a crown jewel. Optionally add prowler findings
            for richer context. The proven paths flow into this page, your issues, and the vCISO risk desk.
          </p>
          <div>
            <label className="mb-1 block text-xs font-medium text-muted">Cloud inventory (JSON) *</label>
            <textarea
              value={inventory}
              onChange={(e) => setInventory(e.target.value)}
              rows={6}
              spellCheck={false}
              placeholder={`{"account_id":"123456789012","provider":"aws","resources":[...],"trusts":[...],"reaches":[...]}`}
              className="mono w-full rounded-lg border border-border bg-surface-2 px-3 py-2 text-xs outline-none transition focus:border-accent"
            />
          </div>
          <details className="text-xs">
            <summary className="cursor-pointer text-muted">Add prowler findings (optional)</summary>
            <textarea
              value={prowler}
              onChange={(e) => setProwler(e.target.value)}
              rows={4}
              spellCheck={false}
              placeholder={`[ {"rule_id":"...","severity":"high", ...} ]`}
              className="mono mt-2 w-full rounded-lg border border-border bg-surface-2 px-3 py-2 text-xs outline-none transition focus:border-accent"
            />
          </details>

          {error && <div className="rounded-lg border border-critical/30 bg-critical/10 px-3 py-2 text-xs leading-relaxed text-critical">{error}</div>}
          {done && (
            <div className="rounded-lg border border-pulse/30 bg-pulse/10 px-3 py-2 text-xs leading-relaxed text-pulse">
              <span className="inline-flex items-center gap-1.5 font-medium"><Check className="h-3.5 w-3.5" /> Investigation complete</span>
              {" — "}{done.pathsFound ?? 0} attack {done.pathsFound === 1 ? "path" : "paths"} proven
              {(done.risksProposed ?? 0) > 0 ? `, ${done.risksProposed} candidate risk${done.risksProposed === 1 ? "" : "s"} on the vCISO desk` : ""}.
              {done.summary ? <span className="mt-1 block text-muted">{done.summary}</span> : null}
            </div>
          )}

          <button
            onClick={run}
            disabled={pending || inventory.trim() === ""}
            className="inline-flex items-center gap-2 rounded-xl bg-accent px-4 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover active:translate-y-px disabled:opacity-50"
          >
            {pending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
            {pending ? "Investigating…" : "Run investigation"}
          </button>
          <p className="text-[11px] leading-relaxed text-faint">
            The agent needs a model: configure one in Settings → LLM, or set <code className="mono">LLM_API_KEY</code> /
            a local Ollama. No model → you&apos;ll get a clear message here, never a silent fail.
          </p>
        </div>
      )}
    </div>
  );
}
