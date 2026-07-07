"use client";

import { useState, useTransition } from "react";
import { Play, Loader2, ShieldCheck, ShieldOff } from "lucide-react";
import { runCodeInvestigation, type CodeInvestigationResult } from "@/app/(app)/code-engineer/actions";
import { SeverityBadge } from "@/components/ui/primitives";

// RunCodeInvestigation is the in-product trigger for the AI Code Engineer. The user posts code findings +
// the repo source they touch; the specialist OPENS the source, traces taint to the sink (or a secret to its
// usage), and returns a grounded verdict per finding — EXPLOITABLE (with blast radius + right-layer fix) or
// CONTAINED (noise the scanner over-reported). Confirmed-exploitable ones persist as verified findings.
// LLM-gated: a missing model surfaces the server's clear message, never a silent fail.
export function RunCodeInvestigation() {
  const [repo, setRepo] = useState("");
  const [findings, setFindings] = useState("");
  const [source, setSource] = useState("");
  const [pending, start] = useTransition();
  const [res, setRes] = useState<CodeInvestigationResult | null>(null);

  function run() {
    setRes(null);
    start(async () => setRes(await runCodeInvestigation(repo, findings, source)));
  }

  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-border bg-surface p-5">
        <p className="text-xs leading-relaxed text-muted">
          Post your code findings (from semgrep / gitleaks / trivy) plus the source files they touch. The code
          specialist opens the real code, traces whether the finding is <span className="font-medium text-ink">actually
          exploitable</span>, measures a leaked secret&apos;s <span className="font-medium text-ink">blast radius</span>,
          and tells you <span className="font-medium text-ink">where the fix belongs</span> — the depth a scanner
          can&apos;t give. When a repo is connected, your AI Security Engineer does this automatically during triage.
        </p>
        <div className="mt-3 space-y-3">
          <input
            value={repo}
            onChange={(e) => setRepo(e.target.value)}
            placeholder="repo (e.g. acme/api)"
            className="mono w-full rounded-lg border border-border bg-surface-2 px-3 py-2 text-xs outline-none transition focus:border-accent"
          />
          <div>
            <label className="mb-1 block text-xs font-medium text-muted">Code findings (JSON array) *</label>
            <textarea
              value={findings}
              onChange={(e) => setFindings(e.target.value)}
              rows={5}
              spellCheck={false}
              placeholder={`[ {"id":"f1","tool":"semgrep","severity":"high","endpoint":"api/handler.go:12","title":"SQL string concatenation"} ]`}
              className="mono w-full rounded-lg border border-border bg-surface-2 px-3 py-2 text-xs outline-none transition focus:border-accent"
            />
          </div>
          <div>
            <label className="mb-1 block text-xs font-medium text-muted">Source (JSON: path → file content) *</label>
            <textarea
              value={source}
              onChange={(e) => setSource(e.target.value)}
              rows={6}
              spellCheck={false}
              placeholder={`{ "api/handler.go": "package api\\nfunc Search(...) { ... }" }`}
              className="mono w-full rounded-lg border border-border bg-surface-2 px-3 py-2 text-xs outline-none transition focus:border-accent"
            />
          </div>
        </div>

        {res?.ok === false && (
          <div className="mt-3 rounded-lg border border-critical/30 bg-critical/10 px-3 py-2 text-xs leading-relaxed text-critical">{res.error}</div>
        )}

        <button
          onClick={run}
          disabled={pending || findings.trim() === "" || source.trim() === ""}
          className="mt-3 inline-flex items-center gap-2 rounded-xl bg-accent px-4 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover active:translate-y-px disabled:opacity-50"
        >
          {pending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
          {pending ? "Reading your code…" : "Assess at source"}
        </button>
        <p className="mt-2 text-[11px] leading-relaxed text-faint">
          The agent needs a model: configure one in Settings → LLM. No model → a clear message here, never a silent fail.
        </p>
      </div>

      {res?.ok && (
        <div className="space-y-3">
          <div className="rounded-lg border border-pulse/30 bg-pulse/10 px-4 py-3 text-sm text-pulse">
            Assessed <span className="font-semibold">{res.assessed ?? 0}</span> finding
            {(res.assessed ?? 0) === 1 ? "" : "s"} at source — <span className="font-semibold">{res.confirmed ?? 0}</span> confirmed
            exploitable{(res.confirmed ?? 0) > 0 ? " (now tracked as verified findings)" : ""}.
            {res.summary ? <span className="mt-1 block text-muted">{res.summary}</span> : null}
          </div>
          {(res.issues ?? []).map((is) => (
            <div key={is.id} className="card p-4">
              <div className="flex flex-wrap items-center gap-2">
                {is.exploitable ? (
                  <span className="inline-flex items-center gap-1 rounded border border-critical/40 bg-critical/10 px-1.5 py-px text-[10px] font-semibold text-critical">
                    <ShieldOff className="h-3 w-3" /> EXPLOITABLE
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1 rounded border border-low/40 bg-low/10 px-1.5 py-px text-[10px] font-semibold text-low">
                    <ShieldCheck className="h-3 w-3" /> CONTAINED
                  </span>
                )}
                <span className="text-sm font-medium text-ink">{is.title || is.finding_id}</span>
                {is.severity && <SeverityBadge severity={is.severity} />}
              </div>
              {is.rationale && <p className="mt-1.5 text-sm leading-relaxed text-muted">{is.rationale}</p>}
              {is.blast_radius && <p className="mt-1 text-xs text-muted"><span className="font-medium text-ink">Blast radius:</span> {is.blast_radius}</p>}
              {(is.fix_location || is.fix) && (
                <p className="mt-1 text-xs text-muted"><span className="font-medium text-ink">Fix{is.fix_location ? ` (${is.fix_location})` : ""}:</span> {is.fix}</p>
              )}
              {(is.evidence?.length ?? 0) > 0 && (
                <div className="mono mt-1.5 text-[11px] text-faint">grounded in: {is.evidence!.join(", ")}</div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
