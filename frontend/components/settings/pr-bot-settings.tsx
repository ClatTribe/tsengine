"use client";

import { useState, useTransition } from "react";
import { GitPullRequest, Loader2, Check } from "lucide-react";
import { setPRBotPolicy } from "@/app/(app)/settings/actions";
import type { PRBotSettings } from "@/lib/types";

// PRBotSettingsPanel configures the repository PR-review bot: post inline review comments on
// PR-changed lines + a merge-gating check-run that fails at/above a severity floor. The live
// GitHub post is gated on a connected GitHub App with the PR scope (surfaced honestly).
const SEVERITIES = [
  { id: "off", label: "Comment only (never block)" },
  { id: "critical", label: "Block at Critical" },
  { id: "high", label: "Block at High or above" },
  { id: "medium", label: "Block at Medium or above" },
  { id: "low", label: "Block at Low or above" },
];

export function PRBotSettingsPanel({ initial }: { initial: PRBotSettings }) {
  const [enabled, setEnabled] = useState(initial.enabled);
  const [blockSeverity, setBlockSeverity] = useState(initial.block_severity || "off");
  const [saved, setSaved] = useState(false);
  const [err, setErr] = useState("");
  const [pending, start] = useTransition();

  function save() {
    setErr("");
    setSaved(false);
    start(async () => {
      try {
        await setPRBotPolicy(enabled, blockSeverity);
        setSaved(true);
      } catch (e) {
        setErr(e instanceof Error ? e.message : "could not save the PR-bot policy");
      }
    });
  }

  return (
    <div className="space-y-3">
      <p className="text-xs text-muted">
        On every pull request, post inline review comments on the changed lines and a merge-gating
        check-run. Comments only ever land on lines the PR touched (no noise on untouched code).
      </p>

      <label className="flex items-center gap-2 text-sm">
        <input
          type="checkbox"
          checked={enabled}
          onChange={(e) => setEnabled(e.target.checked)}
          className="h-4 w-4 rounded border-border accent-accent"
        />
        Enable the PR-review bot
      </label>

      <div className="flex flex-wrap items-end gap-3">
        <label className="text-xs text-muted">
          Merge-gating
          <select
            value={blockSeverity}
            onChange={(e) => setBlockSeverity(e.target.value)}
            disabled={!enabled}
            className="mt-1 block rounded-lg border border-border bg-surface px-2.5 py-1.5 text-sm outline-none focus:border-accent disabled:opacity-50"
          >
            {SEVERITIES.map((s) => (
              <option key={s.id} value={s.id}>{s.label}</option>
            ))}
          </select>
        </label>
        <button
          onClick={save}
          disabled={pending}
          className="inline-flex items-center gap-2 rounded-lg bg-accent px-3.5 py-2 text-sm font-semibold text-white transition hover:bg-accent-hover disabled:opacity-50"
        >
          {pending ? <Loader2 className="h-4 w-4 animate-spin" /> : saved ? <Check className="h-4 w-4" /> : <GitPullRequest className="h-4 w-4" />}
          {saved ? "Saved" : "Save"}
        </button>
      </div>

      {!initial.github_connected && (
        <div className="rounded-lg bg-medium/10 px-3 py-2 text-xs text-medium">
          Connect a GitHub repository (with the PR scope) to let the bot post on pull requests.
          The policy saves now and takes effect once GitHub is connected.
        </div>
      )}
      {err && <div className="rounded-lg bg-critical/10 px-3 py-2 text-xs text-critical">{err}</div>}
    </div>
  );
}
