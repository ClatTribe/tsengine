"use client";

import { useState, useTransition } from "react";
import { GitPullRequest, Loader2, Check, Terminal, Copy } from "lucide-react";
import { setPRBotPolicy } from "@/app/(app)/settings/actions";
import type { PRBotSettings } from "@/lib/types";

// The copy-paste CI gate: post the PR's changed lines + the scan findings to /v1/ci/pr-check; the call
// exits non-zero (fails the build) when a high+ finding lands on a changed line. Works in any CI today —
// with a GitHub App configured the same call also posts the review to the PR. Full GitHub Action: docs/ci/github-action.yml.
const CI_SNIPPET = `# Fail the PR when a high+ finding lands on a changed line (any CI).
curl -sS -X POST "$TENSORSHIELD_URL/v1/ci/pr-check" \\
  -H "Authorization: Bearer $TENSORSHIELD_TOKEN" \\
  -d "$(jq -n --argjson cf "$CHANGED_FILES" --argjson f "$FINDINGS" \\
        '{changed_files:$cf, findings:$f}')" \\
  | jq -e '.blocked == false'   # non-zero exit blocks the merge`;

// PRBotSettingsPanel configures the repository PR-review bot: post inline review comments on
// PR-changed lines + a merge-gating check-run that fails at/above a severity floor. Whether the
// review actually lands in the PR is the SERVER's answer (posting_live + not_posting_reason), rendered verbatim.
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
  const [installationId, setInstallationId] = useState(initial.installation_id ?? "");
  const [saved, setSaved] = useState(false);
  const [err, setErr] = useState("");
  const [copied, setCopied] = useState(false);
  const [pending, start] = useTransition();

  function copySnippet() {
    navigator.clipboard?.writeText(CI_SNIPPET).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }

  function save() {
    setErr("");
    setSaved(false);
    start(async () => {
      try {
        await setPRBotPolicy(enabled, blockSeverity, installationId.trim());
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

      {/* Where the App is installed. The id is what GitHub shows on the installation page
          (github.com/organizations/ORG/settings/installations/ID). Without it the gate still
          runs from the CI exit code; with it the check-run and comments land in the PR. */}
      <label className="block text-xs text-muted">
        GitHub App installation id
        <input
          value={installationId}
          onChange={(e) => setInstallationId(e.target.value)}
          inputMode="numeric"
          placeholder="e.g. 12345678"
          disabled={!initial.github_connected}
          className="mt-1 block w-48 rounded-lg border border-border bg-surface px-2.5 py-1.5 font-mono text-sm outline-none focus:border-accent disabled:opacity-50"
        />
      </label>

      {/* The posting status is the SERVER's — three facts with three owners, and the reason names
          the first missing one. Re-deriving it here would let the page disagree with the gate. */}
      {initial.posting_live ? (
        <div className="rounded-lg bg-accent/10 px-3 py-2 text-xs text-accent">
          Reviews are posted to your pull requests as the GitHub App: a merge-gating check-run plus
          inline comments on the changed lines.
        </div>
      ) : (
        <div className="rounded-lg bg-medium/10 px-3 py-2 text-xs text-medium">
          Not posting to pull requests yet: {initial.not_posting_reason || "the GitHub App is not set up."}{" "}
          The merge gate still works from the CI step&apos;s exit code.
        </div>
      )}
      {err && <div className="rounded-lg bg-critical/10 px-3 py-2 text-xs text-critical">{err}</div>}

      <details className="rounded-lg border border-border bg-surface-2/40 px-3 py-2 text-xs">
        <summary className="flex cursor-pointer items-center gap-2 font-medium text-ink">
          <Terminal className="h-3.5 w-3.5 text-accent" /> Run the gate in CI (GitHub, GitLab, any)
        </summary>
        <p className="mt-2 text-muted">
          Don&apos;t want to wait for the GitHub App? Fail the build directly from CI — POST the PR&apos;s
          changed lines + your scan findings and the call exits non-zero when a high+ finding lands on a
          changed line. Full GitHub Action:{" "}
          <code className="mono text-accent">docs/ci/github-action.yml</code>.
        </p>
        <div className="relative mt-2">
          <pre className="overflow-x-auto rounded-lg bg-ink/90 p-3 text-[11px] leading-relaxed text-surface">
            {CI_SNIPPET}
          </pre>
          <button
            onClick={copySnippet}
            className="absolute right-2 top-2 inline-flex items-center gap-1 rounded-md bg-surface/15 px-2 py-1 text-[11px] font-medium text-surface transition hover:bg-surface/25"
          >
            {copied ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />} {copied ? "Copied" : "Copy"}
          </button>
        </div>
      </details>
    </div>
  );
}
