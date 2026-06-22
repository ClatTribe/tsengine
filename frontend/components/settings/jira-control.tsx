"use client";

import { useState, useTransition } from "react";
import { Ticket, Loader2, Check } from "lucide-react";
import { setJira } from "@/app/(app)/settings/actions";

// Per-tenant Jira ticketing destination (Bucket B). file_ticket remediations land in the tenant's
// OWN Jira. base/email/project are plain; the API token is sealed server-side and never shown again.
export function JiraControl({
  config,
}: {
  config: { base_url: string; email: string; project: string; has_token: boolean };
}) {
  const [baseUrl, setBaseUrl] = useState(config.base_url);
  const [email, setEmail] = useState(config.email);
  const [project, setProject] = useState(config.project);
  const [token, setToken] = useState("");
  const [hasToken, setHasToken] = useState(config.has_token);
  const [err, setErr] = useState("");
  const [saved, setSaved] = useState(false);
  const [pending, start] = useTransition();

  function save(clear: boolean) {
    setErr("");
    setSaved(false);
    start(async () => {
      try {
        const r = await setJira(
          clear
            ? { base_url: "", email: "", project: "", api_token: "" }
            : { base_url: baseUrl.trim(), email: email.trim(), project: project.trim(), api_token: token.trim() },
        );
        setBaseUrl(r.base_url);
        setEmail(r.email);
        setProject(r.project);
        setHasToken(r.has_token);
        setToken("");
        setSaved(true);
      } catch (e) {
        setErr(e instanceof Error ? e.message : "Failed to save");
      }
    });
  }

  const cls = "mono w-full rounded-md border border-border bg-surface px-2 py-1 text-xs text-ink placeholder:text-faint";
  return (
    <div className="rounded-xl border border-border bg-surface-2 px-3.5 py-3">
      <div className="flex items-center gap-3">
        <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-surface text-muted">
          <Ticket className="h-4 w-4" />
        </span>
        <div className="min-w-0 flex-1">
          <div className="text-sm font-medium">Jira</div>
          <div className="text-xs text-muted">Approved fixes file as tickets in your project</div>
        </div>
        <span className={`text-[11px] ${hasToken ? "text-accent" : "text-faint"}`}>{hasToken ? "configured" : "not set"}</span>
      </div>

      <div className="mt-2.5 grid gap-2 sm:grid-cols-2">
        <input value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} placeholder="https://acme.atlassian.net" className={cls} />
        <input value={project} onChange={(e) => setProject(e.target.value)} placeholder="Project key (e.g. SEC)" className={cls} />
        <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="bot@acme.io" className={cls} />
        <input
          type="password"
          value={token}
          onChange={(e) => setToken(e.target.value)}
          placeholder={hasToken ? "API token (leave blank to keep)" : "API token"}
          className={cls}
        />
      </div>

      <div className="mt-2 flex items-center gap-2">
        <button
          onClick={() => save(false)}
          disabled={pending || !baseUrl.trim()}
          className="inline-flex items-center gap-1 rounded-md bg-accent px-3 py-1 text-xs font-medium text-white transition hover:opacity-90 disabled:opacity-50"
        >
          {pending ? <Loader2 className="h-3 w-3 animate-spin" /> : saved ? <Check className="h-3 w-3" /> : null}
          {saved ? "Saved" : "Save"}
        </button>
        {hasToken && (
          <button
            onClick={() => save(true)}
            disabled={pending}
            className="rounded-md border border-border px-2 py-1 text-xs text-muted transition hover:border-critical/40 hover:text-critical disabled:opacity-50"
          >
            Clear
          </button>
        )}
        {err && <span className="text-[11px] text-critical">{err}</span>}
      </div>
    </div>
  );
}
