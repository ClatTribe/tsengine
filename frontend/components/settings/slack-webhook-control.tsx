"use client";

import { useState, useTransition } from "react";
import { MessageSquare, Loader2, Check } from "lucide-react";
import { setSlackWebhook } from "@/app/(app)/settings/actions";

// Per-tenant Slack incident webhook (Bucket B). The customer pastes their OWN Slack Incoming
// Webhook so new-incident heads-ups land in THEIR channel (not the operator's). The URL is a bearer
// capability: it is sealed server-side and never returned, so we only ever know whether one is set.
export function SlackWebhookControl({ configured }: { configured: boolean }) {
  const [hasHook, setHasHook] = useState(configured);
  const [value, setValue] = useState("");
  const [err, setErr] = useState("");
  const [saved, setSaved] = useState(false);
  const [pending, start] = useTransition();

  function save(clear: boolean) {
    setErr("");
    setSaved(false);
    start(async () => {
      try {
        const r = await setSlackWebhook(clear ? "" : value.trim());
        setHasHook(r.has_slack_webhook);
        setValue("");
        setSaved(true);
      } catch (e) {
        setErr(e instanceof Error ? e.message : "Failed to save");
      }
    });
  }

  return (
    <div className="rounded-xl border border-border bg-surface-2 px-3.5 py-3">
      <div className="flex items-center gap-3">
        <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-surface text-muted">
          <MessageSquare className="h-4 w-4" />
        </span>
        <div className="min-w-0 flex-1">
          <div className="text-sm font-medium">Slack</div>
          <div className="text-xs text-muted">New-incident heads-ups to your channel</div>
        </div>
        <span className={`text-[11px] ${hasHook ? "text-accent" : "text-faint"}`}>
          {hasHook ? "configured" : "not set"}
        </span>
      </div>

      <div className="mt-2.5 flex flex-wrap items-center gap-2">
        <input
          type="password"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder="https://hooks.slack.com/services/…"
          className="mono min-w-0 flex-1 rounded-md border border-border bg-surface px-2 py-1 text-xs text-ink placeholder:text-faint"
        />
        <button
          onClick={() => save(false)}
          disabled={pending || !value.trim()}
          className="inline-flex items-center gap-1 rounded-md bg-accent px-3 py-1 text-xs font-medium text-white transition hover:opacity-90 disabled:opacity-50"
        >
          {pending ? <Loader2 className="h-3 w-3 animate-spin" /> : saved ? <Check className="h-3 w-3" /> : null}
          {hasHook ? "Replace" : "Save"}
        </button>
        {hasHook && (
          <button
            onClick={() => save(true)}
            disabled={pending}
            className="rounded-md border border-border px-2 py-1 text-xs text-muted transition hover:border-critical/40 hover:text-critical disabled:opacity-50"
          >
            Clear
          </button>
        )}
      </div>
      <p className="mt-1.5 text-[11px] text-faint">
        Create an Incoming Webhook in your Slack workspace. Stored encrypted; never shown again.
      </p>
      {err && <p className="mt-1 text-[11px] text-critical">{err}</p>}
    </div>
  );
}
