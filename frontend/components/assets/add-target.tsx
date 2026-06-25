"use client";

import { useState, useTransition } from "react";
import { Plus, Loader2, CheckCircle2, CircleAlert } from "lucide-react";
import { addTarget } from "@/app/(app)/assets/actions";

// The scan-target types a user can add by typing (repos/cloud/identity come from a connector;
// mobile needs a bundle upload). Placeholder + hint per type so the founder knows what to paste.
const TYPES: { value: string; label: string; placeholder: string }[] = [
  { value: "web_application", label: "Web app", placeholder: "https://app.acme.com" },
  { value: "api", label: "API", placeholder: "https://api.acme.com" },
  { value: "domain", label: "Domain", placeholder: "acme.com" },
  { value: "ip_address", label: "IP / host", placeholder: "203.0.113.10" },
  { value: "container_image", label: "Container image", placeholder: "ghcr.io/acme/api:1.4.2" },
];

export function AddTarget() {
  const [type, setType] = useState(TYPES[0].value);
  const [target, setTarget] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [pending, start] = useTransition();
  const placeholder = TYPES.find((t) => t.value === type)?.placeholder ?? "";

  function submit() {
    setMsg(null);
    start(async () => {
      const res = await addTarget(type, target.trim(), authorized);
      if (res.ok) {
        setMsg({ ok: true, text: "Target added — the agent will scan it on the next pass." });
        setTarget("");
        setAuthorized(false);
      } else {
        setMsg({ ok: false, text: res.error ?? "Could not add the target" });
      }
    });
  }

  const canSubmit = target.trim() !== "" && authorized && !pending;

  return (
    <div className="rounded-xl border border-border bg-surface p-4">
      <div className="flex items-center gap-2 text-sm font-medium text-ink">
        <Plus className="h-4 w-4 text-accent" /> Add a target
      </div>
      <p className="mt-1 text-xs text-muted">
        Point the agent at a web app, API, domain, IP, or container image you own — no connector needed.
      </p>

      <div className="mt-3 flex flex-col gap-2 sm:flex-row sm:items-center">
        <select
          value={type}
          onChange={(e) => setType(e.target.value)}
          className="rounded-lg border border-border bg-bg px-2.5 py-2 text-sm text-ink outline-none transition focus:border-accent"
        >
          {TYPES.map((t) => (
            <option key={t.value} value={t.value}>{t.label}</option>
          ))}
        </select>
        <input
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && canSubmit && submit()}
          placeholder={placeholder}
          className="flex-1 rounded-lg border border-border bg-bg px-3 py-2 text-sm text-ink outline-none transition placeholder:text-faint focus:border-accent"
        />
        <button
          onClick={submit}
          disabled={!canSubmit}
          className="inline-flex items-center justify-center gap-1.5 rounded-lg bg-accent px-3.5 py-2 text-sm font-semibold text-white transition hover:bg-accent-hover disabled:cursor-not-allowed disabled:opacity-50"
        >
          {pending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />}
          Add
        </button>
      </div>

      <label className="mt-2.5 flex cursor-pointer items-start gap-2 text-xs text-muted">
        <input
          type="checkbox"
          checked={authorized}
          onChange={(e) => setAuthorized(e.target.checked)}
          className="mt-0.5 h-3.5 w-3.5 accent-[var(--accent,#6366f1)]"
        />
        <span>I&apos;m authorized to scan this target (I own it or have written permission).</span>
      </label>

      {msg && (
        <div
          className={`mt-2.5 flex items-center gap-1.5 text-xs ${msg.ok ? "text-emerald-600" : "text-red-600"}`}
        >
          {msg.ok ? <CheckCircle2 className="h-3.5 w-3.5" /> : <CircleAlert className="h-3.5 w-3.5" />}
          {msg.text}
        </div>
      )}
    </div>
  );
}
