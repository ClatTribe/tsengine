"use client";

import { useState, useTransition } from "react";
import { Wrench, Loader2, Check } from "lucide-react";
import { setCloudRemediation } from "@/app/(app)/settings/actions";
import { cn } from "@/lib/utils";

// Per-tenant cloud-remediation config (Bucket B). The customer supplies their OWN cross-account
// write role/SA; the agent uses it only at HITL-approved remediation time. AWS needs a role ARN,
// GCP a write service-account to impersonate, Azure just the enable flag (subscription = the
// connection's account). Stored as non-secret connection config; the actual write stays gated.
export function CloudRemediationControl({
  id,
  kind,
  config,
}: {
  id: string;
  kind: string;
  config?: Record<string, string>;
}) {
  const [open, setOpen] = useState(false);
  const [enabled, setEnabled] = useState(config?.remediation_enabled === "true");
  const [roleArn, setRoleArn] = useState(config?.remediation_role_arn ?? "");
  const [region, setRegion] = useState(config?.remediation_region ?? "");
  const [sa, setSa] = useState(config?.remediation_impersonate_sa ?? "");
  const [err, setErr] = useState("");
  const [saved, setSaved] = useState(false);
  const [pending, start] = useTransition();

  function save() {
    setErr("");
    setSaved(false);
    start(async () => {
      try {
        const r = await setCloudRemediation(id, {
          enabled,
          role_arn: roleArn.trim(),
          region: region.trim(),
          impersonate_sa: sa.trim(),
        });
        setEnabled(r.config?.remediation_enabled === "true");
        setSaved(true);
      } catch (e) {
        setErr(e instanceof Error ? e.message : "Failed to save");
      }
    });
  }

  return (
    <div className="w-full">
      <button
        onClick={() => setOpen((o) => !o)}
        className={cn(
          "inline-flex items-center gap-1 rounded-md border px-2 py-1 text-[11px] font-medium transition",
          enabled ? "border-accent/40 bg-accent/10 text-accent" : "border-border text-muted hover:border-accent/40",
        )}
      >
        <Wrench className="h-3 w-3" />
        Auto-remediation {enabled ? "on" : "off"}
      </button>

      {open && (
        <div className="mt-2 space-y-2 rounded-lg border border-border bg-surface-2 p-3">
          <label className="flex items-center gap-2 text-xs text-ink">
            <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
            Enable live remediation into this {kind.toUpperCase()} account (HITL-approved writes only)
          </label>

          {kind === "aws" && (
            <>
              <input
                value={roleArn}
                onChange={(e) => setRoleArn(e.target.value)}
                placeholder="arn:aws:iam::123456789012:role/tsengine-remediate"
                className="mono w-full rounded-md border border-border bg-surface px-2 py-1 text-xs text-ink placeholder:text-faint"
              />
              <input
                value={region}
                onChange={(e) => setRegion(e.target.value)}
                placeholder="us-east-1 (optional)"
                className="mono w-full rounded-md border border-border bg-surface px-2 py-1 text-xs text-ink placeholder:text-faint"
              />
            </>
          )}
          {kind === "gcp" && (
            <input
              value={sa}
              onChange={(e) => setSa(e.target.value)}
              placeholder="remediate@project.iam.gserviceaccount.com"
              className="mono w-full rounded-md border border-border bg-surface px-2 py-1 text-xs text-ink placeholder:text-faint"
            />
          )}

          <p className="text-[11px] text-faint">
            This is your own cross-account write role — an identifier, not a secret. The agent assumes it
            only after a human approves a fix. A wrong role surfaces an error; it never reports a false success.
          </p>

          {err && <p className="text-[11px] text-critical">{err}</p>}
          <button
            onClick={save}
            disabled={pending}
            className="inline-flex items-center gap-1 rounded-md bg-accent px-3 py-1 text-xs font-medium text-white transition hover:opacity-90 disabled:opacity-50"
          >
            {pending ? <Loader2 className="h-3 w-3 animate-spin" /> : saved ? <Check className="h-3 w-3" /> : null}
            {saved ? "Saved" : "Save"}
          </button>
        </div>
      )}
    </div>
  );
}
