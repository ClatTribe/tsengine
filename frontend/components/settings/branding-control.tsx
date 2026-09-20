"use client";

import { useState, useTransition } from "react";
import { Loader2, Check, Palette } from "lucide-react";
import { setBranding } from "@/app/(app)/settings/actions";
import type { BrandingSettings } from "@/lib/types";

// White-label. The MSP / consultancy motion resells the managed tier under the partner's name, and
// every outward artifact — the VAPT report a customer's security team reads, the public Trust
// Center a buyer opens — said TensorShield. This puts the partner's name, logo and support address
// on those artifacts.
//
// What it does NOT do, stated here because a partner will ask: the engine identifier in a report's
// provenance block stays. That line is evidence about how the assessment was produced, and a
// rebrand that erased it would be a claim about provenance rather than a coat of paint.
export function BrandingControl({ initial }: { initial: BrandingSettings }) {
  const [name, setName] = useState(initial.branding.name ?? "");
  const [logo, setLogo] = useState(initial.branding.logo_url ?? "");
  const [email, setEmail] = useState(initial.branding.support_email ?? "");
  const [state, setState] = useState<BrandingSettings>(initial);
  const [err, setErr] = useState("");
  const [saved, setSaved] = useState(false);
  const [pending, start] = useTransition();

  function save(e: React.FormEvent) {
    e.preventDefault();
    setErr("");
    setSaved(false);
    start(async () => {
      try {
        const r = await setBranding({ name, logo_url: logo, support_email: email });
        setState(r);
        setSaved(true);
      } catch (ex) {
        setErr(ex instanceof Error ? ex.message : "could not save");
      }
    });
  }

  return (
    <form onSubmit={save} className="space-y-3">
      <p className="text-xs leading-relaxed text-muted">
        The name, logo and support address on what this workspace hands to other people — the VAPT report and the
        public Trust Center. Leave the name empty to use {state.default_brand}. Today these read as{" "}
        <span className="font-medium text-ink">{state.effective_name}</span>
        {state.white_labelled ? " (white-labelled)" : ""}.
      </p>
      <div className="grid gap-2 sm:grid-cols-3">
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Brand name (e.g. Northwind Security)" maxLength={64}
          className="rounded-lg border border-border bg-surface px-3 py-2 text-sm outline-none transition focus:border-accent" />
        <input value={logo} onChange={(e) => setLogo(e.target.value)} placeholder="Logo URL (https://…)" type="url"
          className="rounded-lg border border-border bg-surface px-3 py-2 text-sm outline-none transition focus:border-accent" />
        <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="Support email (optional)" type="email"
          className="rounded-lg border border-border bg-surface px-3 py-2 text-sm outline-none transition focus:border-accent" />
      </div>
      <p className="text-[11px] leading-relaxed text-faint">
        Rebrands the wording and the page chrome. The engine line in a report&apos;s provenance block is not
        rebranded — it records what produced the assessment, which an auditor needs.
      </p>
      {err && <p className="text-xs text-critical">{err}</p>}
      <div className="flex items-center gap-3">
        <button type="submit" disabled={pending}
          className="inline-flex items-center gap-1.5 rounded-lg bg-accent px-3 py-1.5 text-sm font-semibold text-white transition hover:bg-accent-hover active:translate-y-px disabled:opacity-60">
          {pending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Palette className="h-3.5 w-3.5" />} Save branding
        </button>
        {saved && <span className="inline-flex items-center gap-1 text-xs text-pulse"><Check className="h-3.5 w-3.5" /> Saved</span>}
      </div>
    </form>
  );
}
