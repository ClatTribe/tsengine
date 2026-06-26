"use client";

import { useState, useTransition } from "react";
import { Loader2, Check, Sparkles } from "lucide-react";
import { FRAMEWORKS, FRAMEWORK_LABEL } from "@/lib/frameworks";
import type { ComplianceProfile, ComplianceScope } from "@/lib/types";
import { saveComplianceScope } from "./actions";

const PROFILE_QUESTIONS: { key: keyof ComplianceProfile; label: string }[] = [
  { key: "handles_phi", label: "We handle protected health information (PHI)" },
  { key: "processes_cards", label: "We process or store payment-card data" },
  { key: "sells_to_gov", label: "We sell to US government / defense" },
  { key: "eu_data_subjects", label: "We handle EU residents' personal data" },
  { key: "india_data_subject", label: "We handle Indian residents' personal data" },
  { key: "public_company", label: "We are a public company (or preparing to be)" },
];

export function ScopeForm({ initial }: { initial: ComplianceScope }) {
  const [profile, setProfile] = useState<ComplianceProfile>(initial.compliance_profile);
  const [targets, setTargets] = useState<string[]>(initial.target_frameworks ?? []);
  const [suggested, setSuggested] = useState<string[]>(initial.suggested ?? []);
  const [pending, start] = useTransition();
  const [msg, setMsg] = useState<string | null>(null);

  // Local mirror of the backend SuggestedFrameworks gating (so suggestions update live as boxes toggle).
  function recompute(p: ComplianceProfile) {
    const s = ["soc2", "iso27001", "cis_v8", "nist_csf"];
    if (p.handles_phi) s.push("hipaa");
    if (p.processes_cards) s.push("pci");
    if (p.sells_to_gov) s.push("fedramp", "nist_800_53", "nist_800_171", "cmmc");
    if (p.eu_data_subjects) s.push("gdpr", "iso27701");
    if (p.india_data_subject) s.push("dpdp");
    if (p.public_company) s.push("sox");
    setSuggested([...new Set(s)]);
  }
  function toggleProfile(key: keyof ComplianceProfile) {
    const next = { ...profile, [key]: !profile[key] };
    setProfile(next);
    recompute(next);
  }
  function toggleTarget(f: string) {
    setTargets((t) => (t.includes(f) ? t.filter((x) => x !== f) : [...t, f]));
  }
  function save() {
    setMsg(null);
    start(async () => {
      const r = await saveComplianceScope(targets, profile);
      setMsg(r.ok ? "Saved — your posture + readiness now focus on this scope." : (r.error ?? "Failed"));
    });
  }

  return (
    <div className="space-y-5">
      <section className="card space-y-3 p-5">
        <div className="text-sm font-medium">1. What applies to you?</div>
        <div className="grid gap-2 sm:grid-cols-2">
          {PROFILE_QUESTIONS.map((q) => (
            <label key={q.key} className="flex cursor-pointer items-start gap-2 text-sm">
              <input type="checkbox" checked={!!profile[q.key]} onChange={() => toggleProfile(q.key)} className="mt-0.5" />
              <span className={profile[q.key] ? "text-ink" : "text-muted"}>{q.label}</span>
            </label>
          ))}
        </div>
        {suggested.length > 0 && (
          <div className="flex flex-wrap items-center gap-1.5 rounded-lg border border-accent/30 bg-accent-soft/20 px-3 py-2 text-xs">
            <Sparkles className="h-3.5 w-3.5 text-accent" />
            <span className="text-muted">Suggested for you:</span>
            {suggested.map((f) => (
              <button key={f} onClick={() => !targets.includes(f) && toggleTarget(f)} className="rounded border border-border bg-surface px-1.5 py-0.5 text-ink hover:border-accent/40">
                {FRAMEWORK_LABEL[f] ?? f}
              </button>
            ))}
            <button onClick={() => setTargets([...new Set([...targets, ...suggested])])} className="ml-auto font-medium text-accent hover:underline">Select all suggested</button>
          </div>
        )}
      </section>

      <section className="card space-y-3 p-5">
        <div className="text-sm font-medium">2. Which frameworks are you pursuing?</div>
        <p className="text-xs text-muted">Your posture, coverage, and the connect-this-first checklist focus on these. Leave empty to track all 22.</p>
        <div className="grid gap-1.5 sm:grid-cols-3">
          {FRAMEWORKS.map((f) => (
            <label key={f} className="flex cursor-pointer items-center gap-2 text-xs">
              <input type="checkbox" checked={targets.includes(f)} onChange={() => toggleTarget(f)} />
              <span className={targets.includes(f) ? "text-ink" : "text-muted"}>{FRAMEWORK_LABEL[f] ?? f}</span>
            </label>
          ))}
        </div>
      </section>

      <div className="flex items-center gap-3">
        <button onClick={save} disabled={pending} className="inline-flex items-center gap-2 rounded-lg bg-accent px-4 py-2 text-sm font-medium text-white disabled:opacity-50">
          {pending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Check className="h-4 w-4" />} Save scope
        </button>
        {msg && <span className="text-xs text-muted">{msg}</span>}
      </div>
    </div>
  );
}
