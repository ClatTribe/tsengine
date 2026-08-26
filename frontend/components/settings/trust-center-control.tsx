"use client";

import { useState, useTransition } from "react";
import { Globe, Loader2, Check, AlertTriangle, Plus, X, EyeOff } from "lucide-react";
import { setTrustCenter, revokeTrustLink } from "@/app/(app)/settings/actions";
import { FRAMEWORK_LABEL } from "@/lib/frameworks";
import type { TrustCenterConfig, TrustDocument, TrustSettings, TrustSubprocessor } from "@/lib/types";

// The owner's side of the Trust Center: which documents a buyer is offered, at which gate, under
// which agreement.
//
// Two things this panel does that a plain settings form would not:
//
//   - It shows CORRECTIONS. The server normalizes what it is sent — a report that names open
//     findings cannot be public, a wildcard auto-approve rule is dropped, the grant window is
//     bounded — and returning silently would leave the owner believing a setting took effect
//     when it did not. On this page that belief is about who can read their pentest report.
//   - It shows what is configured but NOT being served, and why. An unavailable document is
//     absent from the public page by design (a locked row asserts the document exists), so
//     without this the honest omission is invisible and reads as a bug.

const KINDS: { kind: string; label: string; hint: string; framework?: boolean; external?: boolean }[] = [
  { kind: "subprocessors", label: "Sub-processors", hint: "GDPR Art. 28 disclosure — the list you maintain below" },
  { kind: "questionnaire", label: "Security questionnaire", hint: "CAIQ/SIG-lite, answered from live posture" },
  { kind: "policies", label: "Security policies", hint: "Published policies, owners and dates" },
  { kind: "compliance_report", label: "Compliance report", hint: "Gap controls and the findings citing them", framework: true },
  { kind: "vapt_report", label: "Penetration test report", hint: "Findings, severities and reproduction" },
  { kind: "evidence_pack", label: "Signed evidence pack", hint: "Verifiable, not just published", framework: true },
  { kind: "external", label: "External document", hint: "Your SOC 2 report, ISO certificate or DPA — a link you host", external: true },
];

// Kinds whose bodies name open findings. Mirrored from platform.DocKind.MinVisibility so the UI
// can disable the control rather than let the owner pick something the server will refuse. The
// server still clamps — this is a courtesy, never the enforcement.
const NEVER_PUBLIC = new Set(["compliance_report", "vapt_report", "evidence_pack", "external"]);

const FRAMEWORKS = Object.keys(FRAMEWORK_LABEL);

export function TrustCenterControl({ initial }: { initial: TrustSettings }) {
  const [cfg, setCfg] = useState<TrustCenterConfig>(initial.config ?? { enabled: false });
  const [link, setLink] = useState(initial.link);
  const [corrections, setCorrections] = useState<{ field: string; reason: string }[]>([]);
  const [unavailable, setUnavailable] = useState(initial.unavailable ?? []);
  const [err, setErr] = useState("");
  const [saved, setSaved] = useState(false);
  const [pending, start] = useTransition();

  const docs = cfg.documents ?? [];
  const subs = cfg.subprocessors ?? [];

  function patch(p: Partial<TrustCenterConfig>) {
    setCfg((c) => ({ ...c, ...p }));
    setSaved(false);
  }

  function addDoc(kind: string) {
    if (docs.some((d) => d.kind === kind && !KINDS.find((k) => k.kind === kind)?.framework)) return;
    const visibility = NEVER_PUBLIC.has(kind) ? "gated" : "public";
    patch({ documents: [...docs, { kind, visibility } as TrustDocument] });
  }

  function setDoc(i: number, p: Partial<TrustDocument>) {
    patch({ documents: docs.map((d, j) => (j === i ? { ...d, ...p } : d)) });
  }

  function save() {
    setErr("");
    setSaved(false);
    setCorrections([]);
    start(async () => {
      try {
        const r = await setTrustCenter(cfg);
        setCfg(r.config);
        setLink(r.link);
        setCorrections(r.corrections ?? []);
        setSaved(true);
      } catch (e) {
        setErr(e instanceof Error ? e.message : "Failed to save");
      }
    });
  }

  function revoke() {
    setErr("");
    start(async () => {
      try {
        const r = await revokeTrustLink();
        setLink(r.link);
        setCfg((c) => ({ ...c, token_version: r.token_version }));
      } catch (e) {
        setErr(e instanceof Error ? e.message : "Failed to revoke");
      }
    });
  }

  return (
    <div className="rounded-xl border border-border bg-surface-2 px-3.5 py-3">
      <div className="flex items-center gap-3">
        <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-surface text-muted">
          <Globe className="h-4 w-4" />
        </span>
        <div className="min-w-0 flex-1">
          <div className="text-sm font-medium">Trust Center documents</div>
          <div className="text-xs text-muted">What a buyer can self-serve, and what needs your approval</div>
        </div>
        <label className="flex items-center gap-1.5 text-xs text-ink">
          <input type="checkbox" checked={!!cfg.enabled} onChange={(e) => patch({ enabled: e.target.checked })} />
          Enabled
        </label>
      </div>

      <div className="mt-3 space-y-3">
        <div className="grid gap-2 sm:grid-cols-2">
          <input
            value={cfg.headline ?? ""}
            onChange={(e) => patch({ headline: e.target.value })}
            placeholder="Headline shown under your name"
            className="rounded-lg border border-border bg-surface px-3 py-2 text-xs outline-none focus:border-accent"
          />
          <input
            value={cfg.contact_email ?? ""}
            onChange={(e) => patch({ contact_email: e.target.value })}
            placeholder="Contact email for questions"
            className="rounded-lg border border-border bg-surface px-3 py-2 text-xs outline-none focus:border-accent"
          />
        </div>

        {/* Documents */}
        <div>
          <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-faint">Documents offered</div>
          <div className="space-y-1.5">
            {docs.map((d, i) => {
              const meta = KINDS.find((k) => k.kind === d.kind);
              const locked = NEVER_PUBLIC.has(d.kind);
              return (
                <div key={d.kind + i} className="rounded-lg border border-border bg-surface p-2.5">
                  <div className="flex items-center gap-2">
                    <span className="min-w-0 flex-1 text-xs font-medium text-ink">{meta?.label ?? d.kind}</span>
                    <select
                      value={d.visibility}
                      onChange={(e) => setDoc(i, { visibility: e.target.value as TrustDocument["visibility"] })}
                      className="rounded-lg border border-border bg-surface-2 px-2 py-1 text-[11px] outline-none focus:border-accent"
                    >
                      {/* "Public" is simply not offered for a document that names open findings.
                          The server refuses it either way; not rendering the option means the
                          owner is never invited to try. */}
                      {!locked && <option value="public">Public</option>}
                      <option value="gated">Behind approval</option>
                      <option value="private">Hidden</option>
                    </select>
                    <button
                      onClick={() => patch({ documents: docs.filter((_, j) => j !== i) })}
                      className="rounded p-1 text-faint transition hover:text-high"
                      aria-label="Remove"
                    >
                      <X className="h-3.5 w-3.5" />
                    </button>
                  </div>
                  {locked && (
                    <div className="mt-1 flex items-center gap-1 text-[10px] text-faint">
                      <EyeOff className="h-3 w-3" /> Names your open findings, so it can never be public
                    </div>
                  )}
                  {meta?.framework && (
                    <select
                      value={d.framework ?? ""}
                      onChange={(e) => setDoc(i, { framework: e.target.value })}
                      className="mt-1.5 w-full rounded-lg border border-border bg-surface-2 px-2 py-1 text-[11px] outline-none focus:border-accent"
                    >
                      <option value="">Choose a framework…</option>
                      {FRAMEWORKS.map((f) => (
                        <option key={f} value={f}>
                          {FRAMEWORK_LABEL[f] ?? f}
                        </option>
                      ))}
                    </select>
                  )}
                  {meta?.external && (
                    <div className="mt-1.5 grid gap-1.5 sm:grid-cols-2">
                      <input
                        value={d.title ?? ""}
                        onChange={(e) => setDoc(i, { title: e.target.value })}
                        placeholder="Title, e.g. SOC 2 Type II report"
                        className="rounded-lg border border-border bg-surface-2 px-2 py-1 text-[11px] outline-none focus:border-accent"
                      />
                      <input
                        value={d.url ?? ""}
                        onChange={(e) => setDoc(i, { url: e.target.value })}
                        placeholder="https://… (we host no files)"
                        className="rounded-lg border border-border bg-surface-2 px-2 py-1 text-[11px] outline-none focus:border-accent"
                      />
                    </div>
                  )}
                  <input
                    value={d.note ?? ""}
                    onChange={(e) => setDoc(i, { note: e.target.value })}
                    placeholder="Note shown to the buyer (optional)"
                    className="mt-1.5 w-full rounded-lg border border-border bg-surface-2 px-2 py-1 text-[11px] outline-none focus:border-accent"
                  />
                </div>
              );
            })}
          </div>
          <div className="mt-1.5 flex flex-wrap gap-1.5">
            {KINDS.map((k) => (
              <button
                key={k.kind}
                onClick={() => addDoc(k.kind)}
                title={k.hint}
                className="inline-flex items-center gap-1 rounded-lg border border-border bg-surface px-2 py-1 text-[11px] text-muted transition hover:border-accent/40 hover:text-ink"
              >
                <Plus className="h-3 w-3" /> {k.label}
              </button>
            ))}
          </div>
        </div>

        {/* Configured but not served — the honest omission, made visible to the owner only. */}
        {unavailable.length > 0 && (
          <div className="rounded-lg border border-border bg-surface p-2.5">
            <div className="text-[11px] font-semibold text-ink">Not shown to buyers yet</div>
            <ul className="mt-1 space-y-0.5">
              {unavailable.map((u) => (
                <li key={u.key} className="text-[11px] text-muted">
                  <span className="text-ink">{u.title}</span> — {u.reason}
                </li>
              ))}
            </ul>
            <p className="mt-1 text-[10px] text-faint">
              These are left off the page entirely rather than shown locked: a locked row tells a buyer the
              document exists.
            </p>
          </div>
        )}

        {/* Sub-processors */}
        <div>
          <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-faint">Sub-processors</div>
          <div className="space-y-1.5">
            {subs.map((s, i) => (
              <div key={i} className="grid gap-1.5 sm:grid-cols-[1fr_1fr_1fr_auto]">
                {(["name", "purpose", "location"] as const).map((f) => (
                  <input
                    key={f}
                    value={s[f] ?? ""}
                    onChange={(e) =>
                      patch({ subprocessors: subs.map((x, j) => (j === i ? { ...x, [f]: e.target.value } : x)) })
                    }
                    placeholder={f === "name" ? "Name" : f === "purpose" ? "Purpose" : "Location"}
                    className="rounded-lg border border-border bg-surface px-2 py-1 text-[11px] outline-none focus:border-accent"
                  />
                ))}
                <button
                  onClick={() => patch({ subprocessors: subs.filter((_, j) => j !== i) })}
                  className="rounded p-1 text-faint transition hover:text-high"
                  aria-label="Remove"
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              </div>
            ))}
          </div>
          <button
            onClick={() => patch({ subprocessors: [...subs, { name: "" } as TrustSubprocessor] })}
            className="mt-1.5 inline-flex items-center gap-1 rounded-lg border border-border bg-surface px-2 py-1 text-[11px] text-muted transition hover:border-accent/40 hover:text-ink"
          >
            <Plus className="h-3 w-3" /> Add sub-processor
          </button>
          {/* Said explicitly: this list is authored, not inferred. Deriving it from the vendor-risk
              data would publish only the vendors that failed a check. */}
          <p className="mt-1 text-[10px] text-faint">
            You write this list. It is a legal disclosure, not something we infer from your vendor risk data.
          </p>
        </div>

        {/* Gate */}
        <div>
          <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-faint">The gate</div>
          <textarea
            value={cfg.nda_text ?? ""}
            onChange={(e) => patch({ nda_text: e.target.value })}
            rows={3}
            placeholder="Confidentiality agreement a buyer accepts before gated documents open. Leave blank to require none."
            className="w-full rounded-lg border border-border bg-surface px-3 py-2 text-xs outline-none focus:border-accent"
          />
          <div className="mt-1.5 grid gap-1.5 sm:grid-cols-2">
            <input
              value={(cfg.auto_approve_domains ?? []).join(", ")}
              onChange={(e) =>
                patch({ auto_approve_domains: e.target.value.split(",").map((s) => s.trim()).filter(Boolean) })
              }
              placeholder="Auto-approve domains, e.g. acme.com"
              className="rounded-lg border border-border bg-surface px-3 py-2 text-xs outline-none focus:border-accent"
            />
            <label className="flex items-center gap-2 text-xs text-muted">
              Access lasts
              <input
                type="number"
                min={1}
                value={cfg.grant_ttl_hours ?? 720}
                onChange={(e) => patch({ grant_ttl_hours: Number(e.target.value) })}
                className="w-20 rounded-lg border border-border bg-surface px-2 py-1 text-xs outline-none focus:border-accent"
              />
              hours
            </label>
          </div>
          <p className="mt-1 text-[10px] text-faint">
            Domains match exactly — a rule for acme.com does not admit notacme.com. Wildcards are refused: that is
            publishing, so set the document public instead.
          </p>
        </div>

        {/* Link + revoke */}
        {link && (
          <div className="rounded-lg border border-border bg-surface p-2.5">
            <div className="text-[11px] font-semibold text-ink">Share link</div>
            <div className="mono mt-1 overflow-x-auto whitespace-nowrap text-[11px] text-muted">{link}</div>
            <button
              onClick={revoke}
              disabled={pending}
              className="mt-1.5 rounded-lg border border-border bg-surface-2 px-2 py-1 text-[11px] font-medium text-muted transition hover:border-high/40 hover:text-high disabled:opacity-60"
            >
              Revoke this link
            </button>
            <p className="mt-1 text-[10px] text-faint">
              Revoking stops every copy of the current link working and issues a new one. Only yours is affected.
            </p>
          </div>
        )}

        {corrections.length > 0 && (
          <div className="rounded-lg border border-med/30 bg-med-soft/30 p-2.5">
            <div className="flex items-center gap-1.5 text-[11px] font-semibold text-ink">
              <AlertTriangle className="h-3.5 w-3.5 text-med" /> We changed some of what you saved
            </div>
            <ul className="mt-1 space-y-0.5">
              {corrections.map((c, i) => (
                <li key={i} className="text-[11px] text-muted">
                  <span className="text-ink">{c.field}</span> — {c.reason}
                </li>
              ))}
            </ul>
          </div>
        )}

        <div className="flex items-center gap-2">
          <button
            onClick={save}
            disabled={pending}
            className="inline-flex items-center gap-1.5 rounded-lg bg-accent px-3 py-1.5 text-xs font-semibold text-white shadow-sm transition hover:bg-accent-hover disabled:opacity-60"
          >
            {pending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : null}
            Save
          </button>
          {saved && corrections.length === 0 && (
            <span className="inline-flex items-center gap-1 text-[11px] text-pulse">
              <Check className="h-3.5 w-3.5" /> Saved
            </span>
          )}
          {err && <span className="text-[11px] text-high">{err}</span>}
        </div>
      </div>
    </div>
  );
}
