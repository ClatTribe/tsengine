"use client";

import { useState, useTransition } from "react";
import { Filter, Plus, X, Loader2 } from "lucide-react";
import type { ExclusionRule } from "@/lib/types";
import { addExclusion, deleteExclusion } from "@/app/(app)/issues/actions";

const FIELDS = [
  { value: "package", label: "Package", hint: "e.g. lodash" },
  { value: "path", label: "Path", hint: "e.g. */test/*" },
  { value: "rule_id", label: "Rule", hint: "e.g. trivy::CVE-2021-*" },
  { value: "cve", label: "CVE", hint: "e.g. CVE-2021-*" },
  { value: "any", label: "Any", hint: "matches any attribute" },
];

// ExclusionRules is the "custom rules" noise-filter manager: list the tenant's
// pattern exclusions and add/remove them. A matching finding is dropped before it's
// unified into an issue — so the noise never appears.
export function ExclusionRules({ rules, excluded }: { rules: ExclusionRule[]; excluded: number }) {
  const [open, setOpen] = useState(false);
  const [field, setField] = useState("package");
  const [pattern, setPattern] = useState("");
  const [err, setErr] = useState("");
  const [pending, start] = useTransition();

  const hint = FIELDS.find((f) => f.value === field)?.hint ?? "";

  function add() {
    setErr("");
    if (!pattern.trim()) {
      setErr("Enter a pattern (use * as a wildcard).");
      return;
    }
    start(async () => {
      try {
        await addExclusion(field, pattern.trim(), "");
        setPattern("");
      } catch (e) {
        setErr(e instanceof Error ? e.message : "could not add rule");
      }
    });
  }

  return (
    <div className="card p-4">
      <button onClick={() => setOpen((o) => !o)} className="flex w-full items-center justify-between text-left">
        <span className="flex items-center gap-2 text-sm font-medium">
          <Filter className="h-4 w-4 text-muted" /> Exclusion rules
          {rules.length > 0 && <span className="rounded-full bg-surface-2 px-1.5 py-0.5 text-[11px] text-muted">{rules.length}</span>}
        </span>
        <span className="text-[11px] text-faint">
          {excluded > 0 ? `${excluded} finding${excluded === 1 ? "" : "s"} excluded` : "filter out known noise"}
        </span>
      </button>

      {open && (
        <div className="mt-3 space-y-3">
          <p className="text-xs text-muted">
            Exclude specific paths, packages, or rules from your issues — matching findings are dropped before they&apos;re
            unified, so they never show up. Use <code className="mono">*</code> as a wildcard.
          </p>

          {/* Existing rules */}
          {rules.length > 0 && (
            <ul className="space-y-1">
              {rules.map((r) => (
                <li key={r.id} className="flex items-center gap-2 rounded-lg border border-border bg-surface px-3 py-1.5 text-xs">
                  <span className="rounded bg-surface-2 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-muted">{r.field}</span>
                  <code className="mono flex-1 truncate text-ink">{r.pattern}</code>
                  <DeleteButton id={r.id} />
                </li>
              ))}
            </ul>
          )}

          {/* Add form */}
          <div className="flex flex-wrap items-center gap-2">
            <select
              value={field}
              onChange={(e) => setField(e.target.value)}
              className="rounded-lg border border-border bg-surface px-2 py-1.5 text-sm outline-none focus:border-accent"
            >
              {FIELDS.map((f) => (
                <option key={f.value} value={f.value}>{f.label}</option>
              ))}
            </select>
            <input
              value={pattern}
              onChange={(e) => setPattern(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && add()}
              placeholder={hint}
              className="min-w-[12rem] flex-1 rounded-lg border border-border bg-surface px-3 py-1.5 font-mono text-xs outline-none focus:border-accent"
            />
            <button
              onClick={add}
              disabled={pending}
              className="inline-flex items-center gap-1.5 rounded-lg bg-accent px-3 py-1.5 text-sm font-medium text-white transition hover:bg-accent-hover disabled:opacity-50"
            >
              {pending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Plus className="h-3.5 w-3.5" />} Add
            </button>
          </div>
          {err && <div className="text-xs text-critical">{err}</div>}
        </div>
      )}
    </div>
  );
}

function DeleteButton({ id }: { id: string }) {
  const [pending, start] = useTransition();
  return (
    <button
      onClick={() => start(async () => { await deleteExclusion(id); })}
      disabled={pending}
      className="text-faint transition hover:text-critical disabled:opacity-50"
      title="Remove rule"
    >
      {pending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <X className="h-3.5 w-3.5" />}
    </button>
  );
}
