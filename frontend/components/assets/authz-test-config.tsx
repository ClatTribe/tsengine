"use client";

import { useState, useTransition } from "react";
import { ShieldAlert, X, Check, Loader2, Plus, Trash2, Pencil } from "lucide-react";
import { setAuthzTest, runAuthzTest } from "@/app/(app)/assets/actions";
import { cn } from "@/lib/utils";

type Op = { method: string; url: string; class: string; marker: string };
const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"];
const emptyOp: Op = { method: "GET", url: "", class: "bola", marker: "" };

// AuthzTestConfig configures the BOLA/BFLA authorization test for an api asset: two identities (a
// victim that owns an object, an attacker that's a different lower-privilege principal) + the
// object-bearing operations to test. The engine replays the victim's request as the attacker and
// flags only a PROVEN bypass (verified, no false positives). Auth headers are sealed server-side.
// When `configured`, the trigger is a badge that reopens the form to update the test (saving
// overwrites the stored config).
export function AuthzTestConfig({ assetId, configured = false }: { assetId: string; configured?: boolean }) {
  const [open, setOpen] = useState(false);
  const [pending, start] = useTransition();
  const [result, setResult] = useState<{ ok: boolean; error?: string } | null>(null);
  const [victimAuth, setVictimAuth] = useState("");
  const [attackerAuth, setAttackerAuth] = useState("");
  const [ops, setOps] = useState<Op[]>([{ ...emptyOp }]);
  const [runPending, startRun] = useTransition();
  const [authorizedBy, setAuthorizedBy] = useState("");
  const [consented, setConsented] = useState(false);
  const [runRes, setRunRes] = useState<{ ok: boolean; bypasses?: number; error?: string } | null>(null);

  const setOp = (i: number, k: keyof Op, v: string) => setOps(ops.map((o, j) => (j === i ? { ...o, [k]: v } : o)));
  const addOp = () => setOps([...ops, { ...emptyOp }]);
  const delOp = (i: number) => setOps(ops.length > 1 ? ops.filter((_, j) => j !== i) : ops);
  const completeOps = ops.filter((o) => o.url.trim() !== "");
  const canSubmit = victimAuth.trim() !== "" && attackerAuth.trim() !== "" && completeOps.length > 0;

  function submit() {
    setResult(null);
    start(async () => setResult(await setAuthzTest(assetId, { victimAuth, attackerAuth, operations: ops })));
  }

  const canRun = authorizedBy.trim() !== "" && consented;
  function run() {
    setRunRes(null);
    startRun(async () =>
      setRunRes(
        await runAuthzTest(assetId, {
          authorizedBy,
          consent: `Authorized active BOLA/BFLA test of this API asset by ${authorizedBy}.`,
        }),
      ),
    );
  }

  return (
    <>
      {configured ? (
        <button
          onClick={() => setOpen(true)}
          title="Reconfigure the authorization test"
          className="group inline-flex items-center gap-1 rounded-md border border-pulse/30 bg-pulse/5 px-1.5 py-0.5 text-[11px] text-pulse transition hover:border-pulse/60"
        >
          <ShieldAlert className="h-3 w-3" /> Authz test <Pencil className="h-2.5 w-2.5 opacity-50 transition group-hover:opacity-100" />
        </button>
      ) : (
        <button
          onClick={() => setOpen(true)}
          className="inline-flex items-center gap-1 rounded-md border border-border bg-surface-2 px-1.5 py-0.5 text-[11px] text-muted transition hover:border-accent/40 hover:text-ink"
        >
          <ShieldAlert className="h-3 w-3" /> Authz test
        </button>
      )}

      {open && (
        <div className="fixed inset-0 z-50 grid place-items-center bg-black/40 p-4" onClick={() => setOpen(false)}>
          <div className="card max-h-[90vh] w-full max-w-lg overflow-y-auto p-5" onClick={(e) => e.stopPropagation()}>
            <div className="mb-3 flex items-center justify-between">
              <h3 className="flex items-center gap-2 text-sm font-semibold">
                <ShieldAlert className="h-4 w-4 text-accent" /> BOLA / BFLA authorization test
              </h3>
              <button onClick={() => setOpen(false)} className="text-faint hover:text-ink">
                <X className="h-4 w-4" />
              </button>
            </div>
            <p className="mb-4 text-xs leading-relaxed text-muted">
              The engine replays a <span className="text-ink">victim&apos;s</span> request as an{" "}
              <span className="text-ink">attacker</span> and reports a finding only on a <em>proven</em> bypass —
              no false positives. Provide each identity&apos;s <span className="mono">Authorization</span> header and the
              object-bearing operations to test. Credentials are encrypted at rest and never shown again.
            </p>

            <div className="space-y-3">
              <Field label="Victim Authorization header" value={victimAuth} onChange={(e) => setVictimAuth(e.target.value)} placeholder="Bearer eyJ… (owns the object)" />
              <Field label="Attacker Authorization header" value={attackerAuth} onChange={(e) => setAttackerAuth(e.target.value)} placeholder="Bearer eyJ… (a different, lower-privilege user)" />

              <div>
                <div className="mb-1.5 flex items-center justify-between">
                  <span className="text-[11px] uppercase tracking-wide text-faint">Operations to test</span>
                  <button onClick={addOp} className="inline-flex items-center gap-1 text-[11px] text-accent hover:underline">
                    <Plus className="h-3 w-3" /> Add operation
                  </button>
                </div>
                <div className="space-y-2">
                  {ops.map((o, i) => (
                    <div key={i} className="rounded-lg border border-border bg-surface-2 p-2">
                      <div className="flex items-center gap-2">
                        <select
                          value={o.method}
                          onChange={(e) => setOp(i, "method", e.target.value)}
                          className="rounded-md border border-border bg-surface px-1.5 py-1 text-xs outline-none"
                        >
                          {METHODS.map((m) => (
                            <option key={m} value={m}>{m}</option>
                          ))}
                        </select>
                        <input
                          value={o.url}
                          onChange={(e) => setOp(i, "url", e.target.value)}
                          placeholder="https://api.example.com/invoices/42 (victim's object)"
                          className="min-w-0 flex-1 rounded-md border border-border bg-surface px-2 py-1 text-xs outline-none focus:border-accent/50"
                        />
                        <button onClick={() => delOp(i)} disabled={ops.length === 1} className="text-faint hover:text-critical disabled:opacity-30">
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      </div>
                      <div className="mt-2 flex items-center gap-2">
                        <select
                          value={o.class}
                          onChange={(e) => setOp(i, "class", e.target.value)}
                          className="rounded-md border border-border bg-surface px-1.5 py-1 text-xs outline-none"
                        >
                          <option value="bola">BOLA — object access</option>
                          <option value="bfla">BFLA — privileged function</option>
                        </select>
                        <input
                          value={o.marker}
                          onChange={(e) => setOp(i, "marker", e.target.value)}
                          placeholder="leak marker (e.g. victim@acme.com) — optional"
                          className="min-w-0 flex-1 rounded-md border border-border bg-surface px-2 py-1 text-xs outline-none focus:border-accent/50"
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {result?.error && <p className="mt-3 text-xs text-critical">{result.error}</p>}
            {result?.ok && (
              <p className="mt-3 flex items-center gap-1 text-xs text-pulse">
                <Check className="h-3.5 w-3.5" /> Saved — the authorization test is configured.
              </p>
            )}

            {configured && (
              <div className="mt-4 rounded-lg border border-border bg-surface-2 p-3">
                <div className="mb-2 flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wide text-faint">
                  <ShieldAlert className="h-3 w-3 text-accent" /> Run the test now (active)
                </div>
                <p className="mb-2 text-xs leading-relaxed text-muted">
                  Executing replays the victim&apos;s request as the attacker against the live API. This is an{" "}
                  <span className="text-ink">active</span> test — it needs your explicit authorization, and the
                  operator&apos;s live-testing flag must be enabled (otherwise the run is refused).
                </p>
                <Field label="Authorized by (your name)" value={authorizedBy} onChange={(e) => setAuthorizedBy(e.target.value)} placeholder="Jane Sec (CISO)" />
                <label className="mt-2 flex items-start gap-2 text-xs text-muted">
                  <input type="checkbox" checked={consented} onChange={(e) => setConsented(e.target.checked)} className="mt-0.5" />
                  <span>I authorize an active BOLA/BFLA test of this API asset and confirm it is in scope.</span>
                </label>
                {runRes?.error && <p className="mt-2 text-xs text-critical">{runRes.error}</p>}
                {runRes?.ok && (
                  <p className="mt-2 flex items-center gap-1 text-xs text-pulse">
                    <Check className="h-3.5 w-3.5" />
                    {runRes.bypasses ? `${runRes.bypasses} proven bypass${runRes.bypasses > 1 ? "es" : ""} — see Issues.` : "No bypass found — the API enforced authorization."}
                  </p>
                )}
                <button
                  onClick={run}
                  disabled={!canRun || runPending}
                  className="mt-2 inline-flex items-center gap-1.5 rounded-lg border border-critical/40 bg-critical/10 px-3 py-1.5 text-xs font-medium text-critical transition hover:border-critical/60 disabled:opacity-50"
                >
                  {runPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ShieldAlert className="h-3.5 w-3.5" />}
                  {runPending ? "Running…" : "Run test"}
                </button>
              </div>
            )}

            <div className="mt-4 flex items-center justify-between">
              <span className="text-[11px] text-faint">
                Active testing runs only with explicit consent + the operator&apos;s exploit flag.
              </span>
              <div className="flex gap-2">
                <button onClick={() => setOpen(false)} className="rounded-lg px-3 py-1.5 text-xs text-muted hover:text-ink">
                  Close
                </button>
                <button
                  onClick={submit}
                  disabled={!canSubmit || pending}
                  className={cn(
                    "inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-medium transition disabled:opacity-50",
                    "border-accent/40 bg-accent-soft text-accent hover:border-accent",
                  )}
                >
                  {pending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ShieldAlert className="h-3.5 w-3.5" />}
                  {pending ? "Saving…" : "Save test"}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

function Field({
  label,
  ...props
}: { label: string } & React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <label className="block">
      <span className="mb-1 block text-[11px] uppercase tracking-wide text-faint">{label}</span>
      <input
        {...props}
        className="w-full rounded-lg border border-border bg-surface-2 px-2.5 py-1.5 text-sm outline-none transition focus:border-accent/50"
      />
    </label>
  );
}
