"use client";

import { useState, useTransition } from "react";
import { KeyRound, Loader2, ShieldAlert, ShieldCheck, Copy, Check } from "lucide-react";
import { confirmTwoFactor, disableTwoFactor, replaceRecoveryCodes, startTwoFactor } from "@/app/(app)/settings/actions";

// Two-factor sign-in for the signed-in person's own account.
//
// The page never decides whether two-factor is on: it renders `enabled` and `remaining` exactly as
// /v1/auth/me reports them. Turning it on takes two steps on purpose — it is ON only after a code
// from the authenticator has been accepted — so a scan that did not take cannot lock anyone out.
// Turning it off and replacing recovery codes both ask for the password AND a current code, the same
// as the server requires; the form asks for both rather than letting a click fail.

const input =
  "w-full rounded-lg border border-border bg-surface px-3 py-2 text-sm outline-none focus:border-accent focus:ring-2 focus:ring-accent/10";
const primary =
  "inline-flex items-center gap-1.5 rounded-lg bg-accent px-3 py-1.5 text-xs font-semibold text-white disabled:opacity-60";
const secondary =
  "inline-flex items-center gap-1.5 rounded-lg border border-border px-3 py-1.5 text-xs font-medium text-ink hover:bg-white/5 disabled:opacity-60";

export function TwoFactorControl({ enabled, remaining }: { enabled: boolean; remaining?: number }) {
  const [pending, start] = useTransition();
  const [err, setErr] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  // Enrolment: the key the authenticator imports, shown once.
  const [enrol, setEnrol] = useState<{ secret: string; uri: string } | null>(null);
  // Recovery codes, shown once after they are issued.
  const [codes, setCodes] = useState<string[] | null>(null);
  const [notice, setNotice] = useState("");
  const [mode, setMode] = useState<"" | "start" | "off" | "replace">("");
  const [copied, setCopied] = useState(false);

  function reset() {
    setPassword("");
    setCode("");
    setErr("");
    setMode("");
  }

  function begin() {
    start(async () => {
      const r = await startTwoFactor(password);
      if (!r.ok) return setErr(r.error);
      setEnrol({ secret: r.secret, uri: r.uri });
      setPassword("");
      setErr("");
    });
  }

  function confirm() {
    start(async () => {
      const r = await confirmTwoFactor(code);
      if (!r.ok) return setErr(r.error);
      setEnrol(null);
      setCodes(r.recovery_codes);
      setNotice(r.warning ?? "Two-factor sign-in is on. Your other sessions were signed out.");
      reset();
    });
  }

  function weaken(kind: "off" | "replace") {
    // A recovery code is longer than 6 digits and carries a dash; send it as what it is.
    const b = /^\d{6}$/.test(code.replace(/\s/g, "")) ? { password, code } : { password, recovery_code: code };
    start(async () => {
      if (kind === "off") {
        const r = await disableTwoFactor(b);
        if (!r.ok) return setErr(r.error);
        setNotice("Two-factor sign-in is off. Your password alone now signs you in.");
        setCodes(null);
      } else {
        const r = await replaceRecoveryCodes(b);
        if (!r.ok) return setErr(r.error);
        setCodes(r.recovery_codes);
        setNotice("Your old recovery codes no longer work.");
      }
      reset();
    });
  }

  async function copyCodes() {
    if (!codes) return;
    try {
      await navigator.clipboard.writeText(codes.join("\n"));
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable */
    }
  }

  const low = enabled && typeof remaining === "number" && remaining <= 3;

  return (
    <div className="space-y-3">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2 text-sm font-medium">
            <KeyRound className="h-4 w-4 text-muted" /> Two-factor sign-in
          </div>
          <p className="mt-0.5 text-xs text-muted">
            {enabled
              ? "On. Signing in needs your password and a code from your authenticator app."
              : "Off. Your password alone signs you in. Turn this on so a stolen password is not enough."}
          </p>
        </div>
        <span
          className={`shrink-0 rounded-full px-2 py-0.5 text-[11px] font-medium ${
            enabled ? "bg-pulse-soft text-pulse" : "bg-medium/10 text-medium"
          }`}
        >
          {enabled ? "On" : "Off"}
        </span>
      </div>

      {enabled && typeof remaining === "number" && (
        <p className={`flex items-center gap-1.5 text-xs ${low ? "text-critical" : "text-muted"}`}>
          {low ? <ShieldAlert className="h-3.5 w-3.5" /> : <ShieldCheck className="h-3.5 w-3.5" />}
          {remaining === 0
            ? "No recovery codes left — if you lose your phone you cannot sign in. Replace them now."
            : `${remaining} recovery code${remaining === 1 ? "" : "s"} left${low ? " — replace them before you run out." : "."}`}
        </p>
      )}

      {notice && <p className="rounded-lg border border-border bg-surface px-3 py-2 text-xs text-ink">{notice}</p>}

      {codes && (
        <div className="space-y-2 rounded-lg border border-medium/30 bg-medium/5 p-3">
          <p className="text-xs font-medium text-ink">
            Save these recovery codes somewhere safe. Each works once, they are the only way in if you lose your
            phone, and they will not be shown again.
          </p>
          <ul className="grid grid-cols-2 gap-1 font-mono text-xs">
            {codes.map((c) => (
              <li key={c}>{c}</li>
            ))}
          </ul>
          <button type="button" onClick={copyCodes} className={secondary}>
            {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />} {copied ? "Copied" : "Copy codes"}
          </button>
        </div>
      )}

      {!enabled && !enrol && mode !== "start" && (
        <button type="button" onClick={() => setMode("start")} className={primary}>
          Turn on
        </button>
      )}

      {!enabled && !enrol && mode === "start" && (
        <div className="space-y-2">
          <input type="password" autoComplete="current-password" placeholder="Your password" value={password}
            onChange={(e) => setPassword(e.target.value)} className={input} />
          <div className="flex gap-2">
            <button type="button" disabled={pending || !password} onClick={begin} className={primary}>
              {pending && <Loader2 className="h-3.5 w-3.5 animate-spin" />} Continue
            </button>
            <button type="button" onClick={reset} className={secondary}>Cancel</button>
          </div>
        </div>
      )}

      {enrol && (
        <div className="space-y-2">
          <p className="text-xs text-muted">
            In your authenticator app (Google Authenticator, 1Password, Authy…), add an account with this key, or open
            the link on your phone. Then enter the 6-digit code it shows. Two-factor sign-in is not on until that code is
            accepted.
          </p>
          <code className="block break-all rounded-lg border border-border bg-surface px-3 py-2 font-mono text-xs">
            {enrol.secret.match(/.{1,4}/g)?.join(" ")}
          </code>
          <a href={enrol.uri} className="text-xs font-medium text-accent hover:underline">Open in authenticator app</a>
          <input inputMode="numeric" autoComplete="one-time-code" placeholder="123456" value={code}
            onChange={(e) => setCode(e.target.value)} className={`${input} font-mono tracking-widest`} />
          <div className="flex gap-2">
            <button type="button" disabled={pending || !code.trim()} onClick={confirm} className={primary}>
              {pending && <Loader2 className="h-3.5 w-3.5 animate-spin" />} Confirm and turn on
            </button>
            <button type="button" onClick={() => { setEnrol(null); reset(); }} className={secondary}>Cancel</button>
          </div>
        </div>
      )}

      {enabled && mode === "" && (
        <div className="flex gap-2">
          <button type="button" onClick={() => setMode("replace")} className={secondary}>Replace recovery codes</button>
          <button type="button" onClick={() => setMode("off")} className={secondary}>Turn off</button>
        </div>
      )}

      {enabled && (mode === "off" || mode === "replace") && (
        <div className="space-y-2">
          <p className="text-xs text-muted">
            {mode === "off"
              ? "Turning this off needs your password and a current code — an open session alone cannot remove it."
              : "Replacing your recovery codes needs your password and a current code. The old codes stop working."}
          </p>
          <input type="password" autoComplete="current-password" placeholder="Your password" value={password}
            onChange={(e) => setPassword(e.target.value)} className={input} />
          <input autoComplete="one-time-code" placeholder="Authenticator code or a recovery code" value={code}
            onChange={(e) => setCode(e.target.value)} className={`${input} font-mono`} />
          <div className="flex gap-2">
            <button type="button" disabled={pending || !password || !code.trim()} onClick={() => weaken(mode)} className={primary}>
              {pending && <Loader2 className="h-3.5 w-3.5 animate-spin" />} {mode === "off" ? "Turn off" : "Replace codes"}
            </button>
            <button type="button" onClick={reset} className={secondary}>Cancel</button>
          </div>
        </div>
      )}

      {err && <p className="rounded-lg border border-critical/30 bg-critical/5 px-3 py-2 text-xs text-critical">{err}</p>}
    </div>
  );
}
