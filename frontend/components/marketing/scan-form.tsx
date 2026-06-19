"use client";

import { useState } from "react";
import Link from "next/link";
import { Search, Loader2, ShieldCheck, ShieldAlert, Check, X, ArrowRight } from "lucide-react";

type Check = { name: string; ok: boolean; detail: string };
type Finding = { title: string; severity: string };
type Result = { domain: string; score: number; grade: string; checks: Check[]; findings: Finding[] };

const GRADE_TONE: Record<string, string> = {
  A: "text-pulse", B: "text-pulse", C: "text-medium", D: "text-high", F: "text-critical",
};

export function ScanForm() {
  const [domain, setDomain] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<Result | null>(null);

  async function run(e: React.FormEvent) {
    e.preventDefault();
    if (!domain.trim()) return;
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const res = await fetch(`/api/assess?domain=${encodeURIComponent(domain.trim())}`);
      const data = await res.json();
      if (!res.ok) {
        setError(data?.error ?? "Couldn't assess that domain.");
      } else {
        setResult(data as Result);
      }
    } catch {
      setError("Something went wrong — try again.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="mx-auto max-w-2xl">
      <form onSubmit={run} className="flex flex-col gap-2 sm:flex-row">
        <div className="relative flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-faint" />
          <input
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="yourcompany.com"
            autoCapitalize="off"
            autoCorrect="off"
            spellCheck={false}
            className="w-full rounded-xl border border-border bg-surface py-3 pl-10 pr-3 text-sm outline-none transition focus:border-accent"
          />
        </div>
        <button
          type="submit"
          disabled={loading}
          className="inline-flex items-center justify-center gap-2 rounded-xl bg-accent px-5 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover active:translate-y-px disabled:opacity-60"
        >
          {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />}
          {loading ? "Scanning…" : "Scan free"}
        </button>
      </form>
      <p className="mt-2 text-center text-xs text-faint">
        Read-only check of your domain&apos;s email-auth (DMARC/SPF/DKIM) via public DNS. No signup, nothing intrusive.
      </p>

      {error && (
        <div className="mt-5 rounded-lg border border-critical/30 bg-critical/10 px-4 py-3 text-sm text-critical">{error}</div>
      )}

      {result && (
        <div className="mt-6 animate-fade-rise space-y-4 text-left">
          <div className="card flex items-center gap-5 p-6">
            <div className={`grid h-20 w-20 shrink-0 place-items-center rounded-2xl border-2 ${result.grade === "A" || result.grade === "B" ? "border-pulse/40 bg-pulse-soft" : "border-high/40 bg-high/10"}`}>
              <span className={`text-4xl font-bold ${GRADE_TONE[result.grade] ?? "text-ink"}`}>{result.grade}</span>
            </div>
            <div className="min-w-0">
              <div className="mono truncate text-xs text-faint">{result.domain}</div>
              <div className="mt-0.5 text-2xl font-semibold tracking-tight">
                Email-auth score: <span className={GRADE_TONE[result.grade] ?? "text-ink"}>{result.score}/100</span>
              </div>
              <p className="mt-1 text-sm text-muted">
                {result.findings.length === 0
                  ? "No email-spoofing gaps found — strong setup."
                  : `${result.findings.length} gap${result.findings.length > 1 ? "s" : ""} let attackers spoof your domain for phishing.`}
              </p>
            </div>
          </div>

          <div className="card divide-y divide-border p-0">
            {result.checks.map((c) => (
              <div key={c.name} className="flex items-start gap-3 px-5 py-3">
                <span className={`mt-0.5 grid h-5 w-5 shrink-0 place-items-center rounded-full ${c.ok ? "bg-pulse/15 text-pulse" : "bg-critical/10 text-critical"}`}>
                  {c.ok ? <Check className="h-3 w-3" /> : <X className="h-3 w-3" />}
                </span>
                <div className="min-w-0">
                  <div className="text-sm font-medium">{c.name}</div>
                  <div className="text-xs text-muted">{c.detail}</div>
                </div>
              </div>
            ))}
          </div>

          {/* Conversion: this is just one surface — sign up for the full picture */}
          <div className="rounded-2xl border border-accent/30 bg-accent-soft/30 p-5 text-center">
            <div className="flex items-center justify-center gap-2 text-sm font-semibold">
              <ShieldAlert className="h-4 w-4 text-accent" /> This is just your email surface.
            </div>
            <p className="mx-auto mt-1.5 max-w-md text-sm text-muted">
              Connect a system free and TensorShield assesses your code, cloud, and identity too — then fixes what it finds,
              with you approving anything that matters.
            </p>
            <Link href="/signup" className="mt-4 inline-flex items-center gap-2 rounded-xl bg-accent px-5 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover active:translate-y-px">
              See your full posture — free <ArrowRight className="h-4 w-4" />
            </Link>
          </div>
        </div>
      )}
    </div>
  );
}
