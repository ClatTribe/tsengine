"use client";

import { useState, useEffect, useCallback } from "react";
import Link from "next/link";
import { Search, Loader2, ShieldCheck, ShieldAlert, Check, X, ArrowRight, Code, Copy, Wrench, ChevronDown } from "lucide-react";

type FixSnippet = { label: string; lang: string; code: string };
type Fix = { summary: string; snippets: FixSnippet[] };
type Check = { name: string; ok: boolean; detail: string; fix?: Fix };
type Finding = { title: string; severity: string };
type Questionnaire = { failed: number; total: number; headline: string };
type Result = { domain: string; score: number; grade: string; questionnaire?: Questionnaire; checks: Check[]; findings: Finding[] };

const GRADE_TONE: Record<string, string> = {
  A: "text-pulse", B: "text-pulse", C: "text-medium", D: "text-high", F: "text-critical",
};

export function ScanForm({ initialDomain }: { initialDomain?: string }) {
  const [domain, setDomain] = useState(initialDomain ?? "");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<Result | null>(null);
  const [origin, setOrigin] = useState("");

  useEffect(() => setOrigin(window.location.origin), []);

  const scan = useCallback(async (raw: string) => {
    const d = raw.trim();
    if (!d) return;
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const res = await fetch(`/api/assess?domain=${encodeURIComponent(d)}`);
      const data = await res.json();
      if (!res.ok) setError(data?.error ?? "Couldn't assess that domain.");
      else setResult(data as Result);
    } catch {
      setError("Something went wrong — try again.");
    } finally {
      setLoading(false);
    }
  }, []);

  // Shareable permalink: /scan?domain=acme.com auto-runs, so a shared link shows the grade directly.
  useEffect(() => {
    if (initialDomain && initialDomain.trim()) scan(initialDomain);
  }, [initialDomain, scan]);

  function run(e: React.FormEvent) {
    e.preventDefault();
    scan(domain);
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
        Read-only check of your domain — email-auth (DMARC/SPF/DKIM), HTTPS/TLS, and security headers. Public DNS plus one
        request to your homepage. No signup, nothing intrusive.
      </p>

      {error && (
        <div className="mt-5 rounded-lg border border-critical/30 bg-critical/10 px-4 py-3 text-sm text-critical">{error}</div>
      )}

      {result && (
        <div className="mt-6 animate-fade-rise space-y-4 text-left">
          {(() => {
            const q = result.questionnaire ?? { failed: result.findings.length, total: result.checks.length, headline: "" };
            const passed = q.total - q.failed;
            const good = result.grade === "A" || result.grade === "B";
            return (
              <div className="card flex items-center gap-5 p-6">
                <div className={`grid h-20 w-20 shrink-0 place-items-center rounded-2xl border-2 ${good ? "border-pulse/40 bg-pulse-soft" : "border-high/40 bg-high/10"}`}>
                  <span className={`text-4xl font-bold ${GRADE_TONE[result.grade] ?? "text-ink"}`}>{result.grade}</span>
                </div>
                <div className="min-w-0">
                  <div className="mono truncate text-xs text-faint">{result.domain}</div>
                  <div className="mt-0.5 text-lg font-semibold leading-snug tracking-tight">
                    {q.headline || (q.failed === 0 ? "You pass the basic enterprise-questionnaire checks." : `You'd fail ${q.failed} of ${q.total} basic security-questionnaire checks.`)}
                  </div>
                  <p className="mt-1 text-sm text-muted">
                    Security-questionnaire readiness · <span className={GRADE_TONE[result.grade] ?? "text-ink"}>{passed}/{q.total} checks pass</span> · score {result.score}/100
                  </p>
                </div>
              </div>
            );
          })()}

          <div className="card divide-y divide-border p-0">
            {result.checks.map((c) => (
              <CheckRow key={c.name} check={c} />
            ))}
          </div>

          {/* Conversion: this is the surface a questionnaire checks first — sign up for the full picture */}
          <div className="rounded-2xl border border-accent/30 bg-accent-soft/30 p-5 text-center">
            <div className="flex items-center justify-center gap-2 text-sm font-semibold">
              <ShieldAlert className="h-4 w-4 text-accent" /> This is what an enterprise buyer&apos;s security review sees first.
            </div>
            <p className="mx-auto mt-1.5 max-w-md text-sm text-muted">
              It&apos;s the externally-visible surface. Connect a system free and TensorShield assesses your code, cloud, and
              identity too — maps every gap to its SOC 2 control, then fixes what it finds with you approving anything that matters.
            </p>
            <Link href="/signup" className="mt-4 inline-flex items-center gap-2 rounded-xl bg-accent px-5 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover active:translate-y-px">
              See your full posture — free <ArrowRight className="h-4 w-4" />
            </Link>
          </div>

          {origin && <EmbedBadge origin={origin} domain={result.domain} grade={result.grade} />}

          <LeadCapture domain={result.domain} grade={result.grade} failed={result.findings.length} />
        </div>
      )}
    </div>
  );
}

// LeadCapture closes the one gap in the funnel this page sits at the top of: the scan ran, the
// visitor saw their grade and their fixes, and then left without us ever learning who they were.
// The warmest lead source on the site produced nothing.
//
// Two deliberate constraints:
//
//  1. It renders AFTER the result, never in front of it. "Free, no signup, graded in seconds" is a
//     real asset and the page's whole SEO and sharing story; gating the grade behind an email would
//     trade the top of the funnel for the middle of it. Nothing here is required to see anything.
//  2. The offer is only what we can actually do today. It would be easy to write "email me these
//     fixes" — but nothing sends a fixes email, so that would be a promise the product does not
//     keep, on the page whose entire pitch is that we prove things rather than assert them. What we
//     genuinely do is get in touch and help, so that is what it says. Upgrading this to a real
//     fixes-email later is additive and does not invalidate anything captured now.
//
// Posts to the same public /api/lead the demo form uses — no new endpoint, no account, no storage
// of anything beyond the lead itself. `source` carries the domain and grade so sales can open the
// conversation with the person's actual result instead of a generic reply.
function LeadCapture({ domain, grade, failed }: { domain: string; grade: string; failed: number }) {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [state, setState] = useState<"idle" | "sending" | "done" | "error">("idle");

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!name.trim() || !email.trim()) return;
    setState("sending");
    try {
      const res = await fetch("/api/lead", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          // /v1/lead requires a name — the first build of this sent an empty one and every capture
          // 400'd silently, which is exactly the kind of "ships but never works" failure this whole
          // funnel pass exists to remove. Asking for it is also the honest option: the alternative
          // was inventing one from the email local-part, and sales replying to a guessed name is
          // worse than one extra field.
          name: name.trim(),
          email: email.trim(),
          company: domain,
          source: `scan:${domain}:${grade}`,
          message:
            failed > 0
              ? `Ran the free check on ${domain} — grade ${grade}, ${failed} check(s) failing. Asked for help fixing them.`
              : `Ran the free check on ${domain} — grade ${grade}, all checks passing. Asked to talk.`,
        }),
      });
      setState(res.ok ? "done" : "error");
    } catch {
      setState("error");
    }
  }

  if (state === "done") {
    return (
      <div className="card flex items-start gap-3 p-5">
        <Check className="mt-0.5 h-4 w-4 shrink-0 text-pulse" />
        <p className="text-sm text-muted">
          Got it — we&apos;ll be in touch about <span className="text-ink">{domain}</span>. Nothing else happens to your
          address.
        </p>
      </div>
    );
  }

  return (
    <form onSubmit={submit} className="card p-5">
      <div className="text-sm font-medium text-ink">
        {failed > 0 ? "Want a hand fixing these?" : "Want the checks this one can't see?"}
      </div>
      <p className="mt-1 text-xs leading-relaxed text-muted">
        {failed > 0
          ? "Leave your email and we'll get in touch. The fixes above are yours either way — no signup needed."
          : "This checks what an outsider can see. Leave your email and we'll talk about the ones that need to look inside."}
      </p>
      <div className="mt-3 flex flex-col gap-2 sm:flex-row">
        <input
          type="text"
          required
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Your name"
          className="min-w-0 rounded-lg border border-border bg-surface px-3 py-2 text-sm text-ink outline-none transition focus:border-accent/60 sm:w-36"
        />
        <input
          type="email"
          required
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="you@company.com"
          className="min-w-0 flex-1 rounded-lg border border-border bg-surface px-3 py-2 text-sm text-ink outline-none transition focus:border-accent/60"
        />
        <button
          type="submit"
          disabled={state === "sending"}
          className="inline-flex shrink-0 items-center justify-center gap-2 rounded-lg bg-accent px-4 py-2 text-sm font-semibold text-white transition hover:bg-accent-hover disabled:opacity-60"
        >
          {state === "sending" ? "Sending…" : "Get in touch"}
        </button>
      </div>
      {state === "error" && <p className="mt-2 text-xs text-high">Couldn&apos;t send that — try again.</p>}
    </form>
  );
}

// CheckRow renders one check; a failed check with a fix gets a "Fix it" expander showing the exact
// copy-paste remediation (the free "give the fix" tool).
function CheckRow({ check: c }: { check: Check }) {
  const [open, setOpen] = useState(false);
  const hasFix = !c.ok && !!c.fix && c.fix.snippets.length > 0;
  return (
    <div className="px-5 py-3">
      <div className="flex items-start gap-3">
        <span className={`mt-0.5 grid h-5 w-5 shrink-0 place-items-center rounded-full ${c.ok ? "bg-pulse/15 text-pulse" : "bg-critical/10 text-critical"}`}>
          {c.ok ? <Check className="h-3 w-3" /> : <X className="h-3 w-3" />}
        </span>
        <div className="min-w-0 flex-1">
          <div className="text-sm font-medium">{c.name}</div>
          <div className="text-xs text-muted">{c.detail}</div>
        </div>
        {hasFix && (
          <button
            onClick={() => setOpen((o) => !o)}
            className="inline-flex shrink-0 items-center gap-1 rounded-md border border-border px-2 py-1 text-[11px] font-medium text-muted transition hover:border-accent/40 hover:text-accent"
          >
            <Wrench className="h-3 w-3" /> Fix it
            <ChevronDown className={`h-3 w-3 transition-transform ${open ? "rotate-180" : ""}`} />
          </button>
        )}
      </div>
      {hasFix && open && c.fix && (
        <div className="mt-3 space-y-2 rounded-lg bg-surface-2/60 p-3 pl-11">
          <p className="text-xs text-muted">{c.fix.summary}</p>
          {c.fix.snippets.map((s, i) => (
            <CopyRow key={i} label={s.label} value={s.code} mono />
          ))}
        </div>
      )}
    </div>
  );
}

// EmbedBadge is the viral loop: a founder drops this badge on their site/README/trust page as proof
// for their own enterprise buyers — and every render is a branded backlink to /scan.
function EmbedBadge({ origin, domain, grade }: { origin: string; domain: string; grade: string }) {
  const badgeUrl = `${origin}/api/assess/badge?domain=${encodeURIComponent(domain)}`;
  const scanUrl = `${origin}/scan?domain=${encodeURIComponent(domain)}`;
  const md = `[![Security questionnaire readiness — TensorShield](${badgeUrl})](${scanUrl})`;
  const html = `<a href="${scanUrl}"><img src="${badgeUrl}" alt="Security questionnaire readiness — TensorShield"></a>`;
  const good = grade === "A" || grade === "B";

  return (
    <div className="card p-5">
      <div className="flex items-center gap-2 text-sm font-semibold">
        <Code className="h-4 w-4 text-accent" /> Embed your badge
      </div>
      <p className="mt-1 text-sm text-muted">
        {good
          ? "Show enterprise buyers you take security seriously — add this to your site, README, or trust page."
          : "Track your progress publicly — embed this badge and it updates as you fix the gaps below."}
      </p>
      {/* eslint-disable-next-line @next/next/no-img-element */}
      <img src={badgeUrl} alt={`Security questionnaire readiness — Grade ${grade}`} className="mt-3 h-5" />
      <div className="mt-3 space-y-2">
        <CopyRow label="Markdown" value={md} />
        <CopyRow label="HTML" value={html} />
      </div>
      <a href={scanUrl} className="mt-3 inline-flex items-center gap-1 text-xs font-medium text-accent hover:underline">
        Shareable link to this result <ArrowRight className="h-3 w-3" />
      </a>
    </div>
  );
}

function CopyRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  const [copied, setCopied] = useState(false);
  return (
    <div>
      <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-faint">{label}</div>
      <div className="flex items-stretch gap-2">
        {mono ? (
          <pre className="mono min-w-0 flex-1 overflow-x-auto whitespace-pre rounded-lg border border-border bg-surface px-3 py-2 text-xs leading-relaxed text-ink">{value}</pre>
        ) : (
          <code className="mono min-w-0 flex-1 truncate rounded-lg border border-border bg-surface-2 px-3 py-2 text-xs text-muted">{value}</code>
        )}
        <button
          onClick={() => {
            navigator.clipboard.writeText(value).then(() => {
              setCopied(true);
              setTimeout(() => setCopied(false), 1500);
            });
          }}
          className="inline-flex shrink-0 items-center gap-1 rounded-lg border border-border px-3 py-2 text-xs font-medium text-muted transition hover:border-accent/40 hover:text-accent"
        >
          {copied ? <Check className="h-3.5 w-3.5 text-pulse" /> : <Copy className="h-3.5 w-3.5" />}
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
    </div>
  );
}
