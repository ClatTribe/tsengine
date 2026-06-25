import Link from "next/link";
import { pageMeta } from "@/lib/seo";
import { AuroraBackdrop } from "@/components/marketing/aurora";
import {
  KeyRound, ArrowRight, Mail, UserX, AppWindow, Webhook,
  Fingerprint, Radar, Bot, CheckCircle2, XCircle, Minus, Cloud,
} from "lucide-react";
import { ProviderIcon } from "@/components/brand/provider-icon";

export const metadata = pageMeta({
  title: "SaaS & identity posture (SSPM) — Google, M365, Okta, GitHub, Slack, Zoom, Atlassian, Salesforce | TensorShield",
  description:
    "Most breaches start with a misconfigured SaaS app or a missing MFA. TensorShield continuously checks your identity providers and SaaS apps for risky settings — grounded, compliance-mapped, and fixed with you in the loop.",
  path: "/saas-posture",
});

// The posture checks across identity + SaaS apps. A row carries either a topic `icon` (lucide) or a
// `brand` key (real provider logo via ProviderIcon).
const CHECKS: { icon?: typeof KeyRound; brand?: string; t: string; d: string }[] = [
  { icon: KeyRound, t: "MFA enforcement gaps", d: "Admins and members without a second factor across Google Workspace, Microsoft 365, and Okta — the single highest-leverage identity risk." },
  { icon: AppWindow, t: "Risky OAuth / third-party apps", d: "Shadow-admin grants and unverified-publisher apps that can read your data — surfaced live across Google, M365, Okta, and GitHub/Slack app installs." },
  { icon: UserX, t: "Stale & over-privileged accounts", d: "Dormant logins and excess owners/admins — the lateral-movement surface an attacker inherits after a single phish." },
  { icon: Mail, t: "Email spoofing (DMARC/SPF/DKIM)", d: "Your sending domains resolved from public DNS — a weak or missing DMARC record is open season for phishing in your name." },
  { brand: "github", t: "GitHub org hardening", d: "Org-wide 2FA enforcement, default repo permissions, secret scanning / push protection, outside collaborators, and insecure webhooks." },
  { brand: "slack", t: "Slack workspace hardening", d: "2FA / SSO enforcement, app-approval governance, public file-link sharing, guest accounts, and admin sprawl." },
  { brand: "zoom", t: "Zoom account hardening", d: "2FA / SSO enforcement, meeting passcodes and waiting rooms, cloud-recording protection and retention, app-approval governance, and admin sprawl." },
  { brand: "atlassian", t: "Atlassian (Jira/Confluence) hardening", d: "2FA / SSO enforcement, public Confluence spaces, SSO-bypassing user API tokens, open sign-up, Marketplace app governance, and admin sprawl." },
  { icon: Cloud, t: "Salesforce org hardening", d: "MFA / SSO enforcement, public Experience Cloud guest access (the well-known data-leak path), broad-scope connected apps, Modify-All-Data sprawl, login IP restrictions, and admin sprawl." },
];

const DIFF = [
  { icon: Fingerprint, t: "Grounded — a hardened app is silent", d: "Every finding cites the exact setting or account it's about. A correctly-configured workspace returns zero findings, so the alerts you get are real and actionable." },
  { icon: Radar, t: "Continuous + compliance-mapped", d: "Re-checked on a schedule, and every finding maps to the controls it touches (SOC 2, CIS, NIST, PCI) — flowing into the same signed evidence pack as your code and cloud." },
  { icon: Bot, t: "Fixed with you in the loop", d: "The agent prepares the fix — enforce MFA, revoke the grant, suspend the stale account — and applies it the moment you approve (live today for Okta; runbooks for the rest)." },
];

const APPS = ["Google Workspace", "Microsoft 365", "Okta", "GitHub", "Slack", "Zoom", "Atlassian", "Salesforce"];

const COMPARE: { label: string; cells: string[] }[] = [
  { label: "Identity MFA / OAuth / stale-account posture", cells: ["yes", "part"] },
  { label: "Email spoofing (DMARC/SPF/DKIM)", cells: ["yes", "no"] },
  { label: "GitHub org configuration posture", cells: ["yes", "part"] },
  { label: "Slack workspace configuration posture", cells: ["yes", "no"] },
  { label: "Zoom account configuration posture", cells: ["yes", "no"] },
  { label: "Atlassian (Jira/Confluence) configuration posture", cells: ["yes", "no"] },
  { label: "Salesforce org configuration posture", cells: ["yes", "no"] },
  { label: "Compliance-mapped into one evidence pack", cells: ["yes", "part"] },
  { label: "Fixes the misconfiguration on approval", cells: ["yes", "no"] },
];

export default function SaaSPosture() {
  return (
    <>
      {/* Hero */}
      <section className="relative overflow-hidden">
        <AuroraBackdrop />
        <div className="relative animate-fade-rise mx-auto max-w-3xl px-5 pb-12 pt-20 text-center">
          <span className="inline-flex items-center gap-1.5 rounded-full border border-border bg-surface px-3 py-1 text-xs font-medium text-muted shadow-sm">
            <KeyRound className="h-3.5 w-3.5 text-accent" /> SaaS &amp; identity posture (SSPM)
          </span>
          <h1 className="mt-6 text-4xl font-semibold leading-[1.08] tracking-tight sm:text-5xl">
            Your SaaS is misconfigured — and no one&apos;s watching.
          </h1>
          <p className="mx-auto mt-5 max-w-xl text-lg leading-relaxed text-muted">
            The breach rarely starts in your code. It starts with a missing MFA, an over-scoped third-party app, or a
            GitHub org anyone can push to. TensorShield continuously checks your identity providers and SaaS apps for
            the settings that let attackers in — grounded, compliance-mapped, and fixed with you in the loop.
          </p>
          <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
            <Link href="/signup" className="inline-flex items-center gap-2 rounded-xl bg-accent px-5 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover active:translate-y-px">
              Check your posture <ArrowRight className="h-4 w-4" />
            </Link>
            <Link href="/scan" className="inline-flex items-center gap-2 rounded-xl border border-border bg-surface px-5 py-3 text-sm font-semibold text-ink shadow-sm transition hover:border-border-strong">
              Free email-spoofing check
            </Link>
          </div>
          <div className="mt-7 flex flex-wrap items-center justify-center gap-2">
            {APPS.map((a) => (
              <span key={a} className="inline-flex items-center gap-1.5 rounded-full border border-border bg-bg px-3 py-1 text-xs font-medium text-ink shadow-sm">
                <ProviderIcon kind={a} className="h-3.5 w-3.5" /> {a}
              </span>
            ))}
          </div>
        </div>
      </section>

      {/* The checks */}
      <section className="mx-auto max-w-6xl px-5 pb-4 pt-8">
        <div className="mx-auto mb-10 max-w-2xl text-center">
          <span className="text-xs font-semibold uppercase tracking-wider text-accent">What we check</span>
          <h2 className="mt-3 text-3xl font-semibold leading-tight tracking-tight">The misconfigurations that get SMBs breached.</h2>
          <p className="mt-3 text-base leading-relaxed text-muted">
            Identity and SaaS-app settings, assessed continuously from a read-only connection — no agent to install.
          </p>
        </div>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {CHECKS.map(({ icon: Icon, brand, t, d }) => (
            <div key={t} className="card p-5">
              <span className="grid h-9 w-9 place-items-center rounded-lg bg-accent-soft text-accent">
                {brand ? <ProviderIcon kind={brand} className="h-4 w-4" /> : Icon ? <Icon className="h-4 w-4" /> : null}
              </span>
              <h3 className="mt-3.5 text-sm font-semibold">{t}</h3>
              <p className="mt-1.5 text-sm leading-relaxed text-muted">{d}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Differentiators */}
      <section className="bg-surface">
        <div className="mx-auto max-w-6xl px-5 py-20">
          <div className="mx-auto mb-12 max-w-2xl text-center">
            <span className="text-xs font-semibold uppercase tracking-wider text-accent">Why it&apos;s different</span>
            <h2 className="mt-3 text-3xl font-semibold leading-tight tracking-tight">Grounded, continuous, and it fixes things.</h2>
          </div>
          <div className="grid gap-4 sm:grid-cols-3">
            {DIFF.map(({ icon: Icon, t, d }) => (
              <div key={t} className="card bg-bg p-6">
                <span className="grid h-9 w-9 place-items-center rounded-lg bg-accent-soft text-accent">
                  <Icon className="h-4 w-4" />
                </span>
                <h3 className="mt-3.5 text-sm font-semibold">{t}</h3>
                <p className="mt-1.5 text-sm leading-relaxed text-muted">{d}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* How it works */}
      <section className="mx-auto max-w-5xl px-5 py-20">
        <div className="mx-auto mb-12 max-w-2xl text-center">
          <span className="text-xs font-semibold uppercase tracking-wider text-accent">How it works</span>
          <h2 className="mt-3 text-3xl font-semibold leading-tight tracking-tight">Connect once. It watches from there.</h2>
        </div>
        <div className="grid gap-5 md:grid-cols-4">
          {[
            { step: "1", icon: KeyRound, t: "Connect", d: "One-click, read-only OAuth into Google, M365, Okta, GitHub, Slack, Zoom, Atlassian, or Salesforce. Tokens sealed at rest; never a password." },
            { step: "2", icon: Fingerprint, t: "Snapshot", d: "A grounded snapshot of every relevant setting and account — MFA, OAuth grants, org/workspace config, DNS." },
            { step: "3", icon: Webhook, t: "Assess", d: "Deterministic checks map each gap to its compliance controls. A hardened workspace produces zero findings." },
            { step: "4", icon: Bot, t: "Fix on approval", d: "The agent prepares — and on your tap, applies — the fix. Every decision signed into a tamper-evident ledger." },
          ].map(({ step, icon: Icon, t, d }) => (
            <div key={t} className="card p-6">
              <div className="flex items-center gap-3">
                <span className="grid h-10 w-10 place-items-center rounded-xl bg-accent-soft text-accent">
                  <Icon className="h-5 w-5" />
                </span>
                <span className="text-xs font-semibold text-faint">STEP {step}</span>
              </div>
              <h3 className="mt-4 text-sm font-semibold">{t}</h3>
              <p className="mt-1.5 text-sm leading-relaxed text-muted">{d}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Compare */}
      <section className="bg-surface">
        <div className="mx-auto max-w-5xl px-5 py-20">
          <div className="mx-auto mb-12 max-w-2xl text-center">
            <span className="text-xs font-semibold uppercase tracking-wider text-accent">Vs an AppSec-only scanner</span>
            <h2 className="mt-3 text-3xl font-semibold leading-tight tracking-tight">Most tools never look past your code.</h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[560px] border-separate border-spacing-0 text-sm">
              <thead>
                <tr>
                  <th className="w-[58%] p-0" />
                  {[
                    { name: "TensorShield", sub: "SaaS + identity", highlight: true },
                    { name: "AppSec scanner", sub: "code + cloud only", highlight: false },
                  ].map((c) => (
                    <th key={c.name} className={`rounded-t-xl px-4 py-3 text-center align-bottom ${c.highlight ? "bg-accent-soft/60 ring-1 ring-accent/30" : ""}`}>
                      <div className={`text-sm font-semibold ${c.highlight ? "text-accent" : "text-ink"}`}>{c.name}</div>
                      <div className="mt-0.5 text-[11px] font-normal text-faint">{c.sub}</div>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {COMPARE.map((r, ri) => (
                  <tr key={r.label}>
                    <td className="border-t border-border py-3 pr-4 text-sm text-ink">{r.label}</td>
                    {r.cells.map((v, ci) => (
                      <td key={ci} className={`border-t border-border px-4 py-3 text-center ${ci === 0 ? "bg-accent-soft/30" : ""} ${ri === COMPARE.length - 1 ? "rounded-b-xl" : ""}`}>
                        <Cell v={v} highlight={ci === 0} />
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="mt-4 text-center text-[11px] text-faint">Category comparison — capabilities vary by vendor and plan.</p>
        </div>
      </section>

      {/* CTA */}
      <section className="relative overflow-hidden bg-gradient-to-br from-accent via-[#4338CA] to-[#3730A3]">
        <div className="absolute -right-20 -top-24 h-80 w-80 rounded-full bg-white/10 blur-3xl" />
        <div className="relative mx-auto max-w-3xl px-5 py-20 text-center text-white">
          <h2 className="text-3xl font-semibold tracking-tight sm:text-4xl">Close the door attackers actually use.</h2>
          <p className="mx-auto mt-3 max-w-lg text-white/75">
            Connect your identity provider and SaaS apps, see every risky setting in minutes — with the fix ready to ship.
          </p>
          <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
            <Link href="/signup" className="inline-flex items-center gap-2 rounded-xl bg-white px-5 py-3 text-sm font-semibold text-accent shadow-sm transition hover:bg-white/90">
              Start free <ArrowRight className="h-4 w-4" />
            </Link>
            <Link href="/integrations" className="inline-flex items-center gap-2 rounded-xl bg-white/10 px-5 py-3 text-sm font-semibold text-white ring-1 ring-white/20 transition hover:bg-white/15">
              See integrations
            </Link>
          </div>
        </div>
      </section>
    </>
  );
}

function Cell({ v, highlight }: { v: string; highlight: boolean }) {
  if (v === "yes") return <CheckCircle2 className={`mx-auto h-5 w-5 ${highlight ? "text-pulse" : "text-pulse/80"}`} />;
  if (v === "no") return <XCircle className="mx-auto h-5 w-5 text-faint/60" />;
  if (v === "part") return <Minus className="mx-auto h-5 w-5 text-amber-500/70" />;
  return <span className={`text-sm font-semibold ${highlight ? "text-accent" : "text-muted"}`}>{v}</span>;
}
