import Link from "next/link";
import { pageMeta } from "@/lib/seo";
import { AuroraBackdrop } from "@/components/marketing/aurora";
import { KeyRound, ShieldCheck, AppWindow, UserMinus, Share2, ScanFace, ArrowRight, CheckCircle2 } from "lucide-react";

export const metadata = pageMeta({
  title: "Identity & SaaS posture — TensorShield",
  description:
    "The blind spot the code-and-cloud scanners miss: who can log in, what third-party apps hold the keys, and which SaaS settings are leaking data. MFA gaps, shadow-admin OAuth grants, stale access, and SSPM across Google Workspace, M365, Okta, GitHub, Slack — grounded, no agent guesswork.",
  path: "/identity",
});

const CHECKS = [
  { icon: ScanFace, t: "MFA & login posture", d: "Admins without MFA, weak factors, password-only logins, dormant accounts that still authenticate — the account-takeover surface, per identity." },
  { icon: AppWindow, t: "Third-party OAuth grants", d: "Every app with access, flagged for shadow-admin scopes (a SaaS app with write-everything) and unverified publishers — the supply chain into your identity plane." },
  { icon: UserMinus, t: "Stale & over-privileged access", d: "Suspended accounts that still hold admin role bindings, standing privilege that survived offboarding — the deprovisioning gap the active-account checks skip." },
  { icon: Share2, t: "SaaS data-sharing (SSPM)", d: "Anonymous & external sharing in SharePoint/OneDrive/Drive, open Teams/Slack federation, public Confluence, SSO-bypassing API tokens — config that leaks data, not code." },
  { icon: ShieldCheck, t: "Mapped to your frameworks", d: "Each gap lands on SOC 2, ISO 27001, HIPAA, NIST and more — so an identity finding is also an audit finding, in the same evidence pack." },
  { icon: KeyRound, t: "Real-time identity threats (ITDR)", d: "Impossible travel, MFA-fatigue, password spray, MFA-removed-then-login — the account-takeover sequence, detected from the IdP audit stream." },
];

const PROVIDERS = ["Google Workspace", "Microsoft 365", "Okta", "GitHub", "Slack", "Zoom", "Atlassian", "Salesforce"];

export default function Identity() {
  return (
    <>
      <section className="relative overflow-hidden">
        <AuroraBackdrop />
        <div className="relative animate-fade-rise mx-auto max-w-3xl px-5 pb-10 pt-20 text-center">
          <span className="inline-flex items-center gap-1.5 rounded-full border border-border bg-surface px-3 py-1 text-xs font-medium text-muted shadow-sm">
            <KeyRound className="h-3.5 w-3.5 text-accent" /> Identity &amp; SaaS posture
          </span>
          <h1 className="mt-6 text-4xl font-semibold tracking-tight sm:text-5xl">
            Most breaches start with a login, not a CVE.
          </h1>
          <p className="mx-auto mt-4 max-w-xl text-lg leading-relaxed text-muted">
            Code and cloud scanners can&apos;t see who can log in, which third-party app holds admin, or which SaaS
            setting is sharing your data with the world. TensorShield does — across every identity provider and SaaS
            estate you run, grounded in real config, not agent guesswork.
          </p>
        </div>
      </section>

      <section className="mx-auto max-w-6xl px-5 pb-12">
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {CHECKS.map(({ icon: Icon, t, d }) => (
            <div key={t} className="card p-5">
              <span className="grid h-9 w-9 place-items-center rounded-lg bg-accent-soft text-accent">
                <Icon className="h-4 w-4" />
              </span>
              <h3 className="mt-3.5 text-sm font-semibold">{t}</h3>
              <p className="mt-1.5 text-sm leading-relaxed text-muted">{d}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="bg-surface">
        <div className="mx-auto max-w-4xl px-5 py-20 text-center">
          <span className="text-xs font-semibold uppercase tracking-wider text-accent">One connection each</span>
          <h2 className="mt-3 text-3xl font-semibold tracking-tight">Every identity provider and SaaS estate.</h2>
          <p className="mx-auto mt-3 max-w-lg text-base leading-relaxed text-muted">
            Connect read-only and get posture in minutes — a hardened estate yields zero findings, so what you see is
            real, not noise.
          </p>
          <div className="mt-8 flex flex-wrap items-center justify-center gap-2.5">
            {PROVIDERS.map((p) => (
              <span key={p} className="inline-flex items-center gap-1.5 rounded-full border border-border bg-bg px-3.5 py-1.5 text-sm font-medium text-ink shadow-sm">
                <CheckCircle2 className="h-3.5 w-3.5 text-pulse" /> {p}
              </span>
            ))}
          </div>
        </div>
      </section>

      <section className="mx-auto max-w-3xl px-5 py-20 text-center">
        <h2 className="text-2xl font-semibold tracking-tight">See your identity blind spot.</h2>
        <p className="mx-auto mt-3 max-w-xl text-base leading-relaxed text-muted">
          Connect a workspace and the agent surfaces the gaps, maps them to your frameworks, and — with a human in the
          loop — fixes the ones it safely can.
        </p>
        <Link href="/signup" className="mt-7 inline-flex items-center gap-1.5 text-sm font-semibold text-accent hover:underline">
          Start free <ArrowRight className="h-4 w-4" />
        </Link>
      </section>
    </>
  );
}
