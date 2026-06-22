import Link from "next/link";
import { pageMeta } from "@/lib/seo";
import {
  Github, GitBranch, Cloud, Mail, Users, KeyRound, Ticket, ClipboardList,
  MessageSquare, MessagesSquare, MessageCircle, BellRing, ArrowRight, Plug, Webhook, Container, FileJson,
} from "lucide-react";

export const metadata = pageMeta({
  title: "Integrations — TensorShield",
  description:
    "Connect your stack in minutes: GitHub, GitLab, Bitbucket, AWS, Google Workspace, Microsoft 365, Okta — plus Jira, ServiceNow, Linear, Slack, Microsoft Teams, Discord, PagerDuty and signed outbound webhooks for delivery. Read-only by default, write-back only on approval.",
  path: "/integrations",
});

type Item = { icon: typeof Github; name: string; role: string; status: "live" | "soon" };

const GROUPS: { title: string; blurb: string; items: Item[] }[] = [
  {
    title: "Code & repositories",
    blurb: "Source, dependencies and secrets — scanned on every push.",
    items: [
      { icon: Github, name: "GitHub", role: "Repos, SCA, secret scanning, fix PRs", status: "live" },
      { icon: GitBranch, name: "GitLab", role: "Repos, SCA, secret scanning, fix MRs", status: "live" },
      { icon: GitBranch, name: "Bitbucket", role: "Repos, SCA, secret scanning, fix PRs", status: "live" },
    ],
  },
  {
    title: "Cloud",
    blurb: "Misconfig, public exposure and IAM blast-radius — each traced back to the Terraform line that provisioned it (Cloud-to-Code).",
    items: [
      { icon: Cloud, name: "AWS", role: "CSPM, IAM, exposed resources", status: "live" },
      { icon: Cloud, name: "Google Cloud", role: "CSPM & IAM posture", status: "soon" },
      { icon: Cloud, name: "Azure", role: "CSPM & IAM posture", status: "soon" },
    ],
  },
  {
    title: "API specs",
    blurb: "Import your API surface so every endpoint gets tested — from an OpenAPI spec or a Postman collection.",
    items: [
      { icon: FileJson, name: "OpenAPI / Swagger", role: "Spec ingest → per-endpoint DAST", status: "live" },
      { icon: FileJson, name: "Postman", role: "Import a collection → per-endpoint inventory", status: "live" },
    ],
  },
  {
    title: "Container registries",
    blurb: "Scan on push — only new or re-pushed image digests get scanned, never the whole registry every cycle.",
    items: [
      { icon: Container, name: "Docker Hub", role: "Auto-discover images, scan on push (digest-diff)", status: "live" },
      { icon: Container, name: "GitHub Container Registry", role: "Auto-discover images, scan on push", status: "soon" },
      { icon: Container, name: "Amazon ECR", role: "Auto-discover images, scan on push", status: "soon" },
    ],
  },
  {
    title: "Identity & workspace",
    blurb: "MFA gaps, risky OAuth grants, stale accounts and email spoofing.",
    items: [
      { icon: Mail, name: "Google Workspace", role: "Admin MFA, OAuth grants, DMARC/SPF/DKIM", status: "live" },
      { icon: Users, name: "Microsoft 365", role: "Admin MFA, OAuth grants, email auth", status: "live" },
      { icon: KeyRound, name: "Okta", role: "MFA factors, admin roles, stale/suspend", status: "live" },
    ],
  },
  {
    title: "Ticketing & alerts",
    blurb: "Where fixes and approvals land — in the tools you already run on.",
    items: [
      { icon: Ticket, name: "Jira", role: "Remediation tickets with evidence", status: "live" },
      { icon: ClipboardList, name: "ServiceNow", role: "Remediation tickets with evidence", status: "live" },
      { icon: Ticket, name: "Linear", role: "Remediation issues filed to your team", status: "live" },
      { icon: MessageSquare, name: "Slack", role: "Approve/reject fixes in-channel", status: "live" },
      { icon: MessagesSquare, name: "Microsoft Teams", role: "New critical issues posted to your channel", status: "live" },
      { icon: BellRing, name: "PagerDuty", role: "New critical issues page on-call", status: "live" },
      { icon: MessageCircle, name: "Discord", role: "New critical issues posted to your channel", status: "live" },
      { icon: Webhook, name: "Webhooks", role: "Signed JSON event per new issue — wire into Zapier, n8n, a SIEM, anything", status: "live" },
    ],
  },
];

export default function Integrations() {
  return (
    <>
      <section className="relative overflow-hidden">
        <div className="pointer-events-none absolute inset-x-0 -top-40 h-80 bg-gradient-to-b from-accent-soft/60 to-transparent" />
        <div className="relative mx-auto max-w-3xl px-5 pb-10 pt-20 text-center">
          <span className="inline-flex items-center gap-1.5 rounded-full border border-border bg-surface px-3 py-1 text-xs font-medium text-muted shadow-sm">
            <Plug className="h-3.5 w-3.5 text-accent" /> Connect in minutes
          </span>
          <h1 className="mt-6 text-4xl font-semibold tracking-tight sm:text-5xl">Works with the stack you already run.</h1>
          <p className="mx-auto mt-4 max-w-xl text-lg leading-relaxed text-muted">
            One click of OAuth and the agent discovers your assets and starts working. Read-only by default —
            it only writes back the fixes you approve.
          </p>
        </div>
      </section>

      <section className="mx-auto max-w-6xl px-5 pb-12">
        <div className="space-y-10">
          {GROUPS.map((g) => (
            <div key={g.title}>
              <div className="mb-4">
                <h2 className="text-lg font-semibold tracking-tight">{g.title}</h2>
                <p className="mt-1 text-sm text-muted">{g.blurb}</p>
              </div>
              <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                {g.items.map(({ icon: Icon, name, role, status }) => (
                  <div key={name} className="card flex items-start gap-3 p-5">
                    <span className="grid h-10 w-10 shrink-0 place-items-center rounded-xl border border-border bg-surface-2 text-ink">
                      <Icon className="h-5 w-5" />
                    </span>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-semibold">{name}</span>
                        {status === "live" ? (
                          <span className="inline-flex items-center gap-1 rounded-full bg-pulse-soft px-1.5 py-0.5 text-[10px] font-medium text-pulse">
                            <span className="pulse-dot" /> Live
                          </span>
                        ) : (
                          <span className="rounded-full border border-border bg-surface-2 px-1.5 py-0.5 text-[10px] font-medium text-faint">
                            Coming soon
                          </span>
                        )}
                      </div>
                      <p className="mt-1 text-xs leading-relaxed text-muted">{role}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Trust + CTA */}
      <section className="bg-surface">
        <div className="mx-auto max-w-3xl px-5 py-20 text-center">
          <h2 className="text-2xl font-semibold tracking-tight">Don&apos;t see your tool?</h2>
          <p className="mx-auto mt-3 max-w-lg text-base leading-relaxed text-muted">
            New connectors ship continuously. Every integration is least-privilege and read-only by default — the
            agent never changes anything until you approve it.
          </p>
          <div className="mt-7 flex flex-wrap items-center justify-center gap-3">
            <Link href="/signup" className="inline-flex items-center gap-2 rounded-xl bg-accent px-5 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover active:translate-y-px">
              Start free <ArrowRight className="h-4 w-4" />
            </Link>
            <Link href="/product" className="inline-flex items-center gap-2 rounded-xl border border-border bg-bg px-5 py-3 text-sm font-semibold text-ink shadow-sm transition hover:border-border-strong">
              How it works
            </Link>
          </div>
        </div>
      </section>
    </>
  );
}
