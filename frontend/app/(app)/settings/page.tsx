import Link from "next/link";
import {
  Building2, ShieldCheck, ArrowUpRight, Mail, BellRing, Lock, CheckCircle2,
} from "lucide-react";
import { api } from "@/lib/api";
import { getSession } from "@/lib/auth";
import { kindLabel } from "@/lib/connectors";
import { ProviderIcon } from "@/components/brand/provider-icon";
import { Card, SectionTitle } from "@/components/ui/primitives";
import { SignOutButton } from "@/components/settings/sign-out-button";
import { TrustShare } from "@/components/settings/trust-share";
import { TeamSection } from "@/components/settings/team-section";
import { KillSwitch } from "@/components/settings/kill-switch";
import { BillingControl } from "@/components/settings/billing-control";
import { CloudRemediationControl } from "@/components/settings/cloud-remediation-control";
import { SlackWebhookControl } from "@/components/settings/slack-webhook-control";
import { GitHubPostureSync } from "@/components/settings/github-posture-sync";
import { JiraControl } from "@/components/settings/jira-control";
import { EscalationControl } from "@/components/settings/escalation-control";
import { SLAControl } from "@/components/settings/sla-control";
import { MaintenanceControl } from "@/components/settings/maintenance-control";
import { ContactsControl } from "@/components/settings/contacts-control";
import { PractitionersControl } from "@/components/settings/practitioners-control";
import { AIBomPanel } from "@/components/settings/ai-bom-panel";
import { LLMSettings } from "@/components/settings/llm-settings";
import { PRBotSettingsPanel } from "@/components/settings/pr-bot-settings";
import { PageIntro } from "@/components/ui/page-intro";

export const dynamic = "force-dynamic";

const STATUS_CLS: Record<string, string> = {
  active: "text-pulse bg-pulse-soft",
  degraded: "text-medium bg-medium/10",
  revoked: "text-critical bg-critical/10",
};

export default async function SettingsPage() {
  const session = await getSession();
  const [tenant, connections, trust, team, me, aiBom, llm, prBot, notify, jira, escalation] = await Promise.all([
    api.tenant(), api.connections(), api.trustLink(), api.team(), api.me(), api.aiBom(), api.llmSettings(), api.prBotSettings(), api.notifySettings(), api.jiraSettings(), api.escalationSettings(),
  ]);
  const [sla, maintenance, contacts, practitioners] = await Promise.all([api.slaSettings(), api.maintenanceWindows(), api.contacts(), api.practitioners()]);
  const orgName = tenant?.name ?? "Your organization";
  const plan = tenant?.plan || "free";
  // Customer-facing label — the store key for Core is "growth" (legacy); never show that to a user.
  const planLabel = plan === "growth" ? "Core" : plan === "enterprise" ? "Enterprise" : "Free";

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <PageIntro
        icon={Building2}
        title="Settings"
        description="Your organization, connected systems, team, and how the agent reaches you — plus the safety controls: the kill-switch, what the agent is allowed to touch, and your public trust link."
      />

      {/* Organization */}
      <div>
        <SectionTitle>Organization</SectionTitle>
        <Card className="space-y-3 p-5">
          <Row icon={Building2} label="Name" value={orgName} />
          <Row icon={ShieldCheck} label="Plan" value={<span className="inline-flex items-center rounded-full bg-accent-soft px-2 py-0.5 text-xs font-medium text-accent">{planLabel}</span>} />
          <Row icon={Lock} label="Tenant ID" value={<span className="mono text-xs text-muted">{session?.tenant ?? "—"}</span>} />
          {tenant?.created_at && (
            <Row icon={CheckCircle2} label="Member since" value={<span className="text-sm text-muted">{new Date(tenant.created_at).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" })}</span>} />
          )}
        </Card>
      </div>

      {/* Billing — the self-serve purchase path. On Free this is the upgrade to the two AI agents; on a
          paid plan it just confirms what's active. The plan itself only ever changes via Razorpay's
          signed webhook, server-side. */}
      <div>
        <SectionTitle>Plan &amp; billing</SectionTitle>
        <BillingControl plan={plan} planLabel={planLabel} />
      </div>

      {/* Service model — who employs the human-in-the-loop (self-serve / MSP / managed). A defining org
          property (changes who owns approvals across the whole app), so it's its own top-level section,
          not buried in Notifications. */}
      <div>
        <SectionTitle action={<span className="text-[11px] text-faint">changes who owns approvals</span>}>
          Service model
        </SectionTitle>
        <Card className="p-5">
          <PractitionersControl serviceModel={practitioners.service_model} practitioners={practitioners.practitioners} />
        </Card>
      </div>

      {/* Your security team — the accountability hub (who owns the human calls + escalate for a second
          opinion). Account context, so it lives here, not on the daily sidebar. */}
      <div>
        <SectionTitle action={<Link href="/security-team" className="text-[11px] font-medium text-accent hover:underline">view →</Link>}>
          Your security team
        </SectionTitle>
        <Card className="p-5">
          <p className="text-sm text-muted">
            Who&apos;s accountable for the human-in-the-loop decisions — fix approvals, risk calls, policy
            publication, audit attestations, pentest sign-off — and where to escalate any finding for a second opinion.
          </p>
        </Card>
      </div>

      {/* AI engine — bring-your-own-LLM for the agent + autonomous pentest */}
      <div id="ai-engine" className="scroll-mt-20">
        <SectionTitle>AI engine</SectionTitle>
        <Card className="p-5">
          <LLMSettings initial={llm} />
        </Card>
      </div>

      {/* Repository PR-review bot — inline review + merge-gating check-run (ADR 0010) */}
      <div>
        <SectionTitle>Pull-request review</SectionTitle>
        <Card className="p-5">
          <PRBotSettingsPanel initial={prBot} />
        </Card>
      </div>

      {/* Automation control — the global kill-switch + what the agent can touch (WRD-1) */}
      <div>
        <SectionTitle>Automation</SectionTitle>
        <div className="space-y-3">
          <KillSwitch halted={tenant?.agents_halted ?? false} canToggle={me?.role === "owner"} />
          <AIBomPanel bom={aiBom} canQuarantine={me?.role === "owner"} />
        </div>
      </div>

      {/* Team */}
      {team.length > 0 && (
        <div>
          <SectionTitle action={me?.role === "owner" ? <span className="text-[11px] text-faint">owner can invite</span> : undefined}>
            Team
          </SectionTitle>
          <TeamSection members={team} currentEmail={me?.email} canInvite={me?.role === "owner"} />
        </div>
      )}

      {/* Connected systems */}
      <div>
        <SectionTitle action={<Link href="/assets" className="text-[11px] font-medium text-accent hover:underline">manage →</Link>}>
          Connected systems
        </SectionTitle>
        <Card className="p-0">
          {connections.length === 0 ? (
            <div className="p-5 text-sm text-muted">
              No systems connected yet. <Link href="/assets" className="text-accent hover:underline">Connect one →</Link>
            </div>
          ) : (
            <ul className="divide-y divide-border">
              {connections.map((c) => {
                const isCloud = c.kind === "aws" || c.kind === "gcp" || c.kind === "azure";
                return (
                  <li key={c.id} className="px-5 py-3">
                    <div className="flex items-center gap-3">
                      <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg border border-border bg-surface-2 text-ink">
                        <ProviderIcon kind={c.kind} className="h-4 w-4" />
                      </span>
                      <div className="min-w-0 flex-1">
                        <div className="text-sm font-medium">{kindLabel(c.kind)}</div>
                        {c.account && <div className="mono truncate text-xs text-faint">{c.account}</div>}
                      </div>
                      <span className={`rounded-full px-2 py-0.5 text-[11px] font-medium capitalize ${STATUS_CLS[c.status] ?? "text-muted bg-surface-2"}`}>
                        {c.status}
                      </span>
                    </div>
                    {isCloud && (
                      <div className="mt-2 pl-11">
                        <CloudRemediationControl id={c.id} kind={c.kind} config={c.config} />
                      </div>
                    )}
                    {c.kind === "github" && <GitHubPostureSync />}
                  </li>
                );
              })}
            </ul>
          )}
        </Card>
      </div>

      {/* Public Trust Center */}
      {trust?.path && (
        <div>
          <SectionTitle action={<span className="text-[11px] text-faint">public · token-gated</span>}>
            Trust Center
          </SectionTitle>
          <Card className="space-y-3 p-5">
            <p className="text-xs text-muted">
              Share a live, public proof of your security &amp; compliance posture — coverage only, never your findings.
              The link is non-guessable; revoke it by rotating your platform secret.
            </p>
            <TrustShare path={trust.path} />
          </Card>
        </div>
      )}

      {/* Notifications */}
      <div>
        <SectionTitle>Notifications</SectionTitle>
        <Card className="space-y-3 p-5">
          <p className="text-xs text-muted">Where the agent reaches a human. Connect your own Slack below; other channels are provisioned by your administrator.</p>
          <SlackWebhookControl configured={notify.has_slack_webhook} />
          <JiraControl config={jira} />
          <EscalationControl policy={escalation} />
          <ContactsControl contacts={contacts} />
          <SLAControl policy={sla} />
          <MaintenanceControl windows={maintenance} />
          {[
            { icon: BellRing, name: "PagerDuty", role: "New critical issues page on-call" },
            { icon: Mail, name: "Email", role: "Digest of pending approvals" },
          ].map(({ icon: Icon, name, role }) => (
            <div key={name} className="flex items-center gap-3 rounded-xl border border-border bg-surface-2 px-3.5 py-2.5">
              <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-surface text-muted">
                <Icon className="h-4 w-4" />
              </span>
              <div className="min-w-0 flex-1">
                <div className="text-sm font-medium">{name}</div>
                <div className="text-xs text-muted">{role}</div>
              </div>
              <span className="text-[11px] text-faint">admin-managed</span>
            </div>
          ))}
        </Card>
      </div>

      {/* Activity log — the tamper-evident audit trail. Account context, moved off the daily sidebar. */}
      <div>
        <SectionTitle action={<Link href="/activity" className="text-[11px] font-medium text-accent hover:underline">view →</Link>}>
          Activity log
        </SectionTitle>
        <Card className="p-5">
          <p className="text-sm text-muted">
            Every scan, fix, and signed decision, in order — the tamper-evident audit trail for you and your auditor.
          </p>
        </Card>
      </div>

      {/* Security & session */}
      <div>
        <SectionTitle>Security &amp; session</SectionTitle>
        <Card className="space-y-4 p-5">
          <ul className="space-y-2.5 text-sm">
            {[
              "Your session token is httpOnly + SameSite=Strict — never exposed to the browser.",
              "Connections are least-privilege and read-only by default; write-back only on your approval.",
              "Every automated and human decision is signed into a tamper-evident ledger.",
            ].map((x) => (
              <li key={x} className="flex items-start gap-2.5 text-muted">
                <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-pulse" /> {x}
              </li>
            ))}
          </ul>
          <div className="flex items-center justify-between border-t border-border pt-4">
            <Link href="/security" className="inline-flex items-center gap-1 text-xs font-medium text-accent hover:underline">
              How we keep you safe <ArrowUpRight className="h-3.5 w-3.5" />
            </Link>
            <SignOutButton />
          </div>
        </Card>
      </div>
    </div>
  );
}

function Row({ icon: Icon, label, value }: { icon: typeof Building2; label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-center gap-3">
      <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-surface-2 text-muted">
        <Icon className="h-4 w-4" />
      </span>
      <span className="w-28 shrink-0 text-xs text-faint">{label}</span>
      <span className="text-sm font-medium">{value}</span>
    </div>
  );
}
