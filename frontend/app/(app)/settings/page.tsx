import Link from "next/link";
import {
  Building2, Plug, Bell, ShieldCheck, ArrowUpRight, Github, GitBranch, Mail, Users,
  KeyRound, Cloud, MessageSquare, BellRing, Lock, CheckCircle2,
} from "lucide-react";
import { api } from "@/lib/api";
import { getSession } from "@/lib/auth";
import { kindLabel } from "@/lib/connectors";
import { Card, SectionTitle } from "@/components/ui/primitives";
import { SignOutButton } from "@/components/settings/sign-out-button";

export const dynamic = "force-dynamic";

const KIND_ICON: Record<string, typeof Github> = {
  github: Github, gitlab: GitBranch, gworkspace: Mail, m365: Users, okta: KeyRound, aws: Cloud,
};

const STATUS_CLS: Record<string, string> = {
  active: "text-pulse bg-pulse-soft",
  degraded: "text-medium bg-medium/10",
  revoked: "text-critical bg-critical/10",
};

export default async function SettingsPage() {
  const session = await getSession();
  const [tenant, connections] = await Promise.all([api.tenant(), api.connections()]);
  const orgName = tenant?.name ?? "Your organization";
  const plan = tenant?.plan || "free";

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <div>
        <h1 className="text-lg font-semibold">Settings</h1>
        <p className="text-xs text-muted">Your organization, connected systems, and how the agent reaches you.</p>
      </div>

      {/* Organization */}
      <div>
        <SectionTitle>Organization</SectionTitle>
        <Card className="space-y-3 p-5">
          <Row icon={Building2} label="Name" value={orgName} />
          <Row icon={ShieldCheck} label="Plan" value={<span className="inline-flex items-center rounded-full bg-accent-soft px-2 py-0.5 text-xs font-medium capitalize text-accent">{plan}</span>} />
          <Row icon={Lock} label="Tenant ID" value={<span className="mono text-xs text-muted">{session?.tenant ?? "—"}</span>} />
          {tenant?.created_at && (
            <Row icon={CheckCircle2} label="Member since" value={<span className="text-sm text-muted">{new Date(tenant.created_at).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" })}</span>} />
          )}
        </Card>
      </div>

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
                const Icon = KIND_ICON[c.kind] ?? Plug;
                return (
                  <li key={c.id} className="flex items-center gap-3 px-5 py-3">
                    <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg border border-border bg-surface-2 text-ink">
                      <Icon className="h-4 w-4" />
                    </span>
                    <div className="min-w-0 flex-1">
                      <div className="text-sm font-medium">{kindLabel(c.kind)}</div>
                      {c.account && <div className="mono truncate text-xs text-faint">{c.account}</div>}
                    </div>
                    <span className={`rounded-full px-2 py-0.5 text-[11px] font-medium capitalize ${STATUS_CLS[c.status] ?? "text-muted bg-surface-2"}`}>
                      {c.status}
                    </span>
                  </li>
                );
              })}
            </ul>
          )}
        </Card>
      </div>

      {/* Notifications */}
      <div>
        <SectionTitle>Notifications</SectionTitle>
        <Card className="space-y-3 p-5">
          <p className="text-xs text-muted">Where the agent reaches a human. Channels are provisioned by your administrator.</p>
          {[
            { icon: MessageSquare, name: "Slack", role: "Approve or reject fixes in-channel" },
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
