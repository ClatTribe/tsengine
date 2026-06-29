import { AppWindow, ShieldAlert, BadgeCheck, Users, ScanSearch, Bot, Workflow, Plug, KeyRound } from "lucide-react";
import { api } from "@/lib/api";
import type { SaaSApp, NonHumanIdentity } from "@/lib/types";
import { SectionTitle, Empty, Tag } from "@/components/ui/primitives";
import { PageIntro } from "@/components/ui/page-intro";
import { FlagForReview } from "@/components/saas/flag-for-review";
import { cn } from "@/lib/utils";

export const dynamic = "force-dynamic";

export default async function SaaSAppsPage() {
  const [{ apps, summary }, { identities, summary: idSummary }] = await Promise.all([api.saasApps(), api.identities()]);
  // Risky-first ordering: sensitive, then unverified, then by adoption.
  const sorted = [...apps].sort((a, b) => {
    if (a.sensitive !== b.sensitive) return a.sensitive ? -1 : 1;
    if (a.verified !== b.verified) return a.verified ? 1 : -1;
    return b.count - a.count;
  });

  return (
    <div className="space-y-8">
      <PageIntro
        icon={AppWindow}
        title="Connected apps"
        description="Every third-party app your team connected to its identity providers (Google Workspace, Microsoft 365, Okta) — discovered automatically from OAuth grants. Find the unsanctioned, over-permissioned, and unverified apps before they become an incident."
      />

      <section className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Stat icon={AppWindow} label="Discovered apps" value={summary.total_apps} />
        <Stat icon={ShieldAlert} label="Sensitive access" value={summary.sensitive_apps} tone="critical" />
        <Stat icon={BadgeCheck} label="Unverified publisher" value={summary.unverified_apps} tone="medium" />
        <Stat icon={Users} label="Adopted by ≥2 users" value={summary.multi_user_apps} />
      </section>

      {/* Non-human & AI-agent identity posture (the ACSP agentic identity lens) */}
      {idSummary.total > 0 && (
        <section>
          <SectionTitle action={<span className="text-[11px] text-faint">{idSummary.total} non-human identities</span>}>
            Non-human &amp; AI-agent access
          </SectionTitle>
          <p className="mb-3 text-xs leading-relaxed text-muted">
            The AI agents, automations, and integrations holding delegated access to your data. An AI
            agent or unverified app with <span className="font-medium text-ink">write or admin</span> permission is the
            over-privileged, delegated access the agentic era introduces — surfaced here, ranked worst-first.
          </p>
          <div className="mb-3 grid grid-cols-2 gap-3 sm:grid-cols-4">
            <Stat icon={Bot} label="AI agents" value={idSummary.ai_agents} />
            <Stat icon={Workflow} label="Automations" value={idSummary.automations} />
            <Stat icon={KeyRound} label="Write / admin access" value={idSummary.write_or_admin} tone="medium" />
            <Stat icon={ShieldAlert} label="Over-privileged" value={idSummary.risky} tone="critical" />
          </div>
          <div className="card overflow-x-auto p-0">
            <table className="w-full min-w-[620px]">
              <thead>
                <tr className="border-b border-border text-left text-[11px] uppercase tracking-wide text-faint">
                  <th className="py-2.5 pl-5 pr-2 font-medium">Identity</th>
                  <th className="px-2 py-2.5 font-medium">Type</th>
                  <th className="px-2 py-2.5 font-medium">Access</th>
                  <th className="px-2 py-2.5 font-medium text-right">Risk</th>
                  <th className="py-2.5 pr-5 font-medium text-right">Action</th>
                </tr>
              </thead>
              <tbody>
                {identities.map((i) => (
                  <IdentityRow key={i.name} id={i} />
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      <section>
        <SectionTitle action={<span className="text-[11px] text-faint">{apps.length} apps</span>}>
          Discovered SaaS inventory
        </SectionTitle>
        {apps.length === 0 ? (
          <Empty>
            <div className="flex flex-col items-center gap-2 py-4 text-center">
              <ScanSearch className="h-5 w-5 text-faint" />
              No third-party apps discovered yet. Connect an identity provider (Google Workspace,
              Microsoft 365, or Okta) and we enumerate every OAuth-granted app automatically.
            </div>
          </Empty>
        ) : (
          <div className="card overflow-x-auto p-0">
            <table className="w-full min-w-[620px]">
              <thead>
                <tr className="border-b border-border text-left text-[11px] uppercase tracking-wide text-faint">
                  <th className="py-2.5 pl-5 pr-2 font-medium">App</th>
                  <th className="px-2 py-2.5 font-medium">Access</th>
                  <th className="px-2 py-2.5 font-medium">Publisher</th>
                  <th className="px-2 py-2.5 font-medium text-right">Users</th>
                  <th className="px-2 py-2.5 font-medium text-right">Scopes</th>
                  <th className="py-2.5 pr-5 font-medium text-right">Action</th>
                </tr>
              </thead>
              <tbody>
                {sorted.map((a) => (
                  <AppRow key={a.name} app={a} />
                ))}
              </tbody>
            </table>
          </div>
        )}
        <p className="mt-2 text-xs leading-relaxed text-muted">
          Discovery is grounded in real OAuth grants across your connected IdPs. &ldquo;Sensitive&rdquo;
          means the app holds an admin/directory or broad data scope. Shadow-IT (employee-connected,
          un-sanctioned) classification activates once a provider exposes admin-consent state.
        </p>
      </section>
    </div>
  );
}

function Stat({
  icon: Icon,
  label,
  value,
  tone,
}: {
  icon: typeof AppWindow;
  label: string;
  value: number;
  tone?: "critical" | "medium";
}) {
  return (
    <div className="card flex flex-col gap-1 p-4">
      <div className="flex items-center gap-1.5 text-[11px] uppercase tracking-wide text-faint">
        <Icon className="h-3.5 w-3.5" /> {label}
      </div>
      <div
        className={cn(
          "text-2xl font-semibold tabular-nums",
          tone === "critical" && value > 0 && "text-critical",
          tone === "medium" && value > 0 && "text-medium",
        )}
      >
        {value}
      </div>
    </div>
  );
}

function AppRow({ app }: { app: SaaSApp }) {
  return (
    <tr className="border-b border-border last:border-0 transition hover:bg-surface-2">
      <td className="py-2.5 pl-5 pr-2 align-middle">
        <div className="flex items-center gap-2">
          <span className="grid h-7 w-7 shrink-0 place-items-center rounded-md border border-border bg-surface-2 text-[11px] font-semibold uppercase text-muted">
            {app.name.slice(0, 2)}
          </span>
          <span className="truncate text-sm font-medium">{app.name}</span>
        </div>
      </td>
      <td className="px-2 py-2.5 align-middle">
        {app.sensitive ? (
          <span className="inline-flex items-center gap-1 rounded-md border border-critical/30 bg-critical/10 px-1.5 py-0.5 text-[11px] font-medium text-critical">
            <ShieldAlert className="h-3 w-3" /> Sensitive
          </span>
        ) : (
          <Tag>Standard</Tag>
        )}
      </td>
      <td className="px-2 py-2.5 align-middle">
        {app.verified ? (
          <span className="inline-flex items-center gap-1 text-[11px] text-pulse">
            <BadgeCheck className="h-3.5 w-3.5" /> Verified
          </span>
        ) : (
          <span className="text-[11px] text-medium">Unverified</span>
        )}
      </td>
      <td className="px-2 py-2.5 align-middle text-right text-sm tabular-nums">{app.count}</td>
      <td className="px-2 py-2.5 align-middle text-right text-xs text-muted">{app.scopes.length}</td>
      <td className="py-2.5 pr-5 align-middle text-right">
        {app.sensitive || !app.verified ? (
          <FlagForReview
            subject="saas_app"
            name={app.name}
            note={`Third-party app "${app.name}" holds ${app.sensitive ? "sensitive (admin/directory/broad-data) access" : "access"}${app.verified ? "" : " and the publisher is unverified"} across ${app.count} user${app.count === 1 ? "" : "s"}. Please advise: keep, restrict, or revoke?`}
          />
        ) : (
          <span className="text-xs text-faint">—</span>
        )}
      </td>
    </tr>
  );
}

const CLASS_META: Record<string, { icon: typeof Bot; label: string }> = {
  ai_agent: { icon: Bot, label: "AI agent" },
  automation: { icon: Workflow, label: "Automation" },
  integration: { icon: Plug, label: "Integration" },
};
const RISK_TONE: Record<string, string> = {
  high: "border-critical/30 bg-critical/10 text-critical",
  medium: "border-medium/30 bg-medium/10 text-medium",
  low: "border-border bg-surface-2 text-muted",
};

function IdentityRow({ id }: { id: NonHumanIdentity }) {
  const meta = CLASS_META[id.class] ?? CLASS_META.integration;
  const Icon = meta.icon;
  return (
    <tr className="border-b border-border last:border-0 transition hover:bg-surface-2">
      <td className="py-2.5 pl-5 pr-2 align-middle">
        <div className="flex items-center gap-2">
          <span className="truncate text-sm font-medium">{id.name}</span>
          {!id.verified && <span className="text-[11px] text-medium">unverified</span>}
        </div>
      </td>
      <td className="px-2 py-2.5 align-middle">
        <span className="inline-flex items-center gap-1 text-[11px] text-muted">
          <Icon className="h-3.5 w-3.5" /> {meta.label}
        </span>
      </td>
      <td className="px-2 py-2.5 align-middle">
        <span className="text-[11px] capitalize text-ink">{id.privilege}</span>
        {id.users > 0 && <span className="ml-1.5 text-[11px] text-faint">· {id.users} user{id.users === 1 ? "" : "s"}</span>}
      </td>
      <td className="px-2 py-2.5 align-middle text-right">
        <span
          className={cn("inline-flex items-center rounded-md border px-1.5 py-0.5 text-[11px] font-medium capitalize", RISK_TONE[id.risk] ?? RISK_TONE.low)}
          title={id.risk_reason}
        >
          {id.risk}
        </span>
      </td>
      <td className="py-2.5 pr-5 align-middle text-right">
        {id.risk === "high" || id.risk === "medium" ? (
          <FlagForReview
            subject="identity"
            name={id.name}
            note={`Non-human identity "${id.name}" (${meta.label}) holds ${id.privilege} access${id.risk_reason ? ` — ${id.risk_reason}` : ""}. Please advise: keep, restrict, or revoke?`}
          />
        ) : (
          <span className="text-xs text-faint">—</span>
        )}
      </td>
    </tr>
  );
}
