import Link from "next/link";
import { Github, GitBranch, Mail, KeyRound, Users, Plug, ScanLine, CheckCircle2, ShieldCheck, ArrowRight, Cloud } from "lucide-react";
import { CONNECTORS, CATEGORY_LABEL, type ConnectorCategory } from "@/lib/connectors";

const KIND_ICON: Record<string, typeof Github> = {
  github: Github,
  gitlab: GitBranch,
  bitbucket: GitBranch,
  azuredevops: GitBranch,
  gworkspace: Mail,
  m365: Users,
  okta: KeyRound,
  aws: Cloud,
  gcp: Cloud,
  azure: Cloud,
};

const STEPS = [
  { Icon: Plug, title: "Connect a system", body: "GitHub, Google Workspace, Okta — one click of OAuth." },
  { Icon: ScanLine, title: "The agent scans", body: "It discovers your assets and scans them continuously." },
  { Icon: CheckCircle2, title: "Review & approve", body: "It prepares fixes and holds the risky ones for your call." },
];

// The cold-start surface: shown on the Overview when a tenant has no connections yet.
// A self-serve SMB product lives or dies on this first run — so instead of an empty
// dashboard, lead the user straight into connecting their first system.
export function FirstRun() {
  return (
    <div className="mx-auto max-w-3xl space-y-8 py-6">
      <div className="text-center">
        <div className="mx-auto mb-4 grid h-14 w-14 place-items-center rounded-2xl border border-accent/40 bg-accent-soft text-accent">
          <ShieldCheck className="h-7 w-7" />
        </div>
        <h1 className="text-2xl font-semibold">Your security team is ready</h1>
        <p className="mx-auto mt-2 max-w-md text-sm text-muted">
          Connect your first system and the agent starts working — scanning, triaging, and
          preparing fixes for your approval. No security expertise required.
        </p>
      </div>

      {/* How it works */}
      <div className="grid gap-3 sm:grid-cols-3">
        {STEPS.map(({ Icon, title, body }, i) => (
          <div key={title} className="card p-4">
            <div className="mb-2 flex items-center gap-2">
              <span className="grid h-7 w-7 place-items-center rounded-lg border border-border bg-surface-2 text-accent">
                <Icon className="h-3.5 w-3.5" />
              </span>
              <span className="text-[11px] font-medium text-faint">STEP {i + 1}</span>
            </div>
            <div className="text-sm font-medium">{title}</div>
            <div className="mt-0.5 text-xs leading-relaxed text-muted">{body}</div>
          </div>
        ))}
      </div>

      {/* Quick connect */}
      <div className="space-y-5">
        {(["code", "identity"] as ConnectorCategory[]).map((cat) => (
          <div key={cat}>
            <div className="mb-2 text-[11px] uppercase tracking-wider text-faint">{CATEGORY_LABEL[cat]}</div>
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {CONNECTORS.filter((c) => c.category === cat).map((c) => {
                const Icon = KIND_ICON[c.kind] ?? Plug;
                return (
                  <a
                    key={c.kind}
                    href={`/connect/${c.kind}`}
                    className="group card flex flex-col gap-2 p-4 transition hover:border-accent/40 hover:bg-surface-2"
                  >
                    <div className="flex items-center gap-2.5">
                      <span className="grid h-8 w-8 place-items-center rounded-lg border border-border bg-surface-2 text-ink">
                        <Icon className="h-4 w-4" />
                      </span>
                      <span className="flex-1 text-sm font-medium">{c.label}</span>
                      <ArrowRight className="h-4 w-4 text-faint transition group-hover:translate-x-0.5 group-hover:text-accent" />
                    </div>
                    <p className="text-xs leading-relaxed text-muted">{c.monitors}</p>
                  </a>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      <div className="text-center">
        <Link href="/assets" className="text-xs text-accent transition hover:underline">
          See all connection options →
        </Link>
      </div>
    </div>
  );
}
