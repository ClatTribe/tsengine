import Link from "next/link";
import { Stamp, ShieldCheck, AlertTriangle, Microscope } from "lucide-react";
import { api } from "@/lib/api";
import { SeverityBadge, Empty } from "@/components/ui/primitives";
import { PageIntro } from "@/components/ui/page-intro";
import { PageTabs } from "@/components/ui/page-tabs";
import { COMPLIANCE_TABS } from "@/lib/tabs";
import { DecideFinding } from "@/components/audit-signoff/decide-finding";
import { IssueCertificate } from "@/components/audit-signoff/issue-certificate";
import type { AuditItem } from "@/lib/types";

export const dynamic = "force-dynamic";

// The reviewer's desk: the step between a scan and a signed certificate.
//
// THE ORDERING IS THE PRODUCT. Undecided findings lead, and within those the ones the engine could
// NOT prove come first — because those are where the reviewer's judgement is actually load-bearing.
// A page that listed findings by severity would spread an hour evenly over twelve of them; this puts
// it on the four that need it.
//
// FOUR THINGS THIS PAGE MUST NOT DO:
//   1. Never let an empty review read as a clean audit — `progress.detail` says so in the server's
//      own words, and an empty scope is a certificate blocker, not a pass.
//   2. Never hide why a certificate cannot be issued. `blockers` rides on the read, so the reviewer
//      sees the obstacles while working rather than at the button.
//   3. Never show a proven finding and a pattern-match alike. The evidence rung is what the reviewer
//      is being asked to stand behind.
//   4. Never offer a bulk approve. The one decision that cannot be automated must not become a click.
export default async function AuditSignoffPage({
  searchParams,
}: {
  searchParams: Promise<{ target?: string }>;
}) {
  const { target } = await searchParams;
  const assets = await api.assets();
  const webTargets = assets.filter((a) => a.type === "web_application" || a.type === "api");
  const active = target || webTargets[0]?.target || "";

  if (!active) {
    return (
      <div className="space-y-6">
        <PageTabs tabs={COMPLIANCE_TABS} />
        <PageIntro icon={Stamp} title="Audit sign-off" description={INTRO} />
        <Empty>
          No web application or API is being monitored yet. Add one under{" "}
          <Link href="/assets" className="text-accent hover:underline">
            Connections
          </Link>{" "}
          and scan it — a certificate can only be issued over findings that actually exist.
        </Empty>
      </div>
    );
  }

  const review = await api.auditReview(active);
  const p = review.progress;
  const pending = review.items.filter((i) => !i.verdict);
  const decided = review.items.filter((i) => i.verdict);

  return (
    <div className="space-y-6">
      <PageTabs tabs={COMPLIANCE_TABS} />
      <PageIntro icon={Stamp} title="Audit sign-off" description={INTRO} />

      {webTargets.length > 1 && (
        <div className="flex flex-wrap gap-2">
          {webTargets.map((a) => (
            <Link
              key={a.id}
              href={`/audit-signoff?target=${encodeURIComponent(a.target)}`}
              className={`rounded-lg border px-2.5 py-1 text-xs transition ${
                a.target === active ? "border-accent/40 text-accent" : "border-border text-muted hover:text-ink"
              }`}
            >
              {a.target}
            </Link>
          ))}
        </div>
      )}

      <div className="card flex flex-wrap items-center gap-x-6 gap-y-3 px-5 py-4">
        <Stat n={p.total} label="In scope" />
        <Stat n={p.pending} label="Awaiting a decision" cls="text-accent" />
        <Stat n={p.included} label="In the report" />
        <Stat n={p.excluded} label="Excluded" />
        <div className="ml-auto flex items-center gap-2 text-sm">
          {p.complete ? (
            <>
              <ShieldCheck className="h-4 w-4 text-pulse" />
              <span className="text-ink">Every finding answered</span>
            </>
          ) : (
            <>
              <AlertTriangle className="h-4 w-4 text-muted" />
              <span className="text-muted">Not signable yet</span>
            </>
          )}
        </div>
      </div>

      {/* The server's own sentence. It is what keeps an empty review from reading as a clean audit. */}
      <p className="text-sm text-muted">{p.detail}</p>

      {/* WHERE THE REVIEWER'S TIME SHOULD GO — the reason this surface exists rather than a list. */}
      {p.total > 0 && (
        <div className="rounded-2xl border border-border bg-surface-2 px-5 py-4">
          <div className="flex items-center gap-2 text-sm font-medium text-ink">
            <Microscope className="h-4 w-4 text-accent" />
            {p.load.proven} proven · {p.load.unproven} on a pattern match
          </div>
          <p className="mt-1 text-sm text-muted">{p.load.detail}</p>
        </div>
      )}

      <IssueCertificate target={active} blockers={review.blockers ?? []} complete={p.complete} />

      {pending.length > 0 && (
        <section className="space-y-2">
          <h2 className="text-xs font-medium uppercase tracking-wider text-muted">Awaiting your decision</h2>
          <ul className="space-y-2">
            {pending.map((i) => (
              <Row key={i.key} target={active} i={i} />
            ))}
          </ul>
        </section>
      )}

      {decided.length > 0 && (
        <section className="space-y-2">
          <h2 className="text-xs font-medium uppercase tracking-wider text-muted">Decided</h2>
          <ul className="space-y-2">
            {decided.map((i) => (
              <Row key={i.key} target={active} i={i} />
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}

const INTRO =
  "The step between a scan and a signed certificate: every finding gets a keep, exclude or reclassify decision from a named reviewer, and the certificate cannot be issued until they all do. Findings the engine could not prove are listed first — that is where your judgement is actually needed.";

function Row({ target, i }: { target: string; i: AuditItem }) {
  return (
    <li className="card space-y-2 px-5 py-4">
      <div className="flex flex-wrap items-start gap-3">
        <SeverityBadge severity={i.effective_severity} />
        <div className="min-w-0 flex-1">
          <div className="font-medium text-ink">{i.title}</div>
          <div className="mt-0.5 truncate text-xs text-faint">{i.endpoint}</div>
          <div className="mt-1 flex flex-wrap items-center gap-2 text-[11px]">
            {/* The evidence rung, because that is what the reviewer is being asked to stand behind —
                a proven finding is a glance, a pattern match is their name on the scanner's word. */}
            {i.proven ? (
              <span className="rounded-full border border-pulse/40 px-2 py-0.5 text-pulse">
                proven · {i.rung}
              </span>
            ) : (
              <span className="rounded-full border border-border px-2 py-0.5 text-muted">
                {i.rung || "scanner_reported"} — not proven by a predicate
              </span>
            )}
            {i.lowered && (
              <span className="rounded-full border border-high/40 px-2 py-0.5 text-high">
                severity lowered by a reviewer
              </span>
            )}
          </div>
          {i.verdict && (
            <p className="mt-2 text-xs text-faint">
              {label(i.verdict)} by <span className="text-muted">{i.by || "—"}</span>
              {i.at ? ` · ${new Date(i.at).toLocaleDateString()}` : ""}
              {i.reason ? ` · "${i.reason}"` : ""}
            </p>
          )}
        </div>
      </div>
      <DecideFinding target={target} item={i} />
    </li>
  );
}

function label(v: string): string {
  if (v === "include") return "Included";
  if (v === "exclude") return "Excluded";
  return "Reclassified";
}

function Stat({ n, label, cls = "text-ink" }: { n: number; label: string; cls?: string }) {
  return (
    <div>
      <div className={`text-xl font-semibold ${cls}`}>{n}</div>
      <div className="text-[11px] uppercase tracking-wide text-muted">{label}</div>
    </div>
  );
}
