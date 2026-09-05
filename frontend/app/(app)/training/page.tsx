import Link from "next/link";
import { GraduationCap, Users } from "lucide-react";
import { api } from "@/lib/api";
import { Empty } from "@/components/ui/primitives";
import { PageIntro } from "@/components/ui/page-intro";
import { PageTabs } from "@/components/ui/page-tabs";
import { COMPLIANCE_TABS } from "@/lib/tabs";
import { ModuleReader } from "@/components/training/module-reader";
import { RecordExternal } from "@/components/training/record-external";
import type { TrainingStatus } from "@/lib/types";

export const dynamic = "force-dynamic";

// Security-awareness training — SOC 2 CC1.4/CC2.2, ISO A.6.3, PCI 12.6, HIPAA 164.308(a)(5).
//
// THE PAGE LEADS WITH THE READER'S OWN MODULES. Most people who open this are not administering a
// programme; they were asked to do their training. A roster table with their name somewhere in it is
// the version of this screen that nobody finishes.
//
// FOUR THINGS THIS PAGE MUST NOT DO, and the field that stops each:
//
//   1. Never publish a single completion percentage. `summary` carries delivered and attested counts
//      separately and no combined rate exists to render — one figure over both would rise as a
//      customer asserted more and evidenced less.
//   2. Never let an empty roster read as a trained workforce. `no_roster` says there is no
//      denominator, and `detail` says it in words.
//   3. Never hide a record that counts towards nothing. `off_roster` names people with training on
//      file who are not on the roster — otherwise whoever entered it watches the summary not move.
//   4. Never show the two tiers as the same tick. The chip on each module says which one it is.
export default async function TrainingPage() {
  const data = await api.training();
  const s = data.summary;
  const me = data.me ?? "";

  const mine = new Map<string, TrainingStatus>();
  const others: TrainingStatus[] = [];
  for (const st of data.statuses) {
    if (me && st.subject === me) mine.set(st.module_id, st);
    else others.push(st);
  }

  const byPerson = new Map<string, TrainingStatus[]>();
  for (const st of others) byPerson.set(st.subject, [...(byPerson.get(st.subject) ?? []), st]);

  return (
    <div className="space-y-6">
      <PageTabs tabs={COMPLIANCE_TABS} />
      <PageIntro
        icon={GraduationCap}
        title="Security training"
        description="The training every framework asks for and no scanner can answer: were the people who work here taught how attacks actually reach them. Five short modules, read in the browser, recorded under your name — or recorded as completed elsewhere, which is counted separately because it is weaker evidence."
      />

      <div className="card flex flex-wrap items-center gap-x-6 gap-y-3 px-5 py-4">
        <Stat n={s.people} label="On the roster" />
        <Stat n={s.complete_delivered} label="Read here" cls="text-pulse" />
        <Stat n={s.complete_attested} label="Recorded from elsewhere" />
        <Stat n={s.expired} label="Due again" cls="text-high" />
        <Stat n={s.outstanding} label="Not started" cls="text-accent" />
        {(s.roster_sources?.length ?? 0) > 0 && (
          <div className="ml-auto flex items-center gap-1.5 text-xs text-muted">
            <Users className="h-3.5 w-3.5" />
            roster from {s.roster_sources!.map(sourceLabel).join(" + ")}
          </div>
        )}
      </div>

      {/* The server's own sentence about what those numbers mean. It carries the refusal that an
          empty programme is not a finished one, and names any record that counts towards nothing. */}
      <p className="text-sm text-muted">{s.detail}</p>

      {/* No combined completion rate is rendered anywhere on this page, deliberately: "we showed
          them the content" and "somebody says it happened elsewhere" are different evidence, and one
          percentage over both climbs as a customer evidences less. */}

      {s.no_roster && (
        <Empty>
          Nobody is on the roster yet. Connect an HRIS under{" "}
          <Link href="/settings" className="text-accent hover:underline">
            Settings
          </Link>{" "}
          or invite your team, and everyone who works here appears with what they still owe.
        </Empty>
      )}

      {(s.off_roster?.length ?? 0) > 0 && (
        <div className="rounded-2xl border border-high/30 bg-high/5 px-5 py-4">
          <p className="text-sm text-ink">
            {s.off_roster!.length} training {s.off_roster!.length === 1 ? "record" : "records"} not on the roster
          </p>
          <p className="mt-1 text-sm text-muted">
            {s.off_roster!.join(", ")} {s.off_roster!.length === 1 ? "has" : "have"} training on file but{" "}
            {s.off_roster!.length === 1 ? "is" : "are"} not on your roster, so it counts towards nothing here.
            Check the address, or connect the system that knows they work here.
          </p>
        </div>
      )}

      {me && (
        <section className="space-y-3">
          <h2 className="text-xs font-medium uppercase tracking-wider text-muted">Your training</h2>
          {data.curriculum.modules.map((m) => (
            <ModuleReader key={m.id} m={m} status={mine.get(m.id)} />
          ))}
        </section>
      )}

      <section className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h2 className="text-xs font-medium uppercase tracking-wider text-muted">Everyone else</h2>
          <RecordExternal modules={data.curriculum.modules} />
        </div>
        {byPerson.size === 0 ? (
          <p className="text-sm text-muted">Nobody else is on the roster yet.</p>
        ) : (
          <ul className="space-y-2">
            {[...byPerson.entries()].map(([subject, sts]) => (
              <PersonRow key={subject} subject={subject} sts={sts} />
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}

function PersonRow({ subject, sts }: { subject: string; sts: TrainingStatus[] }) {
  const done = sts.filter((s) => s.state === "complete");
  const delivered = done.filter((s) => s.tier !== "attested_external").length;
  const attested = done.length - delivered;
  const expired = sts.filter((s) => s.state === "expired").length;
  const name = sts.find((s) => s.name)?.name;

  return (
    <li className="card flex flex-wrap items-center gap-x-4 gap-y-2 px-5 py-3">
      <div className="min-w-0 flex-1">
        <div className="truncate font-medium text-ink">{name || subject}</div>
        {name && <div className="truncate text-xs text-faint">{subject}</div>}
      </div>
      {/* Per person, the tiers stay apart for the same reason they do in the totals. */}
      <span className="text-xs text-muted">
        <span className="text-pulse">{delivered}</span> read here
        {attested > 0 && (
          <>
            {" · "}
            {attested} from elsewhere
          </>
        )}
        {expired > 0 && (
          <>
            {" · "}
            <span className="text-high">{expired} due again</span>
          </>
        )}
        {" · "}
        {sts.length - done.length - expired} not started
      </span>
    </li>
  );
}

function sourceLabel(s: string): string {
  // Named rather than counted: an HRIS roster and "people who have logged into this product" are
  // very different claims about who works at a company.
  if (s === "hris") return "your HRIS";
  if (s === "workspace_users") return "this workspace's users";
  return s;
}

function Stat({ n, label, cls = "text-ink" }: { n: number; label: string; cls?: string }) {
  return (
    <div>
      <div className={`text-xl font-semibold ${cls}`}>{n}</div>
      <div className="text-[11px] uppercase tracking-wide text-muted">{label}</div>
    </div>
  );
}
