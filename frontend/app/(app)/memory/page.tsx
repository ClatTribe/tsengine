import Link from "next/link";
import { api } from "@/lib/api";
import { Card, SectionTitle } from "@/components/ui/primitives";
import { PageIntro } from "@/components/ui/page-intro";
import type { AgentMemoryLine } from "@/lib/types";
import { AddNote, RemoveNote } from "./notes";

export const dynamic = "force-dynamic";

// What the AI engineer is told about this workspace — the SAME list the prompt receives, so what you read
// here is what it reads. Every fact except your notes is corrected where it lives; the link says where.

const SECTIONS: { kind: AgentMemoryLine["kind"]; title: string; href?: string; fix?: string }[] = [
  { kind: "note", title: "Your notes" },
  { kind: "owner", title: "Who owns what", href: "/assets", fix: "Set owners on Assets" },
  { kind: "out_of_scope", title: "Out of scope", href: "/products", fix: "Change scope on Products" },
  { kind: "decision", title: "Risk decisions in force", href: "/issues", fix: "Manage on Issues" },
  { kind: "declined_fix", title: "Fixes you rejected or sent back", href: "/inbox", fix: "See the approvals" },
  { kind: "explain", title: "Where our evidence did not convince you", href: "/issues", fix: "Answer on Issues" },
];

export default async function MemoryPage() {
  const mem = await api.agentMemory();
  const lines = mem.lines ?? [];
  return (
    <div className="space-y-5">
      <PageIntro
        title="What the AI engineer knows"
        description="Everything below is given to the AI engineer on every run. It is context, not evidence: it shapes who work is routed to, what is in scope, which fixes it avoids re-proposing and how it explains — it never proves a finding and never hides one."
      />
      <Card className="space-y-3 p-5">
        <SectionTitle>Tell it something</SectionTitle>
        <AddNote />
      </Card>
      {SECTIONS.map((s) => {
        const ls = lines.filter((l) => l.kind === s.kind);
        const omitted = mem.omitted?.[s.kind] ?? 0;
        return (
          <Card key={s.kind} className="space-y-2 p-5">
            <SectionTitle action={s.href ? <Link href={s.href} className="text-[11px] text-accent hover:underline">{s.fix}</Link> : undefined}>
              {s.title}
            </SectionTitle>
            {ls.length === 0 ? (
              <p className="text-xs text-faint">Nothing yet.</p>
            ) : (
              <ul className="space-y-1.5">
                {ls.map((l, i) => (
                  <li key={(l.note_id ?? "") + i} className="flex items-start gap-2 text-xs text-ink">
                    <span className="flex-1">
                      {l.text}
                      {l.by && <span className="text-faint"> · {l.by}</span>}
                    </span>
                    {l.note_id && <RemoveNote id={l.note_id} />}
                  </li>
                ))}
              </ul>
            )}
            {omitted > 0 && (
              <p className="text-[11px] text-faint">
                {omitted} more not given to the AI engineer — the list is capped so it never crowds out the findings.
              </p>
            )}
          </Card>
        );
      })}
    </div>
  );
}
