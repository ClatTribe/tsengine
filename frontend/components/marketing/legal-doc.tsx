import { ShieldAlert } from "lucide-react";

// A legal/policy section. A string is a paragraph; a string[] renders as a bullet list.
export type LegalSection = { h: string; body: (string | string[])[] };

// LegalDoc renders a policy document with a consistent header + a standing "draft for counsel
// review" notice — these are honest templates grounded in how the product actually handles data,
// not legal advice, and must be reviewed by counsel before being relied on.
export function LegalDoc({
  title,
  updated,
  intro,
  sections,
}: {
  title: string;
  updated: string;
  intro: string;
  sections: LegalSection[];
}) {
  return (
    <article className="mx-auto max-w-3xl px-5 py-16">
      <p className="text-xs font-semibold uppercase tracking-wider text-accent">Legal</p>
      <h1 className="mt-2 text-3xl font-semibold tracking-tight sm:text-4xl">{title}</h1>
      <p className="mt-2 text-sm text-faint">Last updated {updated}</p>

      <div className="mt-6 flex items-start gap-3 rounded-xl border border-border bg-surface-2/40 p-4 text-sm text-muted">
        <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-high" />
        <span>
          This is a plain-English draft, grounded in how TensorShield actually works. It is not legal
          advice and should be reviewed by your counsel before you rely on it. Sections in [brackets] need
          your company&apos;s specifics filled in.
        </span>
      </div>

      <p className="mt-8 text-[15px] leading-relaxed text-ink">{intro}</p>

      <div className="mt-8 space-y-8">
        {sections.map((s, i) => (
          <section key={s.h}>
            <h2 className="text-lg font-semibold tracking-tight text-ink">
              {i + 1}. {s.h}
            </h2>
            <div className="mt-2 space-y-3">
              {s.body.map((b, j) =>
                Array.isArray(b) ? (
                  <ul key={j} className="space-y-1.5 pl-1">
                    {b.map((li) => (
                      <li key={li} className="flex gap-2.5 text-[15px] leading-relaxed text-muted">
                        <span className="mt-2 h-1 w-1 shrink-0 rounded-full bg-accent" />
                        <span>{li}</span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p key={j} className="text-[15px] leading-relaxed text-muted">
                    {b}
                  </p>
                ),
              )}
            </div>
          </section>
        ))}
      </div>

      <p className="mt-12 border-t border-border pt-6 text-sm text-faint">
        Questions about this document? Contact <span className="text-muted">privacy@tensorshield.io</span>.
      </p>
    </article>
  );
}
