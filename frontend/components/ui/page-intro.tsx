import type { LucideIcon } from "lucide-react";

// PageIntro is the standard after-login page header: an icon chip, a title, and a
// PLAIN-ENGLISH, benefit-first one-liner — what the page is for and why it matters, not
// the mechanism. (Aikido-style clarity: lead with the outcome, drop the jargon.) An
// optional right-aligned slot holds a headline stat or an action.
export function PageIntro({
  icon: Icon,
  title,
  description,
  right,
}: {
  icon?: LucideIcon;
  title: string;
  description: React.ReactNode;
  right?: React.ReactNode;
}) {
  return (
    <div className="flex items-start justify-between gap-4">
      <div className="flex items-start gap-3">
        {Icon && (
          <span className="mt-0.5 grid h-9 w-9 shrink-0 place-items-center rounded-xl bg-accent-soft text-accent">
            <Icon className="h-4 w-4" />
          </span>
        )}
        <div className="min-w-0">
          <h1 className="text-lg font-semibold leading-tight">{title}</h1>
          <p className="mt-1 max-w-2xl text-sm text-muted">{description}</p>
        </div>
      </div>
      {right && <div className="shrink-0 text-right">{right}</div>}
    </div>
  );
}
