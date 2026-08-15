import Link from "next/link";
import { ShieldAlert, AlertTriangle, Sparkles } from "lucide-react";
import type { Degradation } from "@/lib/types";
import { cn } from "@/lib/utils";

// The one place the product admits it is not fully working.
//
// This replaces two hand-written banners that each had to be remembered. That arrangement is what
// produced three shipped defects: a halted workspace whose sidebar still read "agent online", a scan
// that failed while the findings list rendered empty and silent, and a remediation that never
// delivered while its action sat at "approved". In each case the backend knew and no screen said so.
//
// The list is computed server-side, so a new reason appears here without any page knowing it exists.
// This component's only job is to render whatever it is handed — it decides nothing, which is why it
// cannot fall out of step with the state the way a hardcoded string did.
//
// Severity drives treatment, not wording: critical means we are not protecting you right now, warning
// means part of the estate is uncovered, info means a supported choice with a consequence worth
// stating. Nothing renders at all when the list is empty — a bar that is always on is the same as no
// bar, and the point is that its presence carries information.

const STYLE: Record<Degradation["severity"], { wrap: string; icon: typeof ShieldAlert }> = {
  critical: {
    wrap: "border-critical/30 bg-critical/5 text-critical hover:bg-critical/10",
    icon: ShieldAlert,
  },
  warning: {
    wrap: "border-high/30 bg-high/5 text-high hover:bg-high/10",
    icon: AlertTriangle,
  },
  info: {
    wrap: "border-accent/30 bg-accent-soft/40 text-accent hover:bg-accent-soft",
    icon: Sparkles,
  },
};

export function DegradationBar({ degradations }: { degradations: Degradation[] }) {
  if (!degradations?.length) return null;

  return (
    <div>
      {degradations.map((d) => {
        const style = STYLE[d.severity] ?? STYLE.warning;
        const Icon = style.icon;
        const body = (
          <>
            <Icon className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            <span className="min-w-0">
              <span className="font-medium">{d.title}</span>
              {/* The detail is the part that stops an empty list reading as "you are clean", so it is
                  shown here rather than hidden behind a hover or a details page. */}
              <span className="ml-1.5 font-normal opacity-90">{d.detail}</span>
              {d.action_label && <span className="ml-1.5 underline">{d.action_label}</span>}
            </span>
          </>
        );
        const cls = cn(
          "flex items-start justify-center gap-2 border-b px-6 py-2 text-xs transition",
          style.wrap,
        );
        return d.action_href ? (
          <Link key={d.kind} href={d.action_href} className={cls}>
            {body}
          </Link>
        ) : (
          <div key={d.kind} className={cls}>
            {body}
          </div>
        );
      })}
    </div>
  );
}
