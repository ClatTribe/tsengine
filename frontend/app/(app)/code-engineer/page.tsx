import Link from "next/link";
import { Code2, ArrowRight } from "lucide-react";
import { PageIntro } from "@/components/ui/page-intro";
import { RunCodeInvestigation } from "@/components/code/run-code-investigation";

export const dynamic = "force-dynamic";

// The AI Code Security Engineer (codeagent) surface — the code twin of /cloud-engineer. It reasons over the
// repository SOURCE: opening files, tracing a tainted value to its sink, measuring a leaked secret's blast
// radius, and finding the right-layer fix — the depth the whole-estate Lead can't reach from a finding
// digest. Every verdict is grounded in source the agent actually read (§10). When a repo is connected, the
// AI Security Engineer delegates to this specialist automatically during triage (the investigate_code tool).
export default function CodeEngineerPage() {
  return (
    <div className="space-y-8">
      <PageIntro
        icon={Code2}
        title="Code depth"
        description="The source-code specialist your AI Security Engineer delegates to for depth. A scanner tells you a rule fired at a file:line; this specialist opens the actual code, traces whether the tainted value really reaches the sink, measures a leaked secret's blast radius, and tells you which layer the fix belongs in. It separates genuinely exploitable findings from scanner noise — and every verdict is grounded in source it read, nothing invented. Confirmed-exploitable findings flow into your issues and compliance posture."
      />
      <Link href="/brief" className="-mt-4 inline-flex items-center gap-1.5 text-xs font-medium text-accent hover:underline">
        <ArrowRight className="h-3.5 w-3.5 rotate-180" /> Back to the AI Security Engineer
      </Link>

      <RunCodeInvestigation />
    </div>
  );
}
