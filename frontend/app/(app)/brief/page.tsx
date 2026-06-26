import { FileText } from "lucide-react";
import { PageIntro } from "@/components/ui/page-intro";
import { GenerateBrief } from "@/components/brief/generate-brief";

export const dynamic = "force-dynamic";

// The plain-English security brief — the L2 Lead/translator turns the raw findings into the deliverable
// a founder / non-security team can actually act on (exec summary, what to do next, prioritized issues).
export default function BriefPage() {
  return (
    <div className="space-y-8">
      <PageIntro
        icon={FileText}
        title="Plain-English brief"
        description="Your findings, translated by the AI security engineer into a report a non-security team can act on — an executive summary, the prioritized issues that actually matter, and what to do next. The same grounded findings, explained in plain English. Whoever owns the judgment (your team, your MSP's expert, or our hired expert) reviews it and signs off."
      />
      <GenerateBrief />
    </div>
  );
}
