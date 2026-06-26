import Link from "next/link";
import { ArrowLeft, Target } from "lucide-react";
import { api } from "@/lib/api";
import { PageIntro } from "@/components/ui/page-intro";
import { ScopeForm } from "./scope-form";

export const dynamic = "force-dynamic";

export default async function ComplianceScopePage() {
  const scope = await api.complianceScope();
  return (
    <div className="mx-auto max-w-3xl space-y-5">
      <Link href="/compliance" className="inline-flex items-center gap-1.5 text-xs text-muted transition hover:text-ink">
        <ArrowLeft className="h-3.5 w-3.5" /> Compliance
      </Link>
      <PageIntro
        icon={Target}
        title="Compliance scope"
        description="Before we tell you where you stand, tell us what you're aiming for. A few applicability questions decide which frameworks apply, and your target frameworks focus the posture, coverage, and what-to-connect checklist on what you actually need — so we never report on the wrong thing."
      />
      <ScopeForm initial={scope} />
    </div>
  );
}
