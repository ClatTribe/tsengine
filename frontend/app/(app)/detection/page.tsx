import { Radar, ShieldCheck, ShieldAlert, HelpCircle } from "lucide-react";
import { api } from "@/lib/api";
import { Empty } from "@/components/ui/primitives";
import { PageIntro } from "@/components/ui/page-intro";
import { PageTabs } from "@/components/ui/page-tabs";
import { SECURITY_TABS } from "@/lib/tabs";

export const dynamic = "force-dynamic";

export default async function DetectionPage() {
  const dv = await api.detectionValidation();

  return (
    <div className="space-y-5">
      <PageIntro
        icon={Radar}
        title="Did your defences notice?"
        description="When the pentester proved an attack works, we check whether the EDR, WAF or SIEM you already pay for saw it. Proving a vulnerability is exploitable and proving your controls would catch it are different questions, and only the second one tells you whether an attacker would get caught."
      />

      <PageTabs tabs={SECURITY_TABS} />

      {dv.results.length === 0 ? (
        <Empty>
          Nothing to validate yet — this compares probes the pentester fired against events your
          runtime sensor reported, so it needs an engagement that has run and a sensor posting to
          /v1/runtime/events.
        </Empty>
      ) : (
        <>
          <div className="flex flex-wrap gap-4 text-sm">
            <span className="text-muted">
              <span className="font-medium text-ink">{dv.detected}</span> detected
              {dv.blocked > 0 && (
                <span className="text-subtle"> ({dv.blocked} blocked, the rest observed only)</span>
              )}
            </span>
            <span className="text-muted">
              <span className="font-medium text-high">{dv.not_detected}</span> missed
              {dv.missed_proven > 0 && (
                <span className="text-high"> ({dv.missed_proven} of them proved a real vulnerability)</span>
              )}
            </span>
            <span className="text-muted">
              <span className="font-medium text-medium">{dv.undetermined}</span> undetermined
            </span>
          </div>

          {/* The caveat is rendered verbatim and next to the counts, not in a footnote. It is what
              separates the "missed" number from the "undetermined" one, and a reader who sees the
              counts without it will read undetermined as a softer miss. */}
          <p className="text-xs text-subtle">{dv.caveat}</p>

          <div className="space-y-2">
            {dv.results.map((r) => (
              <div key={r.canary} className="card flex items-start gap-3 px-4 py-3 text-sm">
                {r.verdict === "detected" && <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-pulse" />}
                {r.verdict === "not_detected" && <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-high" />}
                {r.verdict === "undetermined" && <HelpCircle className="mt-0.5 h-4 w-4 shrink-0 text-medium" />}
                <div className="min-w-0">
                  <div className="text-ink">
                    {r.verdict === "detected" && (
                      <>
                        Your controls {r.blocked ? "BLOCKED" : "saw but did not stop"} this probe
                        {r.strength === "correlated" && (
                          <span className="text-muted"> (matched by inference, not by our token)</span>
                        )}
                      </>
                    )}
                    {r.verdict === "not_detected" && (
                      <>
                        Your controls did not report this probe
                        {r.proven && (
                          <span className="text-high"> — and this one proved a real vulnerability</span>
                        )}
                      </>
                    )}
                    {r.verdict === "undetermined" && <>We cannot tell whether this was detected</>}
                  </div>
                  <div className="mt-0.5 truncate font-mono text-xs text-subtle">{r.target}</div>
                  {r.why && <div className="mt-1 text-xs text-muted">{r.why}</div>}
                </div>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
