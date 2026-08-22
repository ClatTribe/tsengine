import { ShieldCheck, XCircle, CheckCircle2 } from "lucide-react";

// THE OBJECTION, ANSWERED WHERE IT LANDS.
//
// This sits immediately after <TwoAgents /> because that is the moment the visitor learns the product
// is two AI agents — and the very next thought a security-literate buyer has is "agents make things up".
// They are right to think it. An AI security tool that invents one critical finding and hands it to a
// regulated customer is finished, and no amount of "advanced AI" copy fixes that.
//
// So we answer it with the ARCHITECTURE rather than a reassurance: the model proposes, a deterministic
// check disposes, and the check runs OUTSIDE the model. That is literally how the engine is built
// (CLAUDE.md §10 grounding) — record_finding is refused unless a deterministic indicator fired, and
// record_issue is refused unless the path exists in the graph. This section is honest because the
// product would fail its own tests otherwise, not because marketing says so.
export function VerificationPromise() {
  return (
    <section className="border-y border-border bg-surface">
      <div className="mx-auto max-w-6xl px-6 py-16 sm:py-20">
        <div className="grid items-start gap-10 lg:grid-cols-[1.05fr_.95fr]">
          <div>
            <div className="inline-flex items-center gap-2 rounded-full border border-border bg-bg px-3 py-1 text-xs font-medium text-muted">
              <ShieldCheck className="h-3.5 w-3.5 text-accent" /> The rule we do not break
            </div>
            <h2 className="mt-5 text-3xl font-semibold leading-tight tracking-tight sm:text-4xl">
              If we can&apos;t reproduce it,{" "}
              <span className="text-accent">we don&apos;t show it to you.</span>
            </h2>
            <p className="mt-5 max-w-xl text-lg leading-relaxed text-muted">
              The AI suggests what to try. Something separate — a plain, ordinary test that the AI has no say
              over — actually tries it and checks whether it worked. Nothing reaches you unless that test came
              back with proof.
            </p>
            <p className="mt-4 max-w-xl text-sm leading-relaxed text-faint">
              AI makes things up. One invented critical finding, sent to a customer in a regulated industry,
              ends a company. We built for that failure first, which is why the checking step is a separate
              thing the AI cannot argue its way past.
            </p>
          </div>

          {/* The propose/dispose split, shown rather than asserted. */}
          <div className="card p-5 sm:p-6">
            <div className="text-[11px] font-medium uppercase tracking-wider text-faint">How a finding is admitted</div>

            <div className="mt-4 space-y-3">
              <Row
                tone="muted"
                title="The AI has an idea"
                body="“This login endpoint looks injectable — try this payload.”"
              />
              <div className="pl-4 text-xs text-faint">↓ the AI’s job ends here</div>
              <Row
                tone="accent"
                title="A separate test decides"
                body="Actually sends the request and looks for one specific thing that can only happen if the attack worked — a database error, a redirect to an attacker’s site, code that really ran in a browser."
              />
            </div>

            <div className="mt-5 grid gap-2 border-t border-border pt-4 text-sm">
              <div className="flex items-start gap-2">
                <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-pulse" />
                <span className="text-muted">
                  It worked → <span className="font-medium text-ink">you see it, with the proof attached</span>
                </span>
              </div>
              <div className="flex items-start gap-2">
                <XCircle className="mt-0.5 h-4 w-4 shrink-0 text-faint" />
                <span className="text-muted">
                  Nothing happened → <span className="font-medium text-ink">thrown away</span>, however sure the AI
                  was
                </span>
              </div>
            </div>

            <p className="mt-4 text-xs leading-relaxed text-faint">
              The same rule applies on the defensive side: we only report a route into your systems if it really
              exists in your setup, and really ends somewhere that matters.
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}

function Row({ tone, title, body }: { tone: "muted" | "accent"; title: string; body: string }) {
  const accent = tone === "accent";
  return (
    <div
      className={
        "rounded-xl border p-3.5 " +
        (accent ? "border-accent/30 bg-accent-soft" : "border-border bg-bg")
      }
    >
      <div className={"text-sm font-medium " + (accent ? "text-accent" : "text-ink")}>{title}</div>
      <div className="mt-1 text-[13px] leading-relaxed text-muted">{body}</div>
    </div>
  );
}
