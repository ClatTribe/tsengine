import Link from "next/link";
import { Rocket, UserCheck, Building2, ArrowRight } from "lucide-react";

// EngageModels — the two-sided GTM made plain: the engine does the work; what differs is WHO handles
// the human-in-the-loop judgment. Run it yourself, have us run it (a named expert on your behalf), or
// deliver it to your own clients as an MSP/consultancy. Same product, three ways to buy.
const MODELS = [
  {
    icon: Rocket,
    tag: "Self-serve",
    title: "Run it yourself",
    body: "Connect your stack and the agent finds, fixes, and proves your security. Your team approves anything that matters — no security hire needed.",
    cta: "Start free",
    href: "/signup",
    highlight: false,
  },
  {
    icon: UserCheck,
    tag: "Done for you",
    title: "We run it for you",
    body: "No security team? We provide the named expert — a vCISO, an auditor liaison, a pentester — who handles the judgment calls on your behalf, every decision signed and accountable.",
    cta: "See managed",
    href: "/managed",
    highlight: true,
  },
  {
    icon: Building2,
    tag: "For MSPs & consultancies",
    title: "Deliver it to your clients",
    body: "Run security & compliance for your whole book of clients on TensorShield. Your experts handle the human-in-the-loop from one console — far more clients, far less cost.",
    cta: "Become a partner",
    href: "/demo",
    highlight: false,
  },
];

export function EngageModels() {
  return (
    <section className="mx-auto max-w-6xl px-5 py-20">
      <div className="mx-auto mb-12 max-w-2xl text-center">
        <span className="text-xs font-semibold uppercase tracking-wider text-accent">Two ways to get it handled</span>
        <h2 className="mt-3 text-3xl font-semibold tracking-tight">Bring your own expert, or use ours.</h2>
        <p className="mt-3 text-base leading-relaxed text-muted">
          The AI does the heavy lifting either way. The only question is who makes the judgment calls a machine
          shouldn&apos;t — your team, our experts, or your consultancy&apos;s.
        </p>
      </div>
      <div className="grid gap-4 lg:grid-cols-3">
        {MODELS.map(({ icon: Icon, tag, title, body, cta, href, highlight }) => (
          <div
            key={title}
            className={
              highlight
                ? "relative flex flex-col rounded-2xl border-2 border-accent bg-accent-soft/20 p-6 shadow-elevated"
                : "relative flex flex-col rounded-2xl border border-border bg-surface p-6 shadow-card"
            }
          >
            <span className="grid h-10 w-10 place-items-center rounded-xl bg-accent-soft text-accent">
              <Icon className="h-5 w-5" />
            </span>
            <div className="mt-4 text-[11px] font-semibold uppercase tracking-wide text-accent">{tag}</div>
            <h3 className="mt-1 text-lg font-semibold">{title}</h3>
            <p className="mt-2 flex-1 text-sm leading-relaxed text-muted">{body}</p>
            <Link
              href={href}
              className={
                highlight
                  ? "mt-5 inline-flex items-center justify-center gap-2 rounded-xl bg-accent px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-accent-hover"
                  : "mt-5 inline-flex items-center justify-center gap-2 rounded-xl border border-border px-4 py-2.5 text-sm font-semibold text-ink transition hover:border-accent/40 hover:text-accent"
              }
            >
              {cta} <ArrowRight className="h-4 w-4" />
            </Link>
          </div>
        ))}
      </div>
    </section>
  );
}
