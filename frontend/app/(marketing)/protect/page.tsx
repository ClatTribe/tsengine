import Link from "next/link";
import { pageMeta } from "@/lib/seo";
import { AuroraBackdrop } from "@/components/marketing/aurora";
import { Shield, ShieldCheck, Eye, Activity, Layers, ArrowRight } from "lucide-react";

export const metadata = pageMeta({
  title: "Runtime protection — TensorShield",
  description:
    "Block attacks in production, then see exactly what was stopped — folded into the same findings, incidents, and evidence as the rest of your security. Built on the open-source Zen in-app firewall.",
  path: "/protect",
});

const POINTS = [
  { icon: Shield, t: "Block at the sink, in your app", d: "An in-app firewall (the open-source Zen sensor) sits inside your application and stops SQLi, SSRF, path traversal and command injection at the dangerous call — before it reaches a database or a sensitive action." },
  { icon: Activity, t: "Real exploitation, not theory", d: "A blocked attack is the strongest exploitability signal there is. When the runtime blocks an attempt on an endpoint, the matching finding is flagged 'under active attack' and an incident opens — automatically." },
  { icon: Eye, t: "Monitor first, block when ready", d: "Run in monitor mode to see what would be blocked with zero risk to traffic, then flip to blocking when you're confident. The posture view tells you, honestly, which mode each app is in." },
  { icon: Layers, t: "One platform, not a separate console", d: "Runtime blocks land in the same issues, incidents, and signed evidence as your code, cloud, and identity findings — so production attacks and the vulnerabilities behind them sit side by side." },
];

export default function Protect() {
  return (
    <>
      <section className="relative overflow-hidden">
        <AuroraBackdrop />
        <div className="relative animate-fade-rise mx-auto max-w-3xl px-5 pb-10 pt-20 text-center">
          <span className="inline-flex items-center gap-1.5 rounded-full border border-border bg-surface px-3 py-1 text-xs font-medium text-muted shadow-sm">
            <Shield className="h-3.5 w-3.5 text-accent" /> Runtime protection
          </span>
          <h1 className="mt-6 text-4xl font-semibold tracking-tight sm:text-5xl">
            Stop the attack, then close the hole behind it.
          </h1>
          <p className="mx-auto mt-4 max-w-xl text-lg leading-relaxed text-muted">
            Scanning finds the vulnerability; runtime protection stops it being exploited while you fix it. An in-app
            firewall blocks attacks in production, and every block flows into the same findings and incidents as the rest
            of your security — so detection and defense finally tell one story.
          </p>
        </div>
      </section>

      <section className="mx-auto max-w-5xl px-5 pb-12">
        <div className="grid gap-4 sm:grid-cols-2">
          {POINTS.map(({ icon: Icon, t, d }) => (
            <div key={t} className="card flex gap-4 p-5">
              <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-accent-soft text-accent">
                <Icon className="h-4 w-4" />
              </span>
              <div>
                <h3 className="text-sm font-semibold">{t}</h3>
                <p className="mt-1.5 text-sm leading-relaxed text-muted">{d}</p>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* honest framing — we surface + manage, the OSS sensor blocks */}
      <section className="bg-surface">
        <div className="mx-auto max-w-3xl px-5 py-20 text-center">
          <span className="inline-flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-accent">
            <ShieldCheck className="h-3.5 w-3.5" /> Built on open source
          </span>
          <h2 className="mt-3 text-3xl font-semibold tracking-tight">The blocking is open source. The picture is ours.</h2>
          <p className="mx-auto mt-3 max-w-xl text-base leading-relaxed text-muted">
            The sensor that does the blocking is open-source (Zen) and runs in your app — no black box, no traffic
            routed through us. TensorShield manages it and turns its signal into posture and incidents next to your
            scan findings. Managed rollout is in progress; the protection posture is live today.
          </p>
        </div>
      </section>

      <section className="mx-auto max-w-3xl px-5 py-20 text-center">
        <h2 className="text-2xl font-semibold tracking-tight">See detection and defense in one place.</h2>
        <Link href="/signup" className="mt-7 inline-flex items-center gap-1.5 text-sm font-semibold text-accent hover:underline">
          Start free <ArrowRight className="h-4 w-4" />
        </Link>
      </section>
    </>
  );
}
