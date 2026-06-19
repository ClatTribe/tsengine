import Link from "next/link";
import { ShieldCheck, Lock, FileCheck2, KeyRound, EyeOff, Fingerprint, ArrowRight, CheckCircle2 } from "lucide-react";

export const metadata = {
  title: "Security & Trust — TensorShield",
  description: "Signed, reproducible, grounded evidence. Least-privilege by default, human-gated writes, encrypted at rest. The trust layer SMBs and their auditors need.",
};

const FRAMEWORKS = [
  "SOC 2", "ISO 27001", "PCI-DSS v4", "HIPAA", "CIS v8", "NIST CSF 2.0", "GDPR",
  "ISO 27701", "NIST 800-53", "NIST 800-171", "CCPA / CPRA", "SOX", "FedRAMP", "India DPDP",
];

const PRINCIPLES = [
  { icon: Fingerprint, t: "Signed, tamper-evident evidence", d: "Every compliance pack is ed25519-signed over its canonical contents and pinned to the exact state it was assessed against. Altering it after the fact breaks the signature." },
  { icon: FileCheck2, t: "Grounded — never guessed", d: "The agent can't record a finding no tool supports. Every claim cites the scanner or evaluator that proves it, so there are no hallucinated vulnerabilities." },
  { icon: EyeOff, t: "Read-only by default", d: "Connections are least-privilege and read-only. The agent assesses freely but cannot change anything on its own." },
  { icon: KeyRound, t: "Human-gated writes", d: "The only write path is reached after a human approves it. Tier-gated, and every automated or human decision is signed into a replayable ledger." },
  { icon: Lock, t: "Encrypted, isolated", d: "OAuth tokens are sealed (AES-256-GCM) before they ever touch storage; every tenant's data is strictly isolated at the store and the API." },
  { icon: ShieldCheck, t: "Reproducible proof", d: "An auditor can re-run a finding's evidence predicate against the pinned snapshot — proof they can verify, not screenshots they have to trust." },
];

export default function Security() {
  return (
    <>
      <section className="relative overflow-hidden">
        <div className="pointer-events-none absolute inset-x-0 -top-40 h-80 bg-gradient-to-b from-accent-soft/60 to-transparent" />
        <div className="relative mx-auto max-w-3xl px-5 pb-10 pt-20 text-center">
          <span className="inline-flex items-center gap-1.5 rounded-full border border-border bg-surface px-3 py-1 text-xs font-medium text-muted shadow-sm">
            <ShieldCheck className="h-3.5 w-3.5 text-accent" /> Trust, by construction
          </span>
          <h1 className="mt-6 text-4xl font-semibold tracking-tight sm:text-5xl">Security you can prove.</h1>
          <p className="mx-auto mt-4 max-w-xl text-lg leading-relaxed text-muted">
            A security product you can&apos;t verify is just another thing to trust. TensorShield is built so your evidence is
            signed, reproducible, and grounded in fact — for you, and for your auditors.
          </p>
        </div>
      </section>

      {/* Principles */}
      <section className="mx-auto max-w-6xl px-5 pb-12">
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {PRINCIPLES.map(({ icon: Icon, t, d }) => (
            <div key={t} className="card p-5">
              <span className="grid h-9 w-9 place-items-center rounded-lg bg-accent-soft text-accent">
                <Icon className="h-4 w-4" />
              </span>
              <h3 className="mt-3.5 text-sm font-semibold">{t}</h3>
              <p className="mt-1.5 text-sm leading-relaxed text-muted">{d}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Frameworks */}
      <section className="bg-surface">
        <div className="mx-auto max-w-4xl px-5 py-20 text-center">
          <span className="text-xs font-semibold uppercase tracking-wider text-accent">Frameworks mapped automatically</span>
          <h2 className="mt-3 text-3xl font-semibold tracking-tight">Every finding lands on a control.</h2>
          <p className="mx-auto mt-3 max-w-lg text-base leading-relaxed text-muted">
            As issues are detected they map to the frameworks you care about — so your posture and evidence stay current
            without anyone keeping a spreadsheet.
          </p>
          <div className="mt-8 flex flex-wrap items-center justify-center gap-2.5">
            {FRAMEWORKS.map((f) => (
              <span key={f} className="inline-flex items-center gap-1.5 rounded-full border border-border bg-bg px-3.5 py-1.5 text-sm font-medium text-ink shadow-sm">
                <CheckCircle2 className="h-3.5 w-3.5 text-pulse" /> {f}
              </span>
            ))}
          </div>
        </div>
      </section>

      {/* We practice what we preach */}
      <section className="mx-auto max-w-3xl px-5 py-20 text-center">
        <h2 className="text-2xl font-semibold tracking-tight">We run TensorShield on TensorShield.</h2>
        <p className="mx-auto mt-3 max-w-xl text-base leading-relaxed text-muted">
          Our own posture is continuously monitored by the same engine, on the same signed loop. The trust we ask you to
          extend is trust we hold ourselves to first.
        </p>
        <Link href="/signup" className="mt-7 inline-flex items-center gap-1.5 text-sm font-semibold text-accent hover:underline">
          Start free and see your evidence <ArrowRight className="h-4 w-4" />
        </Link>
      </section>
    </>
  );
}
