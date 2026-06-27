import { pageMeta } from "@/lib/seo";

export const metadata = pageMeta({
  title: "Subprocessors — TensorShield",
  description: "The third-party subprocessors TensorShield uses to deliver the service.",
  path: "/subprocessors",
});

// Grounded in what the product actually uses. AI is only engaged on paid plans (and not at all
// if a customer brings their own model key). Keep this list current as infrastructure changes.
const SUBPROCESSORS = [
  { name: "Amazon Web Services (AWS)", purpose: "Cloud hosting, compute, and data storage", location: "India / configured region", data: "All service data (encrypted at rest)" },
  { name: "Anthropic", purpose: "LLM for the AI security engineer (paid plans; skipped if you bring your own model key)", location: "USA", data: "Finding context sent per-request; not used to train their models" },
  { name: "Email delivery provider (SMTP)", purpose: "Transactional email — invites, password resets, alerts", location: "Configured by operator", data: "Recipient email + message content" },
];

export default function Subprocessors() {
  return (
    <article className="mx-auto max-w-3xl px-5 py-16">
      <p className="text-xs font-semibold uppercase tracking-wider text-accent">Legal</p>
      <h1 className="mt-2 text-3xl font-semibold tracking-tight sm:text-4xl">Subprocessors</h1>
      <p className="mt-2 text-sm text-faint">Last updated 28 June 2026</p>

      <p className="mt-8 text-[15px] leading-relaxed text-ink">
        TensorShield uses a small number of vetted third parties (&ldquo;subprocessors&rdquo;) to deliver the
        service. Each is bound by data-protection terms at least as protective as our{" "}
        <a href="/dpa" className="text-accent hover:underline">
          DPA
        </a>
        . We update this page before adding a new one.
      </p>

      <div className="mt-8 overflow-x-auto">
        <table className="w-full min-w-[560px] border-separate border-spacing-0 text-sm">
          <thead>
            <tr className="text-left text-[11px] font-semibold uppercase tracking-wider text-faint">
              <th className="border-b border-border pb-2 pr-4">Subprocessor</th>
              <th className="border-b border-border pb-2 pr-4">Purpose</th>
              <th className="border-b border-border pb-2 pr-4">Region</th>
              <th className="border-b border-border pb-2">Data</th>
            </tr>
          </thead>
          <tbody>
            {SUBPROCESSORS.map((s) => (
              <tr key={s.name} className="align-top">
                <td className="border-b border-border py-3 pr-4 font-medium text-ink">{s.name}</td>
                <td className="border-b border-border py-3 pr-4 text-muted">{s.purpose}</td>
                <td className="border-b border-border py-3 pr-4 text-muted">{s.location}</td>
                <td className="border-b border-border py-3 text-muted">{s.data}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <p className="mt-8 text-sm leading-relaxed text-muted">
        The global threat-intelligence feeds we ingest (CISA KEV, FIRST.org EPSS, Exploit-DB, NVD) are public,
        read-only reference data and process no customer data, so they are not subprocessors.
      </p>
      <p className="mt-6 border-t border-border pt-6 text-sm text-faint">
        To be notified of changes or object to a subprocessor, email{" "}
        <span className="text-muted">privacy@tensorshield.io</span>.
      </p>
    </article>
  );
}
