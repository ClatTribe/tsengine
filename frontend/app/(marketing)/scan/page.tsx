import { ScanForm } from "@/components/marketing/scan-form";
import { pageMeta } from "@/lib/seo";
import { AuroraBackdrop } from "@/components/marketing/aurora";

export const metadata = pageMeta({
  title: "Free Security Check — Will You Pass an Enterprise Security Questionnaire? | TensorShield",
  description:
    "Instantly check your domain against the basics every enterprise security questionnaire and SOC 2 review asks about — email-auth (DMARC/SPF/DKIM), HTTPS/TLS, and security headers. Free, no signup, graded in seconds.",
  path: "/scan",
});

export default async function ScanPage({ searchParams }: { searchParams: Promise<{ domain?: string }> }) {
  const { domain } = await searchParams;
  return (
    <section className="relative overflow-hidden">
      <AuroraBackdrop />
      <div className="relative animate-fade-rise mx-auto max-w-3xl px-5 pb-24 pt-20 text-center">
        <span className="text-xs font-semibold uppercase tracking-wider text-accent">Free · no signup</span>
        <h1 className="mx-auto mt-3 max-w-2xl text-4xl font-semibold leading-[1.1] tracking-tight sm:text-5xl">
          Would you pass an enterprise security questionnaire?
        </h1>
        <p className="mx-auto mt-4 max-w-xl text-lg leading-relaxed text-muted">
          Enter your domain for an instant, read-only check of the security basics a SOC 2 review and every enterprise
          buyer&apos;s questionnaire look at first — email auth (DMARC/SPF/DKIM), HTTPS/TLS, and security headers. Get a grade in seconds.
        </p>
        <div className="mt-8">
          <ScanForm initialDomain={domain} />
        </div>
      </div>
    </section>
  );
}
