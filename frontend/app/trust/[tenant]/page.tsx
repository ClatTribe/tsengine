import Link from "next/link";
import { ShieldCheck, CheckCircle2, Lock, Activity, UserCheck } from "lucide-react";
import { apiBase } from "@/lib/auth";
import { FRAMEWORK_LABEL } from "@/lib/frameworks";
import type { TrustView } from "@/lib/types";

export const dynamic = "force-dynamic";

export const metadata = {
  title: "Trust Center",
  description: "Live security & compliance posture, continuously monitored and signed.",
};

async function fetchTrust(tenant: string, token: string): Promise<TrustView | null> {
  if (!token) return null;
  try {
    const res = await fetch(
      `${apiBase()}/v1/trust/${encodeURIComponent(tenant)}?token=${encodeURIComponent(token)}`,
      { cache: "no-store" },
    );
    if (!res.ok) return null;
    return (await res.json()) as TrustView;
  } catch {
    return null;
  }
}

export default async function TrustCenter({
  params,
  searchParams,
}: {
  params: Promise<{ tenant: string }>;
  searchParams: Promise<{ token?: string }>;
}) {
  const { tenant } = await params;
  const { token } = await searchParams;
  const data = await fetchTrust(tenant, token ?? "");

  if (!data) {
    return (
      <main className="grid min-h-screen place-items-center px-5">
        <div className="max-w-md text-center">
          <div className="mx-auto mb-4 grid h-12 w-12 place-items-center rounded-xl border border-border bg-surface-2 text-faint">
            <Lock className="h-6 w-6" />
          </div>
          <h1 className="text-lg font-semibold">This Trust Center isn&apos;t available</h1>
          <p className="mx-auto mt-1.5 max-w-xs text-sm text-muted">
            The link may be incomplete or has been revoked. Ask whoever shared it for a fresh link.
          </p>
          <Link href="/" className="mt-5 inline-block text-sm font-semibold text-accent hover:underline">
            What is TensorShield? →
          </Link>
        </div>
      </main>
    );
  }

  const generated = new Date(data.generated_at).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" });

  return (
    <main className="min-h-screen">
      {/* top bar */}
      <header className="border-b border-border/70">
        <div className="mx-auto flex h-16 max-w-4xl items-center justify-between px-5">
          <Link href="/" className="flex items-center gap-2.5">
            <span className="grid h-8 w-8 place-items-center rounded-lg bg-accent text-white shadow-sm">
              <ShieldCheck className="h-4 w-4" />
            </span>
            <span className="text-sm font-semibold tracking-tight">TensorShield</span>
          </Link>
          <span className="text-xs font-medium uppercase tracking-wider text-faint">Trust Center</span>
        </div>
      </header>

      <div className="relative overflow-hidden">
        <div className="pointer-events-none absolute inset-x-0 -top-40 h-80 bg-gradient-to-b from-accent-soft/60 to-transparent" />
        <div className="relative mx-auto max-w-4xl px-5 py-16">
          {/* hero */}
          <div className="text-center">
            <span className="inline-flex items-center gap-1.5 rounded-full bg-pulse-soft px-3 py-1 text-xs font-medium text-pulse">
              <span className="pulse-dot" /> Continuously monitored
            </span>
            <h1 className="mt-5 text-4xl font-semibold tracking-tight sm:text-5xl">{data.org}</h1>
            <p className="mt-3 text-lg text-muted">Security &amp; compliance posture — live, and independently verifiable.</p>
          </div>

          {/* trust pills */}
          <div className="mx-auto mt-10 grid max-w-2xl gap-3 sm:grid-cols-3">
            {[
              { icon: Activity, t: "Continuously monitored", d: "Re-scanned on every change" },
              { icon: Lock, t: "Evidence signed", d: "ed25519, tamper-evident" },
              { icon: UserCheck, t: "Human in the loop", d: "Gated, auditable actions" },
            ].map(({ icon: Icon, t, d }) => (
              <div key={t} className="card p-4 text-center">
                <span className="mx-auto grid h-9 w-9 place-items-center rounded-lg bg-accent-soft text-accent">
                  <Icon className="h-4 w-4" />
                </span>
                <div className="mt-2.5 text-sm font-semibold">{t}</div>
                <div className="mt-0.5 text-xs text-muted">{d}</div>
              </div>
            ))}
          </div>

          {/* framework coverage */}
          {(data.frameworks ?? []).length > 0 && (
            <div className="mx-auto mt-12 max-w-2xl">
              <h2 className="mb-4 text-center text-xs font-semibold uppercase tracking-wider text-faint">Framework coverage</h2>
              <div className="space-y-3">
                {(data.frameworks ?? []).map((f) => (
                  <div key={f.framework} className="card p-4">
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-medium">{FRAMEWORK_LABEL[f.framework] ?? f.framework}</span>
                      <span className={`text-sm font-semibold ${f.coverage === 100 ? "text-pulse" : "text-ink"}`}>{f.coverage}%</span>
                    </div>
                    <div className="mt-2 h-2 overflow-hidden rounded-full bg-surface-3">
                      <div
                        className={`h-full rounded-full ${f.coverage === 100 ? "bg-pulse" : "bg-accent"}`}
                        style={{ width: `${Math.max(4, f.coverage)}%` }}
                      />
                    </div>
                    <div className="mt-1.5 text-[11px] text-faint">{f.met} of {f.total} controls met</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* footer */}
          <div className="mx-auto mt-12 max-w-2xl border-t border-border pt-6 text-center">
            <p className="flex items-center justify-center gap-1.5 text-xs text-muted">
              <CheckCircle2 className="h-3.5 w-3.5 text-pulse" />
              Generated live from {data.org}&apos;s security posture on {generated}.
            </p>
            <Link href="/" className="mt-3 inline-block text-xs font-semibold text-accent hover:underline">
              Secured by TensorShield — see how it works →
            </Link>
          </div>
        </div>
      </div>
    </main>
  );
}
