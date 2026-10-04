import { redirect } from "next/navigation";
import Link from "next/link";
import { ShieldCheck } from "lucide-react";
import { getSession } from "@/lib/auth";
import { api } from "@/lib/api";
import { TwoFactorControl } from "@/components/settings/two-factor-control";
import { confirmTwoFactor, disableTwoFactor, replaceRecoveryCodes, startTwoFactor } from "@/app/(app)/settings/actions";

// Lives OUTSIDE the (app) route group so the layout's two-factor redirect cannot loop here. A person
// lands here when their workspace requires two-factor sign-in and they have not enrolled: the API
// refuses everything else until they do, so the dashboard would render empty rather than explain.
export default async function TwoFactorSetupPage() {
  const session = await getSession();
  if (!session) redirect("/login");
  const me = await api.me();
  if (!me) redirect("/login");
  // Enrolled (or the policy was lifted): nothing to do here.
  if (me.two_factor_enabled || !me.two_factor_required) redirect("/dashboard");

  return (
    <main className="flex min-h-screen items-center justify-center px-6 py-12">
      <div className="w-full max-w-md animate-fade-rise">
        <Link href="/" className="mb-10 inline-flex items-center gap-2.5">
          <span className="grid h-9 w-9 place-items-center rounded-xl bg-accent text-white shadow-sm">
            <ShieldCheck className="h-5 w-5" />
          </span>
          <span className="text-base font-semibold tracking-tight">TensorShield</span>
        </Link>
        <h1 className="text-2xl font-semibold tracking-tight">Turn on two-factor sign-in</h1>
        <p className="mt-1.5 mb-6 text-sm text-muted">
          {me.tenant_name ?? "Your workspace"} requires a second factor for everyone who signs in. It takes about a
          minute with an authenticator app, and the workspace opens as soon as it is on.
        </p>
        <div className="card p-5">
          <TwoFactorControl
            enabled={false}
            canDisable={false}
            actions={{ start: startTwoFactor, confirm: confirmTwoFactor, disable: disableTwoFactor, replace: replaceRecoveryCodes }}
          />
        </div>
        <p className="mt-4 text-xs text-faint">
          Once you have saved your recovery codes, <Link href="/dashboard" className="text-accent hover:underline">continue to the workspace</Link>.
        </p>
      </div>
    </main>
  );
}
