import { redirect } from "next/navigation";
import { UserCog } from "lucide-react";
import { getOperatorToken } from "@/lib/operator";
import { OperatorLoginForm } from "@/components/operator/login-form";

export const dynamic = "force-dynamic";
export const metadata = { title: "Practitioner sign in | TensorShield" };

export default async function OperatorLoginPage() {
  if (await getOperatorToken()) redirect("/operator");
  return (
    <main className="grid min-h-screen place-items-center bg-bg px-5">
      <div className="w-full max-w-sm">
        <div className="mb-6 text-center">
          <span className="mx-auto mb-3 grid h-11 w-11 place-items-center rounded-xl border border-accent/40 bg-accent-soft text-accent">
            <UserCog className="h-5 w-5" />
          </span>
          <h1 className="text-xl font-semibold tracking-tight">Practitioner console</h1>
          <p className="mt-1 text-sm text-muted">Sign in to work your clients&apos; pending reviews across tenants.</p>
        </div>
        <OperatorLoginForm />
        <p className="mt-4 text-center text-xs text-faint">
          Operator accounts are provisioned by your administrator. This is separate from a tenant login.
        </p>
      </div>
    </main>
  );
}
