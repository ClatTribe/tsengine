import { redirect } from "next/navigation";
import Link from "next/link";
import { ShieldCheck } from "lucide-react";
import { getSession } from "@/lib/auth";
import { api } from "@/lib/api";
import { ChangePasswordForm } from "./change-password-form";

// Lives OUTSIDE the (app) route group so the layout's must_change_password redirect can't
// loop here. An invited member lands here automatically; anyone can also reach it to
// change their password voluntarily.
export default async function ChangePasswordPage() {
  const session = await getSession();
  if (!session) redirect("/login");
  const me = await api.me();
  const forced = !!me?.must_change_password;

  return (
    <main className="flex min-h-screen items-center justify-center px-6 py-12">
      <div className="w-full max-w-sm animate-fade-rise">
        <Link href="/" className="mb-10 inline-flex items-center gap-2.5">
          <span className="grid h-9 w-9 place-items-center rounded-xl bg-accent text-white shadow-sm">
            <ShieldCheck className="h-5 w-5" />
          </span>
          <span className="text-base font-semibold tracking-tight">Sentinel</span>
        </Link>

        <h1 className="text-2xl font-semibold tracking-tight">
          {forced ? "Set your password" : "Change your password"}
        </h1>
        <p className="mt-1.5 text-sm text-muted">
          {forced
            ? "You were invited with a one-time password. Choose your own to finish setting up your account — it's the only thing standing between you and the dashboard."
            : "Pick a new password for your account."}
        </p>

        <ChangePasswordForm forced={forced} email={me?.email ?? ""} />
      </div>
    </main>
  );
}
