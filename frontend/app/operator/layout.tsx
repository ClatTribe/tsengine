import Link from "next/link";
import { UserCog, LogOut } from "lucide-react";
import { LogoMark } from "@/components/brand/logo";
import { getOperatorToken, operatorMe } from "@/lib/operator";
import { operatorLogout } from "./actions";

export const dynamic = "force-dynamic";

// The operator console's app shell — a branded top bar shared by the login + the cross-tenant queue, so
// the practitioner desk reads as a real product surface (not a bare typed-URL page). This is a SEPARATE
// auth namespace from the tenant app (op_token cookie, §18.5) — deliberately its own minimal shell, not
// the tenant sidebar. Identity + sign-out render only when an operator session exists (so the login page
// shows just the brand).
export default async function OperatorLayout({ children }: { children: React.ReactNode }) {
  const tok = await getOperatorToken();
  const me = tok ? await operatorMe() : null;
  return (
    <div className="flex min-h-screen flex-col bg-bg">
      <header className="sticky top-0 z-30 flex h-14 items-center gap-3 border-b border-border bg-bg/80 px-5 backdrop-blur-md">
        <Link href="/operator" className="flex items-center gap-2.5">
          <span className="grid h-8 w-8 place-items-center rounded-lg bg-[#0b1220] ring-1 ring-white/10">
            <LogoMark className="h-5 w-5" />
          </span>
          <span className="text-sm font-semibold tracking-tight">TensorShield</span>
        </Link>
        <span className="hidden items-center gap-1.5 rounded-md border border-accent/30 bg-accent-soft px-2 py-0.5 text-[11px] font-medium text-accent sm:inline-flex">
          <UserCog className="h-3 w-3" /> Practitioner console
        </span>
        {me && (
          <div className="ml-auto flex items-center gap-3">
            <span className="hidden text-xs text-muted sm:block">
              {me.name || me.email}
              {me.firm ? ` · ${me.firm}` : ""}
            </span>
            <form action={operatorLogout}>
              <button className="inline-flex items-center gap-1.5 rounded-lg border border-border px-2.5 py-1.5 text-xs text-muted transition hover:border-border-strong hover:text-ink">
                <LogOut className="h-3.5 w-3.5" /> Sign out
              </button>
            </form>
          </div>
        )}
      </header>
      <div className="flex-1">{children}</div>
    </div>
  );
}
