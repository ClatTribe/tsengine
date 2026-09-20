"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect } from "react";
import { GraduationCap, FileCheck2, LogOut, ShieldCheck } from "lucide-react";

// The shell an EMPLOYEE seat gets: their training and their policies, and nothing else.
//
// Not the console with pages hidden. An employee is 403'd on every estate endpoint (the allowlist in
// internal/platformapi/employee_scope.go), so rendering the normal shell around them would draw a
// risk rating, a findings badge and a nav of dead links — pages that would come back EMPTY rather
// than forbidden, which reads as "my data vanished" rather than "this is not for you". The frame
// should say what the account is for.
//
// The redirect below is NAVIGATIONAL ONLY. The real boundary is the server gate; this just keeps
// someone who typed a URL from staring at a page that will never fill in.
const ALLOWED = ["/training", "/program"];

export function EmployeeShell({ name, children }: { name: string; children: React.ReactNode }) {
  const path = usePathname();
  const router = useRouter();
  const allowed = ALLOWED.some((p) => path === p || path.startsWith(p + "/"));

  useEffect(() => {
    if (!allowed) router.replace("/training");
  }, [allowed, router]);

  return (
    <div className="min-h-screen bg-bg">
      <header className="border-b border-border bg-surface">
        <div className="mx-auto flex max-w-4xl flex-wrap items-center gap-x-6 gap-y-2 px-5 py-3">
          <div className="flex items-center gap-2 font-semibold text-ink">
            <ShieldCheck className="h-4 w-4 text-accent" /> {name}
          </div>
          <nav className="flex items-center gap-1">
            <Tab href="/training" label="Training" icon={GraduationCap} active={path.startsWith("/training")} />
            <Tab href="/program" label="Policies" icon={FileCheck2} active={path.startsWith("/program")} />
          </nav>
          <button
            onClick={() => {
              fetch("/api/session", { method: "DELETE" }).then(() => {
                router.push("/login");
                router.refresh();
              });
            }}
            className="ml-auto inline-flex items-center gap-1.5 text-xs text-muted transition hover:text-ink"
          >
            <LogOut className="h-3.5 w-3.5" /> Sign out
          </button>
        </div>
      </header>
      <main className="mx-auto max-w-4xl px-5 py-8">
        {allowed ? (
          children
        ) : (
          // Said plainly rather than rendered as an empty page. "Nothing here" and "not for your
          // account" look identical otherwise, and only one of them is true.
          <p className="text-sm text-muted">
            This account is for security training and policy acknowledgements. Taking you to your
            training…
          </p>
        )}
      </main>
    </div>
  );
}

function Tab({
  href,
  label,
  icon: Icon,
  active,
}: {
  href: string;
  label: string;
  icon: typeof GraduationCap;
  active: boolean;
}) {
  return (
    <Link
      href={href}
      className={`inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-sm transition ${
        active ? "bg-surface-2 text-ink" : "text-muted hover:text-ink"
      }`}
    >
      <Icon className="h-3.5 w-3.5" /> {label}
    </Link>
  );
}
