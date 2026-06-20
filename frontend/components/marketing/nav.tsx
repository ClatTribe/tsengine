"use client";

import { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { ShieldCheck, Menu, X } from "lucide-react";
import { cn } from "@/lib/utils";

const LINKS = [
  { href: "/product", label: "Product" },
  { href: "/ai-security-engineer", label: "AI engineer" },
  { href: "/ci-cd", label: "CI/CD" },
  { href: "/vapt", label: "VAPT" },
  { href: "/pricing", label: "Pricing" },
  { href: "/security", label: "Security" },
];

export function MarketingNav() {
  const [open, setOpen] = useState(false);
  const path = usePathname();

  return (
    <header className="sticky top-0 z-40 border-b border-border/70 bg-bg/80 backdrop-blur-md">
      <nav className="mx-auto flex h-16 max-w-6xl items-center gap-6 px-5">
        <Link href="/" className="flex items-center gap-2.5" onClick={() => setOpen(false)}>
          <span className="grid h-8 w-8 place-items-center rounded-lg bg-accent text-white shadow-sm">
            <ShieldCheck className="h-4 w-4" />
          </span>
          <span className="text-base font-semibold tracking-tight">TensorShield</span>
        </Link>

        {/* Desktop section links */}
        <div className="ml-2 hidden items-center gap-1 md:flex">
          {LINKS.map((l) => (
            <Link
              key={l.href}
              href={l.href}
              className={cn(
                "rounded-lg px-3 py-1.5 text-sm transition hover:bg-surface-2 hover:text-ink",
                path === l.href ? "text-ink" : "text-muted",
              )}
            >
              {l.label}
            </Link>
          ))}
        </div>

        {/* Desktop CTAs */}
        <div className="ml-auto hidden items-center gap-2 md:flex">
          <Link href="/login" className="rounded-lg px-3 py-1.5 text-sm font-medium text-muted transition hover:text-ink">
            Sign in
          </Link>
          <Link
            href="/signup"
            className="rounded-xl bg-accent px-3.5 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover active:translate-y-px"
          >
            Start free
          </Link>
        </div>

        {/* Mobile: keep the primary CTA + a menu toggle */}
        <div className="ml-auto flex items-center gap-2 md:hidden">
          <Link
            href="/signup"
            className="rounded-xl bg-accent px-3 py-1.5 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover active:translate-y-px"
          >
            Start free
          </Link>
          <button
            onClick={() => setOpen((v) => !v)}
            aria-label={open ? "Close menu" : "Open menu"}
            aria-expanded={open}
            className="grid h-9 w-9 place-items-center rounded-lg border border-border bg-surface text-muted transition hover:border-border-strong hover:text-ink"
          >
            {open ? <X className="h-4 w-4" /> : <Menu className="h-4 w-4" />}
          </button>
        </div>
      </nav>

      {/* Mobile dropdown */}
      {open && (
        <div className="border-t border-border/70 bg-bg px-5 py-3 md:hidden animate-fade-rise">
          <div className="flex flex-col gap-0.5">
            {LINKS.map((l) => (
              <Link
                key={l.href}
                href={l.href}
                onClick={() => setOpen(false)}
                className={cn(
                  "rounded-lg px-3 py-2.5 text-sm transition hover:bg-surface-2",
                  path === l.href ? "bg-surface-2 text-ink" : "text-muted",
                )}
              >
                {l.label}
              </Link>
            ))}
            <Link
              href="/login"
              onClick={() => setOpen(false)}
              className="mt-1 rounded-lg px-3 py-2.5 text-sm font-medium text-muted transition hover:bg-surface-2 hover:text-ink"
            >
              Sign in
            </Link>
          </div>
        </div>
      )}
    </header>
  );
}
