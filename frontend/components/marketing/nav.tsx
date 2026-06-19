import Link from "next/link";
import { ShieldCheck } from "lucide-react";

const LINKS = [
  { href: "/product", label: "Product" },
  { href: "/pricing", label: "Pricing" },
  { href: "/security", label: "Security" },
];

export function MarketingNav() {
  return (
    <header className="sticky top-0 z-40 border-b border-border/70 bg-bg/80 backdrop-blur-md">
      <nav className="mx-auto flex h-16 max-w-6xl items-center gap-6 px-5">
        <Link href="/" className="flex items-center gap-2.5">
          <span className="grid h-8 w-8 place-items-center rounded-lg bg-accent text-white shadow-sm">
            <ShieldCheck className="h-4 w-4" />
          </span>
          <span className="text-base font-semibold tracking-tight">Sentinel</span>
        </Link>

        <div className="ml-2 hidden items-center gap-1 md:flex">
          {LINKS.map((l) => (
            <Link
              key={l.href}
              href={l.href}
              className="rounded-lg px-3 py-1.5 text-sm text-muted transition hover:bg-surface-2 hover:text-ink"
            >
              {l.label}
            </Link>
          ))}
        </div>

        <div className="ml-auto flex items-center gap-2">
          <Link href="/login" className="rounded-lg px-3 py-1.5 text-sm font-medium text-muted transition hover:text-ink">
            Sign in
          </Link>
          <Link
            href="/login"
            className="rounded-xl bg-accent px-3.5 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover"
          >
            Start free
          </Link>
        </div>
      </nav>
    </header>
  );
}
