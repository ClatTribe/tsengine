import Link from "next/link";
import { Compass } from "lucide-react";

// Global 404 — also what a finding/[id] notFound() lands on.
export default function NotFound() {
  return (
    <div className="grid min-h-screen place-items-center px-4">
      <div className="max-w-md text-center">
        <div className="mx-auto mb-4 grid h-12 w-12 place-items-center rounded-xl border border-border bg-surface-2 text-faint">
          <Compass className="h-6 w-6" />
        </div>
        <h1 className="text-base font-semibold">Nothing here</h1>
        <p className="mx-auto mt-1.5 max-w-xs text-sm text-muted">
          That page doesn&apos;t exist, or the resource is no longer tracked.
        </p>
        <Link
          href="/"
          className="mt-5 inline-flex items-center gap-2 rounded-lg border border-border bg-surface px-3 py-1.5 text-sm text-muted transition hover:border-border-strong hover:text-ink"
        >
          Back to Overview
        </Link>
      </div>
    </div>
  );
}
