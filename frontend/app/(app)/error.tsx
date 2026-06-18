"use client";

import { useEffect } from "react";
import { AlertTriangle, RotateCw } from "lucide-react";

// Segment error boundary — if a Server Component throws (e.g. the API is unreachable on a
// write path), the user gets a recoverable surface instead of a blank screen.
export default function Error({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  useEffect(() => {
    // eslint-disable-next-line no-console
    console.error(error);
  }, [error]);

  return (
    <div className="mx-auto max-w-md py-16 text-center">
      <div className="mx-auto mb-4 grid h-12 w-12 place-items-center rounded-xl border border-high/30 bg-high/10 text-high">
        <AlertTriangle className="h-6 w-6" />
      </div>
      <h2 className="text-base font-semibold">Something went sideways</h2>
      <p className="mx-auto mt-1.5 max-w-sm text-sm text-muted">
        The console couldn&apos;t load this view — the platform API may be briefly unreachable.
      </p>
      <button
        onClick={reset}
        className="mt-5 inline-flex items-center gap-2 rounded-lg border border-accent/40 bg-accent-soft px-3 py-1.5 text-sm font-medium text-accent transition hover:border-accent"
      >
        <RotateCw className="h-4 w-4" /> Try again
      </button>
    </div>
  );
}
