"use client";

import { useEffect, useState } from "react";
import { Copy, Check, ExternalLink } from "lucide-react";

// Shows the tenant's public Trust Center link with copy + open. The absolute URL is built
// from the live origin after mount (avoids any SSR/CSR hydration mismatch on window).
export function TrustShare({ path }: { path: string }) {
  const [origin, setOrigin] = useState("");
  const [copied, setCopied] = useState(false);
  useEffect(() => setOrigin(window.location.origin), []);
  const url = origin ? `${origin}${path}` : path;

  async function copy() {
    try {
      await navigator.clipboard.writeText(url);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard blocked — the input is selectable as a fallback */
    }
  }

  return (
    <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
      <input
        readOnly
        value={url}
        onFocus={(e) => e.currentTarget.select()}
        className="mono min-w-0 flex-1 rounded-lg border border-border bg-surface-2 px-3 py-2 text-xs text-muted outline-none focus:border-accent"
      />
      <div className="flex gap-2">
        <button
          onClick={copy}
          className="inline-flex items-center gap-1.5 rounded-lg bg-accent px-3 py-2 text-xs font-semibold text-white shadow-sm transition hover:bg-accent-hover active:translate-y-px"
        >
          {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
          {copied ? "Copied" : "Copy link"}
        </button>
        <a
          href={url}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-1.5 rounded-lg border border-border bg-surface px-3 py-2 text-xs font-medium text-muted transition hover:border-border-strong hover:text-ink"
        >
          <ExternalLink className="h-3.5 w-3.5" /> Open
        </a>
      </div>
    </div>
  );
}
