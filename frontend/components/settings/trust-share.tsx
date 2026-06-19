"use client";

import { useEffect, useState } from "react";
import { Copy, Check, ExternalLink } from "lucide-react";

// Shows the tenant's public Trust Center link with copy + open, plus an embeddable
// "Secured by TensorShield" badge (the viral loop: a customer puts it on their site →
// visitors click through to the Trust Center → discover TensorShield). The absolute URL is
// built from the live origin after mount (avoids any SSR/CSR hydration mismatch on window).
export function TrustShare({ path }: { path: string }) {
  const [origin, setOrigin] = useState("");
  const [copied, setCopied] = useState<"" | "link" | "embed">("");
  useEffect(() => setOrigin(window.location.origin), []);
  const url = origin ? `${origin}${path}` : path;
  const badgeSrc = origin ? `${origin}/api/badge` : "/api/badge";
  const embed = `<a href="${url}" target="_blank" rel="noopener">\n  <img src="${badgeSrc}" alt="Secured by TensorShield" width="196" height="40">\n</a>`;

  async function copy(what: "link" | "embed", text: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(what);
      setTimeout(() => setCopied(""), 1500);
    } catch {
      /* clipboard blocked — the fields are selectable as a fallback */
    }
  }

  return (
    <div className="space-y-4">
      {/* Shareable link */}
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
        <input
          readOnly
          value={url}
          onFocus={(e) => e.currentTarget.select()}
          className="mono min-w-0 flex-1 rounded-lg border border-border bg-surface-2 px-3 py-2 text-xs text-muted outline-none focus:border-accent"
        />
        <div className="flex gap-2">
          <button
            onClick={() => copy("link", url)}
            className="inline-flex items-center gap-1.5 rounded-lg bg-accent px-3 py-2 text-xs font-semibold text-white shadow-sm transition hover:bg-accent-hover active:translate-y-px"
          >
            {copied === "link" ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
            {copied === "link" ? "Copied" : "Copy link"}
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

      {/* Embeddable trust badge — the viral loop */}
      <div className="rounded-lg border border-border bg-surface-2 p-3">
        <div className="flex items-center justify-between gap-3">
          <div className="text-xs font-medium text-ink">Add a trust badge to your site</div>
          <button
            onClick={() => copy("embed", embed)}
            className="inline-flex items-center gap-1.5 rounded-lg border border-border bg-surface px-2.5 py-1.5 text-[11px] font-medium text-muted transition hover:border-accent/40 hover:text-ink"
          >
            {copied === "embed" ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
            {copied === "embed" ? "Copied" : "Copy embed code"}
          </button>
        </div>
        <p className="mt-1 text-[11px] text-faint">
          Show customers you&apos;re continuously monitored — the badge links back to your public Trust Center.
        </p>
        <div className="mt-2.5 flex flex-wrap items-center gap-3">
          {/* eslint-disable-next-line @next/next/no-img-element */}
          {origin && <img src={badgeSrc} alt="Secured by TensorShield" width={196} height={40} />}
          <code className="mono min-w-0 flex-1 overflow-x-auto whitespace-pre rounded border border-border bg-bg px-2.5 py-1.5 text-[10px] text-muted">{embed}</code>
        </div>
      </div>
    </div>
  );
}
