import { cn } from "@/lib/utils";

// LogoMark — the TensorShield brand mark as a crisp, theme-aware SVG (from the brand artwork): a
// shield enclosing a tensor/network mesh of nodes, an upward-right growth arrow, and the handshake
// "human accountability layer" motif at its heart. Drawn in currentColor so it inherits the parent's
// color (white on the accent chip, accent on a plain surface) and scales without a raster asset.
export function LogoMark({ className, title = "TensorShield" }: { className?: string; title?: string }) {
  return (
    <svg viewBox="0 0 48 48" fill="none" className={className} role="img" aria-label={title}>
      <title>{title}</title>
      {/* shield */}
      <path
        d="M24 3.5 L40 9.5 V22 C40 32 33 39.5 24 44 C15 39.5 8 32 8 22 V9.5 Z"
        stroke="currentColor"
        strokeWidth="2.2"
        strokeLinejoin="round"
        opacity="0.95"
      />
      {/* tensor / network mesh — nodes + edges */}
      <g stroke="currentColor" strokeWidth="1.4" opacity="0.7" strokeLinecap="round">
        <path d="M16 16 L24 12 L32 16 M16 16 L16 26 L24 31 L32 26 L32 16 M16 16 L24 21 L32 16 M24 12 L24 21 M16 26 L24 21 L32 26" />
      </g>
      {/* nodes */}
      <g fill="currentColor">
        <circle cx="24" cy="12" r="2" />
        <circle cx="16" cy="16" r="1.8" />
        <circle cx="32" cy="16" r="1.8" />
        <circle cx="16" cy="26" r="1.8" />
        <circle cx="32" cy="26" r="1.8" />
        <circle cx="24" cy="31" r="2" />
        <circle cx="24" cy="21" r="1.6" />
      </g>
      {/* upward-right growth arrow */}
      <path
        d="M19 30 L30 19 M25 18.5 H30.5 V24"
        stroke="currentColor"
        strokeWidth="2.4"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      {/* handshake clasp at the heart — the human accountability layer */}
      <path
        d="M20.5 24.5 L23.5 22 L25 23 L27.5 21 L29.5 23"
        stroke="currentColor"
        strokeWidth="2.2"
        strokeLinecap="round"
        strokeLinejoin="round"
        opacity="0.95"
      />
    </svg>
  );
}

// Logo — the mark inside the brand chip + the wordmark, the standard lockup used in the header/footer.
export function Logo({ className, markClass }: { className?: string; markClass?: string }) {
  return (
    <span className={cn("flex items-center gap-2.5", className)}>
      <span className="grid h-8 w-8 place-items-center rounded-lg bg-accent text-white shadow-sm">
        <LogoMark className={cn("h-5 w-5", markClass)} />
      </span>
      <span className="text-base font-semibold tracking-tight">TensorShield</span>
    </span>
  );
}
