import { cn } from "@/lib/utils";

// LogoMark — the TensorShield brand mark: a clean, bold shield enclosing a single upward "tensor"
// node-chevron (three connected nodes = network + growth + protection). Deliberately minimal so it
// stays crisp and legible at favicon size (16px) — a busy multi-motif mark reads as a blob when small.
// Drawn in currentColor so it inherits the parent's color (white on the accent chip, accent on a plain
// surface) and scales without a raster asset.
export function LogoMark({ className, title = "TensorShield" }: { className?: string; title?: string }) {
  return (
    <svg viewBox="0 0 48 48" fill="none" className={className} role="img" aria-label={title}>
      <title>{title}</title>
      {/* shield */}
      <path
        d="M24 4 L39 9.5 V22.5 C39 32 32.5 39.5 24 43.5 C15.5 39.5 9 32 9 22.5 V9.5 Z"
        stroke="currentColor"
        strokeWidth="2.6"
        strokeLinejoin="round"
      />
      {/* upward tensor chevron — three connected nodes */}
      <path
        d="M16.5 29 L24 18 L31.5 29"
        stroke="currentColor"
        strokeWidth="2.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <g fill="currentColor">
        <circle cx="16.5" cy="29" r="2.1" />
        <circle cx="31.5" cy="29" r="2.1" />
        <circle cx="24" cy="18" r="2.7" />
      </g>
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
