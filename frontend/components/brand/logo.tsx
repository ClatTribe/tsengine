import { cn } from "@/lib/utils";

// LogoMark — the TensorShield brand mark. A cyan-gradient shield enclosing a node network
// (the unified finding graph), a growth arrow breaking out to the upper-right (autonomous
// security), and a warm "clasp" glow at the heart (the human-accountability layer — the
// handshake). Self-contained gradients so it renders in full colour on any background; it's
// designed to sit on a dark chip (see Logo). Simplified for legibility down to ~20px.
export function LogoMark({ className, title = "TensorShield" }: { className?: string; title?: string }) {
  return (
    <svg viewBox="0 0 48 48" fill="none" className={className} role="img" aria-label={title}>
      <title>{title}</title>
      <defs>
        <linearGradient id="ts-cyan" x1="9" y1="5" x2="40" y2="45" gradientUnits="userSpaceOnUse">
          <stop stopColor="#7dd3fc" />
          <stop offset="0.5" stopColor="#38bdf8" />
          <stop offset="1" stopColor="#4f46e5" />
        </linearGradient>
        <radialGradient id="ts-warm" cx="0.5" cy="0.5" r="0.5">
          <stop stopColor="#fff7ed" />
          <stop offset="0.45" stopColor="#fb923c" />
          <stop offset="1" stopColor="#f97316" stopOpacity="0" />
        </radialGradient>
      </defs>

      {/* shield: faint inner fill + bright gradient edge */}
      <path
        d="M24 4 L40 9.6 V22.6 C40 32.4 33.1 40.2 24 44 C14.9 40.2 8 32.4 8 22.6 V9.6 Z"
        fill="#0ea5e9"
        fillOpacity="0.08"
        stroke="url(#ts-cyan)"
        strokeWidth="2.2"
        strokeLinejoin="round"
      />

      {/* node network — the finding graph */}
      <g stroke="url(#ts-cyan)" strokeWidth="1.2" strokeLinecap="round" opacity="0.75">
        <path d="M24 12.5 L14 22 M24 12.5 L34 22 M14 22 L18.5 32 M34 22 L29.5 32 M18.5 32 L29.5 32 M14 22 L34 22" />
      </g>
      <g fill="url(#ts-cyan)">
        <circle cx="24" cy="12.5" r="1.7" />
        <circle cx="14" cy="22" r="1.7" />
        <circle cx="34" cy="22" r="1.7" />
        <circle cx="18.5" cy="32" r="1.7" />
        <circle cx="29.5" cy="32" r="1.7" />
      </g>

      {/* growth arrow breaking out to the upper-right */}
      <g stroke="url(#ts-cyan)" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
        <path d="M17.5 30.5 L33 15" />
        <path d="M26 14.5 L33.5 14.5 L33.5 22" />
      </g>

      {/* human-accountability clasp — warm glow at the heart of the network */}
      <circle cx="23.5" cy="24" r="6.2" fill="url(#ts-warm)" />
      <circle cx="23.5" cy="24" r="1.8" fill="#fffaf2" />
    </svg>
  );
}

// The dark chip the colour mark sits on — a deep navy like the brand art, with a hairline ring.
// Exported so every lockup (nav, footer, auth) frames the mark identically.
export const logoChip = "bg-[#0b1220] ring-1 ring-white/10";

// Logo — the mark inside the brand chip + the wordmark, the standard header/footer lockup.
export function Logo({ className, markClass }: { className?: string; markClass?: string }) {
  return (
    <span className={cn("flex items-center gap-2.5", className)}>
      <span className={cn("grid h-8 w-8 place-items-center rounded-lg shadow-sm", logoChip)}>
        <LogoMark className={cn("h-5 w-5", markClass)} />
      </span>
      <span className="text-base font-semibold tracking-tight">TensorShield</span>
    </span>
  );
}
