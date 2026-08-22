import { cn } from "@/lib/utils";
import { SHIELD, EMERALD, lattice } from "@/lib/brand-mark.mjs";

// ---------------------------------------------------------------------------
// The TensorShield brand mark — "Lattice Shield". Geometry lives in
// lib/brand-mark.mjs; this file only decides how it is cut and coloured.
//
// ONE CUT: the shield fills and the cells KNOCK OUT, so whatever sits behind the
// mark shows through them and there is no light-on-dark variant to keep in sync.
// That is the cut because of where the mark is actually read — every consumer in
// this app (nav, footer, sidebar, login, signup, operator) renders it at 20-24px
// inside the dark chip. A stroked alternative was drawn and rasterised at
// 16/20/24/40px alongside it, and below ~28px its 2.8 stroke and the lattice
// merge into stripes. Measured, not predicted; re-run that check before changing
// the cut, at the sizes the mark ships at rather than the size you design it at.
// ---------------------------------------------------------------------------

// The default cut of the lattice. Optical sizes (the wider gap the 16px favicon
// needs) live in scripts/gen-icons.mjs, which is the only caller that needs them.
const L = lattice();

// indigo-300. The mark's home is the dark chip below, and the app-token indigo
// (#4F46E5) is too dark to read on it. Written as a literal, NOT interpolated
// from brand-mark's MARK constant: Tailwind extracts class names statically, so
// a template-built `text-[${MARK}]` would never be generated. Callers on a light
// ground override with their own text-* class — the fill is currentColor and cn()
// runs tailwind-merge, so the caller's colour wins.
const ON_CHIP = "text-[#A5B4FC]";

type MarkProps = {
  className?: string;
  title?: string;
  /** Drop the emerald cell — monochrome, for a single-colour reproduction. */
  mono?: boolean;
};

/**
 * LogoMark — the solid cut, and what ships everywhere in the app. The shield
 * fills and the cells knock out, so whatever is behind the mark shows through
 * them and there is no light-on-dark variant to keep in sync.
 */
export function LogoMark({ className, title = "TensorShield", mono = false }: MarkProps) {
  const [ax, ay] = L.accent;
  return (
    <svg viewBox="0 0 48 48" fill="none" className={cn(ON_CHIP, className)} role="img" aria-label={title}>
      <title>{title}</title>
      <path fillRule="evenodd" clipRule="evenodd" fill="currentColor" d={`${SHIELD} ${L.path}`} />
      {!mono && <rect x={ax} y={ay} width={L.cell} height={L.cell} rx={L.radius} fill={EMERALD} />}
    </svg>
  );
}

// There is deliberately NO second exported cut. A stroked variant (outline shield,
// filled cells) was drawn and measured, and it lost every surface it was a
// candidate for: the app renders the mark at 20-24px, and the OG card is read at
// roughly 16px once a feed scales it down. Shipping it anyway would have been an
// unreachable export of exactly the kind that let the old mark and app/icon.tsx
// drift apart. If a genuine large-format surface appears (print, a hero), build it
// from SHIELD + lattice() above rather than re-typing a path.

// The dark chip the mark sits on — deep navy with a hairline ring. Exported so
// every lockup (nav, footer, sidebar, auth, operator) frames the mark identically.
export const logoChip = "bg-[#0b1220] ring-1 ring-white/10";

// Logo — mark in the chip plus the wordmark: the standard header/footer lockup.
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
