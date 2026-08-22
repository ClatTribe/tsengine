import { cn } from "@/lib/utils";
import { SHIELD, EMERALD, lattice } from "@/lib/brand-mark.mjs";

// ---------------------------------------------------------------------------
// The TensorShield brand mark — "Lattice Shield". Geometry lives in
// lib/brand-mark.mjs; this file only decides how it is cut and coloured.
//
// ONE CUT: the shield fills and the cells KNOCK OUT, so whatever sits behind the
// mark shows through them and there is no light-on-dark variant to keep in sync.
// That is the cut because of where the mark is actually read — every consumer in
// this app (nav, footer, sidebar, login, signup, operator) renders it at 28-32px
// directly on the page. A stroked alternative was drawn and rasterised at
// 16/20/24/40px alongside it, and below ~28px its 2.8 stroke and the lattice
// merge into stripes. Measured, not predicted; re-run that check before changing
// the cut, at the sizes the mark ships at rather than the size you design it at.
// ---------------------------------------------------------------------------

// The default cut of the lattice. Optical sizes (the wider gap the 16px favicon
// needs) live in scripts/gen-icons.mjs, which is the only caller that needs them.
const L = lattice();

// The mark takes the app's own accent token, so it themes itself: indigo-600
// (#4F46E5) on the light canvas, indigo-400 (#818CF8) on the dark one. Both are
// the colour the rest of the UI already uses for "the agent".
//
// It used to be a hardcoded indigo-300, because the mark sat on a hardcoded
// near-black chip. That chip was a leftover from the dark console this product
// stopped being in 2026-06 (frontend/DESIGN.md §3): it never resolved from a
// variable, so in dark mode it matched the canvas to within a few points and
// vanished as intended, while on the light canvas it rendered as a black square
// behind the logo on every marketing page. The mark is a solid shield with the
// lattice KNOCKED OUT — the ground shows through the cells — which is precisely
// the cut that needs no chip. Callers override with their own text-* class if
// they need to; the fill is currentColor and cn() runs tailwind-merge.
const MARK_COLOR = "text-accent";

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
    <svg viewBox="0 0 48 48" fill="none" className={cn(MARK_COLOR, className)} role="img" aria-label={title}>
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

// There is no exported chip any more. `logoChip` was `bg-[#0b1220] ring-1
// ring-white/10` and every lockup hand-rolled the same two classes beside it, so
// removing it here is only half the fix — the eight call sites are updated too.
//
// The two surfaces whose ground really is dark and fixed keep theirs, and neither
// goes through this component: app/opengraph-image.tsx paints its own card, and
// scripts/gen-icons.mjs paints the favicon tile. A chip is right there and wrong
// here, which is why it now lives with each of them rather than as a shared token
// applied to grounds that are not dark.

// Logo — the mark plus the wordmark: the standard header/footer lockup.
export function Logo({ className, markClass }: { className?: string; markClass?: string }) {
  return (
    <span className={cn("flex items-center gap-2.5", className)}>
      {/* 28px, not the 20px the chipped version used: without a chip the mark has
          to carry the lockup's visual weight against the wordmark on its own. */}
      <LogoMark className={cn("h-7 w-7", markClass)} />
      <span className="text-base font-semibold tracking-tight">TensorShield</span>
    </span>
  );
}
