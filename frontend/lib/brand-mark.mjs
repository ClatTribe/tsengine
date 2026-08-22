// ---------------------------------------------------------------------------
// The TensorShield mark — "Lattice Shield" — as pure geometry.
//
// THIS FILE IS THE ONLY PLACE THE MARK IS DRAWN. Four surfaces render it and one
// script rasterises it, and before this module existed they had each drifted into
// their own drawing: the React component carried a shield + five-node graph +
// arrow + glow, while app/icon.tsx carried a hand-simplified version of the same
// idea that no longer matched. Nobody noticed because nothing compared them.
// Import from here; do not re-type a path.
//
// The idea: a rank-2 tensor (the 2x2 lattice) inside the shield's guard, so both
// halves of the name are the same shape rather than two shapes glued together.
// The lower-right cell is emerald, which means here what it means everywhere else
// in the product — HANDLED. Indigo is the agent. Nothing else gets a colour.
// ---------------------------------------------------------------------------

/** The shield outline. Shared by every cut. */
export const SHIELD =
  "M24 4.2 L39.5 9.6 L39.5 23.2 C39.5 32.6 33 40.3 24 43.8 C15 40.3 8.5 32.6 8.5 23.2 L8.5 9.6 Z";

/** Deep navy chip the mark sits on, and the two mark colours. */
export const CHIP = "#0B1220";
/** indigo-300 — the app-token indigo (#4F46E5) is too dark to read on the chip. */
export const MARK = "#A5B4FC";
/** emerald-400 — "handled", the same meaning it carries everywhere else. */
export const EMERALD = "#34D399";

const roundedRect = (x, y, s, r) =>
  `M${x + r} ${y} H${x + s - r} A${r} ${r} 0 0 1 ${x + s} ${y + r} ` +
  `V${y + s - r} A${r} ${r} 0 0 1 ${x + s - r} ${y + s} H${x + r} ` +
  `A${r} ${r} 0 0 1 ${x} ${y + s - r} V${y + r} A${r} ${r} 0 0 1 ${x + r} ${y} Z`;

/**
 * The 2x2 lattice, centred on the shield's optical centre (24, 24.5).
 *
 * `cell` and `gap` are the ONLY things an optical size may move — the shield and
 * the 2x2 arrangement stay identical, so a size-specific cut is a parameter rather
 * than a second drawing.
 *
 * The DEFAULTS are tuned for 20-24px, not for the 48px the mark is drawn at,
 * because 20-24px is where every surface actually renders it. Drawn at 48 the
 * natural gap is about 2.2 units and it looks right; at 20px that is 0.9 of a real
 * pixel and the four cells close up into a block. Widening it to 2.8 (and taking
 * the cell down to 6.6 to pay for it) separates them at 20px and costs nothing
 * large. Compared by rasterising 2.2 / 2.8 / 3.2 at 20 and 24px and looking, not
 * by picking a number. The 16px favicon needs a wider gap still — see
 * scripts/gen-icons.mjs, which is the only caller that overrides these.
 */
export function lattice({ cell = 6.6, gap = 2.8, radius = 1.6 } = {}) {
  const span = cell * 2 + gap;
  const x0 = 24 - span / 2;
  const y0 = 24.5 - span / 2;
  const origins = [
    [x0, y0],
    [x0 + cell + gap, y0],
    [x0, y0 + cell + gap],
    [x0 + cell + gap, y0 + cell + gap],
  ];
  return {
    /** All four cells as one path — union it with SHIELD under fill-rule="evenodd" to knock them out. */
    path: origins.map(([x, y]) => roundedRect(x, y, cell, radius)).join(" "),
    origins,
    /** The emerald is always the lower-right cell. */
    accent: origins[3],
    cell,
    radius,
  };
}

/**
 * The stroke width a stroked cut would use, kept only as the record of a measured
 * decision: the shield can be drawn filled-with-knockouts (what every surface
 * ships) or stroked-with-filled-cells. Both were rasterised at 16/20/24/40px, and
 * below ~28px this stroke and the lattice merge into stripes — which is every size
 * this product actually renders the mark at, including the OG card once a feed
 * scales it down. Nothing imports this; if you build a large-format surface that
 * warrants the stroked cut, this is the weight it was drawn at.
 */
export const OUTLINE_STROKE = 2.8;
