import { ImageResponse } from "next/og";
import { SHIELD, CHIP, MARK, EMERALD, lattice } from "@/lib/brand-mark.mjs";

// The iOS "add to home screen" icon — the same Lattice Shield from
// lib/brand-mark.mjs, at the Apple touch-icon size. iOS applies its own rounded
// mask, so the chip is drawn square-cornered here and let the OS shape it.
export const size = { width: 180, height: 180 };
export const contentType = "image/png";

const L = lattice();

export default function AppleIcon() {
  const [ax, ay] = L.accent;
  return new ImageResponse(
    (
      <div style={{ width: "100%", height: "100%", display: "flex" }}>
        <svg width="180" height="180" viewBox="0 0 48 48" fill="none">
          <rect width="48" height="48" fill={CHIP} />
          <g transform="translate(24 24) scale(0.88) translate(-24 -24)">
            <path fillRule="evenodd" fill={MARK} d={`${SHIELD} ${L.path}`} />
            <rect x={ax} y={ay} width={L.cell} height={L.cell} rx={L.radius} fill={EMERALD} />
          </g>
        </svg>
      </div>
    ),
    { ...size },
  );
}
