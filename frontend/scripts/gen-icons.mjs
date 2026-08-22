// Regenerates the binary brand icons from the Lattice Shield geometry.
//
//   node scripts/gen-icons.mjs        (from frontend/)
//
// Why this exists: app/favicon.ico and public/logo-512.png are BINARY, so they
// cannot be reviewed in a diff and will silently drift from the mark. This script
// is the single place they come from, and it imports the geometry from
// lib/brand-mark.mjs rather than restating it — so "the icon no longer matches the
// logo" is not a state this repo can reach without someone editing both.
// If you change the mark, re-run this and commit the output.
//
// Why a static /favicon.ico at all, when app/icon.tsx already renders one:
// Google requires the favicon it shows in search results to live at a URL that
// does not change. next/og serves the dynamic icon at /icon?<content-hash>, so
// the URL moves every time the artwork does. A static app/favicon.ico is served
// at the fixed /favicon.ico — the URL Google's favicon crawler looks for first.
//
// Sizes: 16 and 32 are the browser tab. 48 and 96 are for Google, which wants the
// favicon to be a multiple of 48px and rescales from there.

import sharp from "sharp";
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { SHIELD, CHIP, MARK, EMERALD, lattice } from "../lib/brand-mark.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

/**
 * One tile: the chip, with the mark scaled to bleed toward its edge.
 *
 * `accent:false` drops the emerald cell. Below ~24px the cell is under three real
 * pixels and reads as a green smudge rather than a signal, so the small entries
 * are monochrome on purpose — that is what a multi-size icon is for.
 */
function chipSVG({ size, radius = 10, scale = 0.95, accent = true, cells }) {
  const l = lattice(cells);
  const [ax, ay] = l.accent;
  return Buffer.from(
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" width="${size}" height="${size}">` +
      `<rect width="48" height="48" rx="${radius}" fill="${CHIP}"/>` +
      `<g transform="translate(24 24) scale(${scale}) translate(-24 -24)">` +
      `<path fill-rule="evenodd" fill="${MARK}" d="${SHIELD} ${l.path}"/>` +
      (accent
        ? `<rect x="${ax}" y="${ay}" width="${l.cell}" height="${l.cell}" rx="${l.radius}" fill="${EMERALD}"/>`
        : "") +
      `</g></svg>`,
  );
}

const png = (opts) => sharp(chipSVG(opts)).png({ compressionLevel: 9 }).toBuffer();

/**
 * A PNG-payload .ico: 6-byte header, one 16-byte directory entry per size, then
 * the PNG bytes. Every browser in current use and Google's crawler read this form.
 */
function buildICO(images) {
  const header = Buffer.alloc(6);
  header.writeUInt16LE(0, 0); // reserved
  header.writeUInt16LE(1, 2); // 1 = icon
  header.writeUInt16LE(images.length, 4);

  const dir = Buffer.alloc(16 * images.length);
  let offset = header.length + dir.length;
  images.forEach(({ size, data }, i) => {
    const e = i * 16;
    dir.writeUInt8(size >= 256 ? 0 : size, e + 0); // width  (0 means 256)
    dir.writeUInt8(size >= 256 ? 0 : size, e + 1); // height
    dir.writeUInt8(0, e + 2); // palette size — 0 for truecolour
    dir.writeUInt8(0, e + 3); // reserved
    dir.writeUInt16LE(1, e + 4); // colour planes
    dir.writeUInt16LE(32, e + 6); // bits per pixel
    dir.writeUInt32LE(data.length, e + 8);
    dir.writeUInt32LE(offset, e + 12);
    offset += data.length;
  });

  return Buffer.concat([header, dir, ...images.map((i) => i.data)]);
}

// Per-size CUT, not one drawing resampled. Two things move, both found by
// rasterising the icon and looking at it rather than by prediction:
//
//   scale — the shield carries its own margin inside the 48 box, so at 16px that
//           margin plus the chip's left the mark about ten real pixels wide and it
//           read as a smudge. The small entries bleed it toward the chip edge.
//   cells — even the small-tuned default gap of 2.8 is under a real pixel at 16px,
//           so that entry alone widens it further and the lattice resolves.
//
// This is an optical size, the way a text cut of a typeface differs from its
// display cut. The shield and the 2x2 arrangement are identical at every size.
const icoSizes = [
  { size: 16, radius: 9, scale: 1.14, accent: false, cells: { cell: 6.4, gap: 3.4, radius: 1.5 } },
  { size: 32, radius: 10, scale: 1.04, accent: false },
  { size: 48, radius: 10, scale: 0.98, accent: true },
  { size: 96, radius: 10, scale: 0.95, accent: true },
];

const out = [];
mkdirSync(join(root, "public"), { recursive: true });

// --- /favicon.ico : the stable URL Google indexes ---------------------------
const entries = [];
for (const s of icoSizes) entries.push({ size: s.size, data: await png(s) });
const ico = buildICO(entries);
writeFileSync(join(root, "app", "favicon.ico"), ico);
out.push(`app/favicon.ico       ${entries.map((e) => e.size).join("/")}px   ${ico.length} bytes`);

// --- /logo-512.png : the square logo schema.org Organization.logo points at ---
const logo512 = await png({ size: 512, radius: 108, accent: true });
writeFileSync(join(root, "public", "logo-512.png"), logo512);
out.push(`public/logo-512.png   512px           ${logo512.length} bytes`);

console.log(out.join("\n"));
