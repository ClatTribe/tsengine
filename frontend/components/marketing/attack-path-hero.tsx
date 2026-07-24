// The hero centerpiece for the cross-surface wedge. The product's whole thesis in one picture: a leaked
// secret in CODE and a breached SaaS login both bridge — via a REAL shared entity (an ARN, an email) —
// through cloud IAM to your cloud root. All roads lead to cloud root, and one AI engineer walks + shuts
// every one. Illustrative (generic example, never a real customer's data). Pure CSS animation: the three
// edges draw in; the global prefers-reduced-motion guard (globals.css) snaps them to their END state
// (fully drawn), so reduced-motion users still see the whole graph. The SVG viewBox scales the graph down
// on mobile; the edge labels hide below 420px (see .ap-edge-label) so the node labels stay legible.
import type { CSSProperties } from "react";

export function AttackPathHero() {
  return (
    <div className="card animate-fade-rise p-4 sm:p-5">
      <div className="mb-2 flex items-center gap-2 px-1 text-[11px] font-medium uppercase tracking-wider text-faint">
        <span className="pulse-dot" /> Example · how the chain forms
      </div>

      <svg viewBox="0 0 526 264" className="w-full" role="img" aria-labelledby="aph-t aph-d">
        <title id="aph-t">Cross-surface attack path</title>
        <desc id="aph-d">
          A leaked AWS key in code and a breached SaaS login both bridge through an over-permissioned
          cloud IAM user to reach cloud root.
        </desc>
        <defs>
          <marker id="aph-arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse">
            <path d="M0 0L10 5L0 10z" className="fill-accent" />
          </marker>
        </defs>

        {/* edges — drawn in, staggered. --len ≥ true path length so the "from" is fully hidden. */}
        <path d="M156 55 C190 55 188 104 214 116" fill="none" strokeWidth={2} className="draw-path stroke-accent" style={{ "--len": "230" } as CSSProperties} markerEnd="url(#aph-arrow)" />
        <path d="M156 185 C190 185 188 136 214 124" fill="none" strokeWidth={2} className="draw-path draw-path-2 stroke-accent" style={{ "--len": "230" } as CSSProperties} markerEnd="url(#aph-arrow)" />
        <path d="M334 120 L414 120" fill="none" strokeWidth={2} className="draw-path draw-path-3 stroke-accent" style={{ "--len": "80" } as CSSProperties} markerEnd="url(#aph-arrow)" />

        {/* edge labels — hidden < 420px */}
        <text x="186" y="80" className="ap-edge-label fill-muted" fontSize="10.5" textAnchor="middle">shared ARN</text>
        <text x="186" y="160" className="ap-edge-label fill-muted" fontSize="10.5" textAnchor="middle">same email</text>
        <text x="374" y="110" className="ap-edge-label fill-muted" fontSize="10.5" textAnchor="middle">assume role</text>

        {/* entry: code */}
        <g className="node-pop">
          <rect x="6" y="30" width="150" height="50" rx="12" className="fill-surface stroke-border" strokeWidth={1} />
          <text x="24" y="55" className="fill-ink" fontSize="14" fontWeight="500">code</text>
          <text x="24" y="71" className="fill-muted" fontSize="11">leaked AWS key</text>
        </g>
        {/* entry: SaaS */}
        <g className="node-pop node-pop-2">
          <rect x="6" y="160" width="150" height="50" rx="12" className="fill-surface stroke-border" strokeWidth={1} />
          <text x="24" y="185" className="fill-ink" fontSize="14" fontWeight="500">SaaS</text>
          <text x="24" y="201" className="fill-muted" fontSize="11">breached login</text>
        </g>
        {/* bridge: cloud IAM */}
        <g className="node-pop node-pop-3">
          <rect x="214" y="95" width="120" height="50" rx="12" className="fill-accent-soft stroke-accent" strokeOpacity={0.4} strokeWidth={1} />
          <text x="230" y="120" className="fill-accent" fontSize="14" fontWeight="500">cloud IAM</text>
          <text x="230" y="135" className="fill-accent" fontSize="11" opacity={0.8}>over-permissioned</text>
        </g>
        {/* crown jewel: cloud root — soft halo + filled accent (the destination, strongest) */}
        <g className="node-pop node-pop-4">
          <rect x="414" y="89" width="108" height="62" rx="15" className="fill-accent" opacity={0.12} />
          <rect x="422" y="95" width="92" height="50" rx="12" className="fill-accent" />
          <text x="438" y="120" fill="#fff" fontSize="14" fontWeight="600">cloud root</text>
          <text x="438" y="135" fill="#fff" fontSize="11" opacity={0.85}>admin</text>
        </g>
      </svg>

      {/* the fix half — find AND fix, with the human gate */}
      <div className="mt-3 flex items-center gap-2 border-t border-border pt-3 text-[13px] text-muted">
        <span className="inline-flex h-4 w-4 items-center justify-center rounded-full bg-pulse/15 text-pulse">
          <svg viewBox="0 0 24 24" className="h-3 w-3" fill="none" stroke="currentColor" strokeWidth={3}><path d="M5 13l4 4L19 7" strokeLinecap="round" strokeLinejoin="round" /></svg>
        </span>
        AI engineer: revoke the key, restrict the IAM role <span className="text-faint">· you approve</span>
      </div>
    </div>
  );
}
