// The hero centerpiece for the cross-surface wedge. The product's whole thesis in one picture: a leaked
// secret in CODE and a breached SaaS login both bridge — via a REAL shared entity (an ARN, an email) —
// through cloud IAM to your cloud root. All roads lead to cloud root, and one AI engineer walks + shuts
// every one. Illustrative (generic example, never a real customer's data). Pure CSS animation: the three
// edges draw in; the global prefers-reduced-motion guard (globals.css) snaps them to their END state
// (fully drawn), so reduced-motion users still see the whole graph. The SVG viewBox scales the graph down
// on mobile; the edge labels hide below 420px (see .ap-edge-label) so the node labels stay legible.
//
// LABELS ARE PLAIN ENGLISH ON PURPOSE. This graphic is the FIRST thing a visitor sees, and it used to
// read "shared ARN → cloud IAM (over-permissioned) → assume role → cloud root". Every one of those is
// correct AWS vocabulary and none of it means anything to the founder we are selling to — the person
// who has an enterprise deal stuck in security review and no security team. A picture that has to be
// decoded is not doing the job of a hero. The chain is identical; only the words changed, and the
// precise terms still live one click away on /cloud-security for the engineer who wants them.
import type { CSSProperties } from "react";

export function AttackPathHero() {
  return (
    <div className="card animate-fade-rise p-4 sm:p-5">
      <div className="mb-2 flex items-center gap-2 px-1 text-[11px] font-medium uppercase tracking-wider text-faint">
        <span className="pulse-dot" /> Example · how two small problems become one big one
      </div>

      <svg viewBox="0 0 526 264" className="w-full" role="img" aria-labelledby="aph-t aph-d">
        <title id="aph-t">Cross-surface attack path</title>
        <desc id="aph-d">
          A password left in code and a stolen staff login both lead, through one cloud login that has
          too much access, to full control of the company's cloud.
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

        {/* edge labels — hidden < 420px.
            KEEP THESE SHORT (≈9 chars at 10.5px). They sit in the ~58px gap between the entry boxes
            (ending x=156) and the bridge node (starting x=214); a longer label silently overlaps BOTH
            neighbours instead of wrapping, which is how "same cloud account" shipped on top of the
            nodes. Plain English still wins — it just has to fit. SVG <text> does NOT wrap or clip, so a
            too-long label silently draws over its neighbour; the node sublabels have the same constraint
            (the bridge node is 120px wide, the destination 92px). Measure, do not eyeball. */}
        <text x="186" y="80" className="ap-edge-label fill-muted" fontSize="10.5" textAnchor="middle">same key</text>
        <text x="186" y="160" className="ap-edge-label fill-muted" fontSize="10.5" textAnchor="middle">same user</text>
        <text x="374" y="110" className="ap-edge-label fill-muted" fontSize="10.5" textAnchor="middle">unlocks</text>

        {/* entry: code */}
        <g className="node-pop">
          <rect x="6" y="30" width="150" height="50" rx="12" className="fill-surface stroke-border" strokeWidth={1} />
          <text x="24" y="55" className="fill-ink" fontSize="14" fontWeight="500">code</text>
          <text x="24" y="71" className="fill-muted" fontSize="11">a password left in code</text>
        </g>
        {/* entry: SaaS */}
        <g className="node-pop node-pop-2">
          <rect x="6" y="160" width="150" height="50" rx="12" className="fill-surface stroke-border" strokeWidth={1} />
          <text x="24" y="185" className="fill-ink" fontSize="14" fontWeight="500">SaaS</text>
          <text x="24" y="201" className="fill-muted" fontSize="11">a stolen staff login</text>
        </g>
        {/* bridge: cloud IAM */}
        <g className="node-pop node-pop-3">
          <rect x="214" y="95" width="120" height="50" rx="12" className="fill-accent-soft stroke-accent" strokeOpacity={0.4} strokeWidth={1} />
          <text x="230" y="120" className="fill-accent" fontSize="13.5" fontWeight="500">a cloud login</text>
          <text x="230" y="135" className="fill-accent" fontSize="11" opacity={0.8}>too much access</text>
        </g>
        {/* crown jewel: cloud root — soft halo + filled accent (the destination, strongest) */}
        <g className="node-pop node-pop-4">
          <rect x="414" y="89" width="108" height="62" rx="15" className="fill-accent" opacity={0.12} />
          <rect x="422" y="95" width="92" height="50" rx="12" className="fill-accent" />
          <text x="434" y="120" fill="#fff" fontSize="13.5" fontWeight="600">everything</text>
          <text x="434" y="135" fill="#fff" fontSize="11" opacity={0.85}>full access</text>
        </g>
      </svg>

      {/* the fix half — find AND fix, with the human gate */}
      <div className="mt-3 flex items-center gap-2 border-t border-border pt-3 text-[13px] text-muted">
        <span className="inline-flex h-4 w-4 items-center justify-center rounded-full bg-pulse/15 text-pulse">
          <svg viewBox="0 0 24 24" className="h-3 w-3" fill="none" stroke="currentColor" strokeWidth={3}><path d="M5 13l4 4L19 7" strokeLinecap="round" strokeLinejoin="round" /></svg>
        </span>
        AI engineer: kills the leaked password and cuts the over-broad access <span className="text-faint">· you approve first</span>
      </div>
    </div>
  );
}
