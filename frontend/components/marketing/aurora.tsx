// AuroraBackdrop — the shared animated hero backdrop: two slow-drifting blurred gradient blobs over a
// faint masked grid. Server component (pure markup, no state). Drop inside a `relative overflow-hidden`
// section as the first child; the hero content goes after it in a `relative` wrapper so it paints on
// top. Motion comes from the `aurora` keyframe, which the global prefers-reduced-motion guard stills.

export function AuroraBackdrop({ className }: { className?: string }) {
  return (
    <div className={`pointer-events-none absolute inset-0 ${className ?? ""}`} aria-hidden>
      <div className="absolute -top-24 left-[20%] h-[26rem] w-[26rem] -translate-x-1/2 rounded-full bg-accent/15 blur-[110px] animate-aurora" />
      <div className="absolute -top-16 right-[16%] h-[22rem] w-[22rem] translate-x-1/2 rounded-full bg-pulse/12 blur-[110px] animate-aurora [animation-delay:-7s]" />
      <div className="absolute inset-0 bg-[linear-gradient(to_right,rgba(16,24,40,0.025)_1px,transparent_1px),linear-gradient(to_bottom,rgba(16,24,40,0.025)_1px,transparent_1px)] bg-[size:44px_44px] [mask-image:radial-gradient(ellipse_at_top,black,transparent_72%)]" />
    </div>
  );
}
