// ConfidencePill renders the FP-control signal from a finding's REAL verification field — never a hardcoded
// label. Shared so every agent-output surface (cloud-engineer, osint, pentest) holds the same
// no-false-positive bar the core findings/incidents tabs enforce: verified (exploit-proven) → green,
// corroborated (≥2 independent tools) → accent, anything still unconfirmed → "confirm". No field → no pill
// (we never imply a confidence the engine didn't record).
export function ConfidencePill({ verification, confidence }: { verification?: string; confidence?: number }) {
  if (!verification) return null;
  const pct = confidence ? ` ${Math.round(confidence * 100)}%` : "";
  if (verification === "verified")
    return (
      <span className="rounded-md border border-pulse/40 bg-pulse/10 px-1.5 py-0.5 text-[10px] font-medium text-pulse" title={`Exploit-verified${pct ? ` · confidence${pct}` : ""}`}>
        verified{pct}
      </span>
    );
  if (verification === "corroborated")
    return (
      <span className="rounded-md border border-accent/30 bg-accent-soft px-1.5 py-0.5 text-[10px] font-medium text-accent" title={`Corroborated by ≥2 independent tools${pct ? ` · confidence${pct}` : ""}`}>
        corroborated{pct}
      </span>
    );
  return (
    <span className="rounded-md border border-medium/40 bg-medium/10 px-1.5 py-0.5 text-[10px] font-medium text-medium" title={`Single-tool match — confirm before acting${pct ? ` · confidence${pct}` : ""}`}>
      confirm{pct}
    </span>
  );
}
