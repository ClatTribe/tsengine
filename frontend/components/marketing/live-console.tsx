"use client";

// The "live" hero centerpiece — an animated agent console that streams the loop as if it's running
// right now: detect → prove → fix → approve → sign. Scripted, deterministic sequence (an illustrative
// product preview, clearly labelled — never claims real customer data). Pure React + setInterval, no
// deps. Honors prefers-reduced-motion via the CSS keyframes' global guard.

import { useEffect, useState } from "react";

type Kind = "scan" | "found" | "verify" | "fix" | "approve" | "sign";

interface Ev {
  kind: Kind;
  tool: string;
  msg: string;
}

// One full pass through the loop, in order. Realistic but generic — no real target, no real data.
const SCRIPT: Ev[] = [
  { kind: "scan", tool: "katana", msg: "crawled 142 routes on the web app" },
  { kind: "scan", tool: "semgrep", msg: "static analysis across 38k LOC" },
  { kind: "found", tool: "sqlmap", msg: "SQL injection candidate · /api/search?q=" },
  { kind: "verify", tool: "agent", msg: "boolean-differential probe — exploit confirmed" },
  { kind: "fix", tool: "agent", msg: "opened PR #214 · parameterized the query" },
  { kind: "scan", tool: "prowler", msg: "CIS benchmark across the AWS account" },
  { kind: "found", tool: "prowler", msg: "S3 bucket public-read · customer-exports" },
  { kind: "fix", tool: "agent", msg: "staged: enable Block Public Access (4 flags)" },
  { kind: "approve", tool: "you", msg: "approved — change applied, session signed" },
  { kind: "scan", tool: "trivy", msg: "dependency + image CVE sweep" },
  { kind: "found", tool: "govulncheck", msg: "reachable RCE in a bundled dependency" },
  { kind: "verify", tool: "agent", msg: "call path traced to the vulnerable sink" },
  { kind: "sign", tool: "evidence", msg: "ed25519 evidence pack · 14 frameworks mapped" },
];

const META: Record<Kind, { label: string; dot: string; chip: string }> = {
  scan: { label: "SCAN", dot: "bg-accent", chip: "text-accent" },
  found: { label: "FOUND", dot: "bg-high", chip: "text-high" },
  verify: { label: "VERIFY", dot: "bg-accent", chip: "text-accent" },
  fix: { label: "FIX", dot: "bg-pulse", chip: "text-pulse" },
  approve: { label: "APPROVE", dot: "bg-pulse", chip: "text-pulse" },
  sign: { label: "SIGNED", dot: "bg-pulse", chip: "text-pulse" },
};

const VISIBLE = 6;

export function LiveConsole() {
  const [rows, setRows] = useState<{ ev: Ev; id: number }[]>(() =>
    SCRIPT.slice(0, VISIBLE).map((ev, i) => ({ ev, id: i })),
  );

  useEffect(() => {
    let i = VISIBLE;
    const t = setInterval(() => {
      const ev = SCRIPT[i % SCRIPT.length];
      const id = i;
      i += 1;
      setRows((prev) => [...prev.slice(-(VISIBLE - 1)), { ev, id }]);
    }, 1900);
    return () => clearInterval(t);
  }, []);

  return (
    <div className="card overflow-hidden p-0 shadow-elevated">
      {/* console chrome */}
      <div className="flex items-center gap-2 border-b border-border bg-surface-2/60 px-4 py-2.5">
        <span className="flex gap-1.5">
          <span className="h-2.5 w-2.5 rounded-full bg-critical/50" />
          <span className="h-2.5 w-2.5 rounded-full bg-medium/50" />
          <span className="h-2.5 w-2.5 rounded-full bg-pulse/50" />
        </span>
        <span className="mono ml-1 text-[11px] text-faint">tensorshield · agent console</span>
        <span className="ml-auto inline-flex items-center gap-1.5 text-[11px] font-semibold text-pulse">
          <span className="pulse-dot" /> Live
        </span>
      </div>

      {/* streaming rows */}
      <div className="relative min-h-[268px] bg-surface px-1.5 py-1.5">
        {/* faint scan beam for "it's working" motion */}
        <div className="pointer-events-none absolute inset-x-0 top-0 h-8 animate-scanline bg-gradient-to-b from-accent/[0.06] to-transparent" />
        {rows.map(({ ev, id }) => {
          const m = META[ev.kind];
          return (
            <div key={id} className="flex animate-row-in items-center gap-2.5 rounded-lg px-2.5 py-1.5">
              <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${m.dot}`} />
              <span className={`mono w-[58px] shrink-0 text-[10px] font-semibold ${m.chip}`}>{m.label}</span>
              <span className="mono shrink-0 text-[11px] text-ink">{ev.tool}</span>
              <span className="truncate text-[12px] text-muted">{ev.msg}</span>
            </div>
          );
        })}
      </div>

      <div className="border-t border-border bg-surface-2/40 px-4 py-2 text-center text-[10px] text-faint">
        Illustrative preview · detect → prove → fix → approve → sign
      </div>
    </div>
  );
}
