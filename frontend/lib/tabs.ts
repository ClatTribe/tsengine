// tabs.ts — the sibling-route tab sets, defined once.
//
// WHY THIS FILE EXISTS. The nav used to carry one row per page: four for the GRC artifacts, three for
// the inventories. That is a catalogue of surfaces, not a product — the person reading it has to know
// what "Program" means before they can decide whether they want it, and the sidebar grows every time a
// page is added.
//
// A row per DESTINATION, with the related artifacts as tabs on it, keeps the same pages reachable in
// the same number of clicks while cutting what the reader has to hold in their head. Defined here
// rather than repeated in each page so the tab strip cannot say different things depending on which tab
// you are standing on — the drift that makes tabbed surfaces feel broken.

export type Tab = { href: string; label: string };

// COMPLIANCE — the audit-readiness outcome. Four genuinely distinct artifacts, not one page sliced
// four ways: the live control posture (findings → controls), the risk register (accept/mitigate
// decisions a named human makes), the external-auditor engagement, and the policy set.
export const COMPLIANCE_TABS: Tab[] = [
  { href: "/compliance", label: "Posture" },
  { href: "/risks", label: "Risks" },
  { href: "/audits", label: "Audits" },
  { href: "/program", label: "Program" },
];

// CONNECTIONS — what you have connected. Inventories, not finding-views: the risk these carry already
// shows up under the AI Security Engineer, so here you see WHAT you have, not what is wrong with it.
export const CONNECTION_TABS: Tab[] = [
  { href: "/assets", label: "Assets" },
  { href: "/posture", label: "Vendors & devices" },
  { href: "/saas-apps", label: "Connected apps" },
];

// SECURITY — the Engineer's output. Issues is the deduplicated one-per-problem list; findings is the
// raw per-tool detail behind it, kept as a tab rather than a destination so nobody has to learn the
// difference between an issue and a finding to use the product.
// The security-analysis surface, grouped as tabs on one destination so a security
// engineer reaches the depth they work in — the prioritized issues, the raw findings,
// how those issues CHAIN into a breach, and what was actually tested — one click from
// each other, without hunting the command palette. (Tabs on a destination, not new
// flat nav rows — same principle as COMPLIANCE_TABS / CONNECTION_TABS.)
export const SECURITY_TABS: Tab[] = [
  { href: "/issues", label: "Issues" },
  { href: "/findings", label: "All findings" },
  { href: "/attack-paths", label: "Attack paths" },
  { href: "/coverage", label: "Coverage" },
  // Verify sits beside Coverage as the other half of "what actually happened": Coverage says what
  // was tested, Verify says what the filter then suppressed — and lets a human overrule it.
  { href: "/verify", label: "Verify" },
  // Your evals completes the trio: Coverage says what was tested, Verify says what was suppressed,
  // and this says whether the setup still agrees with your own experts about your own findings.
  { href: "/eval", label: "Your evals" },
];
