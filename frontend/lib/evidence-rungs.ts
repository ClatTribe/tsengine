// evidence-rungs.ts mirrors pkg/types/evidencerung.go — ADR 0029 D2d.
//
// WHY A MIRROR AND NOT PROSE. The marketing pages were claiming that we prove findings across code,
// cloud, identity, web, API and containers. The engine EXPLOITS on two of those, asks the provider
// on one, analyses the code on one, and reports a scanner's word on the rest. That gap is not a
// wording problem — it is the product claiming a capability it does not have on four surfaces — and
// prose alone would drift back the first time someone rewrote a hero.
//
// So the ladder lives here as data, mirrored from the engine's own enum, and a Go guard
// (internal/icpcheck) fails if the two disagree. Marketing cannot advertise a rung the engine cannot
// reach, and a rung the engine gains does not silently stay unadvertised.
//
// Keep the `id` values byte-identical to the Go constants.

export type EvidenceRungID =
  | "exploited"
  | "provider_confirmed"
  | "reachability_confirmed"
  | "corroborated"
  | "scanner_reported";

export type EvidenceRung = {
  id: EvidenceRungID;
  /** What we did, in the customer's words. */
  act: string;
  /** Which surfaces this rung is actually available on today. */
  surfaces: string;
  /** The limit of the claim — what this rung does NOT establish. */
  limit: string;
  /** True for the one rung that entitles anyone to say "exploitable". */
  claimsExploitability?: boolean;
};

export const EVIDENCE_RUNGS: EvidenceRung[] = [
  {
    id: "exploited",
    act: "We ran the attack and it worked",
    surfaces: "Web apps and APIs",
    limit:
      "Only inside limits you authorise, and only where a deterministic check can confirm the attempt actually succeeded.",
    claimsExploitability: true,
  },
  {
    id: "provider_confirmed",
    act: "We asked your cloud provider and it said yes",
    surfaces: "AWS",
    limit:
      "This confirms the permission exists, not that anyone could use it end to end. It is not the same as breaking in, and we never call it that.",
  },
  {
    id: "reachability_confirmed",
    act: "We read your code and found the path to it",
    surfaces: "Dependencies in connected repositories",
    limit:
      "It shows your code can reach the vulnerable package. Whether the specific flaw is triggerable is a further question.",
  },
  {
    id: "corroborated",
    act: "Two or more independent tools reported the same thing",
    surfaces: "Every surface",
    limit: "Agreement between scanners, not a demonstration.",
  },
  {
    id: "scanner_reported",
    act: "One scanner matched a pattern",
    surfaces: "Every surface",
    limit:
      "A lead worth looking at, and where most findings honestly sit. We label it rather than dressing it up.",
  },
];

/**
 * RUNG_SHORT is the badge text — what fits beside a severity chip.
 *
 * Deliberately not the raw id: "provider_confirmed" is our word, and a customer reading a badge
 * should get the claim, not the enum. The full sentence lives in the tooltip.
 */
export const RUNG_SHORT: Record<EvidenceRungID, string> = {
  exploited: "exploited",
  provider_confirmed: "provider-confirmed",
  reachability_confirmed: "reachable in your code",
  corroborated: "corroborated",
  scanner_reported: "scanner-reported",
};

/** RUNG_TOOLTIP states the limit of the claim, which is the half a badge cannot carry. */
export const RUNG_TOOLTIP: Record<EvidenceRungID, string> = Object.fromEntries(
  EVIDENCE_RUNGS.map((r) => [r.id, `${r.act}. ${r.limit}`]),
) as Record<EvidenceRungID, string>;
