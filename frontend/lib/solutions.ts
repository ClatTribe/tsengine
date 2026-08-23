// solutions.ts is the single source of truth for the Solutions hub.
//
// WHY IT EXISTS. We had 39 marketing pages and 14 of them — every surface page beyond the top three,
// and ALL SIX competitor comparisons — were unreachable from the nav. They were written, indexed by
// Google, and invisible to anyone browsing the site.
//
// The deeper problem was shape, not routing. Every page opens "here is a problem, here is our
// solution", which only works if the visitor already shares our framing. Real buyers arrive with one
// of three different questions, and the hub is organised around those instead of around our product
// taxonomy:
//
//   1. SCENARIO   — "I have to get X done."         (a deadline, a blocked deal, a board ask)
//   2. SURFACE    — "I need to cover Y."            (they know the asset class)
//   3. ALTERNATIVE— "How is this different from Z?" (already evaluating someone)
//
// A visitor should be able to enter through whichever they actually have, and leave through a
// different one — which is what "let them explore multiple problems" means in practice.

export type Lane = {
  slug: string;
  title: string;
  blurb: string;
  items: SolutionLink[];
};

export type SolutionLink = {
  href: string;
  label: string;
  /** The buyer's words, not ours — what they'd type or say. */
  prompt: string;
};

/** SCENARIO — the situation that made them look. Ordered by how often it drives an SMB search. */
export const SCENARIOS: SolutionLink[] = [
  {
    // Routed to /startups rather than /soc2-readiness. The readiness page is a good lead magnet, but
    // it puts a 15-question quiz in front of someone whose deal is stuck today: it tells them how
    // ready they are, when what they came for is the report and the evidence that unblocks the deal.
    // /startups leads with that, and still links out to the free checks for anyone not ready to talk.
    href: "/startups",
    label: "A deal is blocked on a security questionnaire",
    prompt: "Enterprise sent a 200-row questionnaire and we don't know what we'd fail.",
  },
  {
    href: "/frameworks",
    label: "We need SOC 2 / ISO 27001 and have no security team",
    prompt: "An auditor is booked. Nobody here owns compliance.",
  },
  {
    href: "/vapt",
    label: "A customer is asking for a penetration test report",
    prompt: "They want a VAPT report and ours is a year old, or doesn't exist.",
  },
  {
    href: "/ai-security-engineer",
    label: "We have findings nobody has time to triage",
    prompt: "Scanners give us hundreds of alerts. We don't know which five matter.",
  },
  {
    href: "/cross-detection",
    label: "We can't see how a small issue becomes a breach",
    prompt: "Each tool says 'medium'. Nobody can tell us if they chain together.",
  },
  {
    href: "/agent-controls",
    label: "We're adopting AI agents and can't govern them",
    prompt: "Engineers are running coding agents. We don't know what they can reach.",
  },
];

/** SURFACE — for the visitor who already knows which asset class they need covered. */
export const SURFACES: SolutionLink[] = [
  { href: "/cloud-security", label: "Cloud", prompt: "AWS, GCP, Azure — misconfig, attack paths, drift" },
  { href: "/code-security", label: "Code & supply chain", prompt: "SAST, dependencies, secrets, malicious packages" },
  { href: "/saas-posture", label: "Identity & SaaS", prompt: "MFA gaps, OAuth grants, stale access, SSPM" },
  { href: "/web-application-security", label: "Web applications", prompt: "Deployed apps — injection, auth, XSS" },
  { href: "/api-security", label: "APIs", prompt: "REST/GraphQL — BOLA, BFLA, shadow endpoints" },
  { href: "/container-security", label: "Containers", prompt: "Images, base layers, CVEs, Dockerfile hygiene" },
  { href: "/network-security", label: "Network & IPs", prompt: "Exposed ports, services, default credentials" },
  { href: "/dns-domain-security", label: "Domains & DNS", prompt: "Spoofable email, subdomain takeover, certs" },
  { href: "/ci-cd", label: "CI/CD", prompt: "Pull-request checks and merge gating" },
];

/** ALTERNATIVE — they are already evaluating something. Meeting that head-on beats ignoring it. */
export const ALTERNATIVES: SolutionLink[] = [
  { href: "/vs-vanta", label: "vs Vanta", prompt: "Compliance automation — but who finds the vulnerabilities?" },
  { href: "/vs-drata", label: "vs Drata", prompt: "Same question, different logo." },
  { href: "/vs-sprinto", label: "vs Sprinto", prompt: "Built for the same SMB buyer." },
  { href: "/vs-secureframe", label: "vs Secureframe", prompt: "Evidence collection vs evidence generation." },
  { href: "/vs-aikido", label: "vs Aikido", prompt: "Scanner coverage — and what happens after a finding." },
  { href: "/vs-consulting", label: "vs a consultant or vCISO", prompt: "What a person does, and what a system should." },
];

export const LANES: Lane[] = [
  {
    slug: "scenarios",
    title: "Start from what you need to get done",
    blurb:
      "Most people arrive because something forced the issue — a questionnaire, an auditor, a customer, a board. Pick the one that sounds like your week.",
    items: SCENARIOS,
  },
  {
    slug: "surfaces",
    title: "Start from what you need covered",
    blurb: "If you already know the gap, go straight to it. Every surface is scanned by the same engine and rolls into the same evidence.",
    items: SURFACES,
  },
  {
    slug: "alternatives",
    title: "Start from what you're comparing us to",
    blurb:
      "You are probably evaluating something else. These pages are written to be useful even if you pick the other one — including where the other one is the better fit.",
    items: ALTERNATIVES,
  },
];
