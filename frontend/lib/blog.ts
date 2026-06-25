// The blog content model + posts. Content lives as structured blocks (no MDX dependency) rendered by
// the post page with the marketing design system. Each post is tagged to a funnel stage (ToFu /
// MoFu / BoFu) and links to the matching free tool — so the blog is the SEO/awareness engine that
// feeds the scanner (ToFu), the readiness self-assessment (MoFu), and the trial (BoFu).

export type FunnelStage = "ToFu" | "MoFu" | "BoFu";

export const STAGE_META: Record<FunnelStage, { label: string; blurb: string }> = {
  ToFu: { label: "Awareness", blurb: "Find out where you stand" },
  MoFu: { label: "Consideration", blurb: "Get ready, the right way" },
  BoFu: { label: "Decision", blurb: "Close the deal" },
};

export type Block =
  | { t: "p"; text: string }
  | { t: "h2"; text: string }
  | { t: "ul"; items: string[] }
  | { t: "cta"; text: string; href: string; label: string };

export interface Post {
  slug: string;
  title: string;
  description: string;
  stage: FunnelStage;
  date: string; // ISO
  readMins: number;
  body: Block[];
}

export const POSTS: Post[] = [
  {
    slug: "pass-enterprise-security-questionnaire",
    title: "Will you pass an enterprise security questionnaire? The checks buyers run first",
    description:
      "Before a big customer signs, their security team runs a checklist against your domain. Here are the externally-visible checks that come first — and how to see your own score for free.",
    stage: "ToFu",
    date: "2026-06-20",
    readMins: 5,
    body: [
      { t: "p", text: "The first time most founders think about security is the day a promising deal stalls on a security questionnaire they can't answer. By then it's expensive: the deal slips a quarter while you scramble, and the buyer's trust takes a hit." },
      { t: "p", text: "The good news is that the first round of an enterprise security review is mostly mechanical. Before anyone reads your policies, their security team — or their automated vendor-risk tool — checks a handful of things about your domain and app that are visible from the outside, no access required. If those fail, you start the conversation on the back foot." },
      { t: "h2", text: "The checks that come first" },
      { t: "p", text: "These are the externally-detectable basics that map directly to SOC 2's common criteria and to the questions on almost every vendor security questionnaire (VSQ):" },
      { t: "ul", items: [
        "Email authentication — DMARC, SPF, and DKIM. No DMARC means anyone can spoof email from your domain, and it's one of the first things flagged.",
        "HTTPS everywhere — HTTP redirects to HTTPS, modern TLS, and HSTS so browsers never fall back to plaintext.",
        "Security headers — Content-Security-Policy, X-Frame-Options / frame-ancestors, X-Content-Type-Options.",
        "A documented security contact — a /.well-known/security.txt or a /security page that tells a researcher where to report something.",
        "No live, known vulnerabilities in your shipped dependencies.",
      ] },
      { t: "p", text: "None of these are unusual to miss for a team shipping fast. They just all surface at once the moment a customer's security review begins — and they're the cheapest things in your whole security program to fix." },
      { t: "h2", text: "See your own score in 30 seconds" },
      { t: "p", text: "You don't have to guess. Our free scanner runs exactly these read-only checks against your domain and gives you a grade plus the precise fix for anything that fails — no signup, nothing intrusive, just the public checks anyone could run." },
      { t: "cta", text: "Run the free check on your domain", href: "/scan", label: "Scan my domain" },
      { t: "p", text: "If you score well, you can embed a badge on your site to show enterprise buyers you take this seriously. If you don't, you'll get the copy-paste fix for each gap. Either way you'll know where you stand before a customer tells you." },
    ],
  },
  {
    slug: "soc2-readiness-for-seed-stage-startups",
    title: "SOC 2 for seed-stage startups: a founder's readiness checklist",
    description:
      "You don't need a compliance team to get SOC 2-ready. Here's the founder's-eye view of what a Type I actually requires, in plain English, with a free self-assessment.",
    stage: "MoFu",
    date: "2026-06-22",
    readMins: 7,
    body: [
      { t: "p", text: "Once a deal has stalled on security once, SOC 2 stops being abstract. But the framework is written for auditors, not founders, and the consultancies quoting you five figures aren't incentivized to tell you how much you can do yourself. Here's the plain-English version." },
      { t: "h2", text: "Type I vs Type II — start with Type I" },
      { t: "p", text: "A Type I report says your controls are designed correctly at a point in time. A Type II says they actually operated over a period (usually 3–12 months). For a seed-stage company trying to unblock a deal, a Type I — or even a credible \"SOC 2 in progress\" with evidence — is often enough to keep the conversation alive while you work toward Type II." },
      { t: "h2", text: "The controls that actually matter early" },
      { t: "p", text: "SOC 2's Trust Services Criteria are broad, but the gaps that sink seed-stage companies cluster in a few areas:" },
      { t: "ul", items: [
        "Access control (CC6) — MFA on everything, least-privilege, no shared logins, off-boarding that actually revokes access. This is where most early findings land.",
        "Change management (CC8) — code review before merge, a record of what shipped, separation between who writes and who deploys.",
        "Vulnerability management (CC7) — you scan your code and dependencies, and you fix what's exploitable. Not perfection — a process.",
        "Monitoring (CC7.2) — you'd notice if something broke or someone got in. Logging and alerting that a human actually watches.",
        "Vendor & data (CC6.7 / CC9) — you know which third parties touch your data and what they can do.",
      ] },
      { t: "p", text: "Notice what's not on the list: nothing here requires a dedicated security hire. It requires that the basics are turned on and that you can produce evidence they're turned on." },
      { t: "h2", text: "Evidence is the real work" },
      { t: "p", text: "Auditors don't take your word for it; they ask for evidence. The reason SOC 2 feels heavy isn't the controls — it's collecting screenshots and logs to prove each one. The closer your tooling is to producing that evidence automatically, the cheaper the audit." },
      { t: "h2", text: "Score your own readiness, free" },
      { t: "p", text: "Before you pay anyone, find out how ready you actually are. Our free, no-account readiness self-assessment walks you through the controls above and gives you a readiness score plus the specific gaps to close first." },
      { t: "cta", text: "Take the free SOC 2 readiness self-assessment", href: "/soc2-readiness", label: "Check my readiness" },
      { t: "p", text: "It takes a few minutes, requires no login, and tells you exactly where to start — so you spend money on the gaps that matter, not on a consultant to find them for you." },
    ],
  },
  {
    slug: "security-for-the-sales-cycle",
    title: "Security for the sales cycle: fixing the gaps before they block a deal",
    description:
      "Security is cheaper before a deal stalls than during. Here's how a fractional, AI-run security team closes the gaps a buyer's review will find — without a hire.",
    stage: "BoFu",
    date: "2026-06-24",
    readMins: 6,
    body: [
      { t: "p", text: "Every founder we talk to who got serious about security did so for the same reason: a deal they wanted stalled on a security review they couldn't pass. The lesson isn't \"do security earlier\" in the abstract — it's that the fix is dramatically cheaper before that happens than during a live deal with a customer waiting." },
      { t: "h2", text: "The choice you actually have" },
      { t: "p", text: "When the questionnaire lands, you have three options. Hire a security engineer (slow and expensive at your stage). Pay a consultancy per-engagement (a point-in-time snapshot that's stale by your next deal). Or run a continuous, automated security program that watches your code, cloud, and identity, finds what a buyer's review would find, and fixes it — with you approving anything that matters." },
      { t: "h2", text: "What \"fractional AI security team\" means concretely" },
      { t: "p", text: "TensorShield connects to the systems you already use and runs the work a security engineer would:" },
      { t: "ul", items: [
        "Finds the issues — across code, dependencies, cloud, and identity — and proves which ones are real and actually reachable, instead of dumping a 500-item scanner queue on you.",
        "Maps every finding to the SOC 2 (and PCI, HIPAA, ISO…) control it affects, so your evidence pack writes itself.",
        "Writes the fix — a pull request, a config change, a DNS record — and waits for your approval before anything changes.",
        "Answers the questionnaire — produces the trust-center page and the evidence a buyer's security team asks for.",
      ] },
      { t: "h2", text: "Start where it's free" },
      { t: "p", text: "You can see your externally-visible posture in 30 seconds with no account at all. When you're ready to see the full picture — your code, cloud, and identity — connecting one system is free, and you'll get a prioritized, deal-blocker-first view of exactly what to fix." },
      { t: "cta", text: "See your full posture — free", href: "/signup", label: "Get started free" },
      { t: "p", text: "The next deal that hits a security review shouldn't be the thing that tells you about a gap. Fix it on your schedule, not the buyer's." },
    ],
  },
];

export function postBySlug(slug: string): Post | undefined {
  return POSTS.find((p) => p.slug === slug);
}

export function postsByStage(stage: FunnelStage): Post[] {
  return POSTS.filter((p) => p.stage === stage);
}
