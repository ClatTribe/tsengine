// Content for the competitor-comparison SEO pages (/vs-<competitor>). HONEST by policy (§10): each entry
// names what the competitor is genuinely strong at before positioning our real differences. We never
// fabricate a competitor weakness. Our consistent, true edge: we're the security ENGINE + compliance in one
// (not just an evidence-collector wired to your other tools), exploitation-proven pentest is built in, the
// detection is OSS-transparent, and the human-in-the-loop (vCISO / auditor liaison / pentester) can be your
// team, ours (managed), or an MSP's — the two-GTM model nobody else packages.
//
// Rendered by app/(marketing)/vs-[competitor]/page.tsx via <ComparisonPage data={COMPETITORS.<key>} />.

export type CompareRow = { dim: string; us: string; them: string };
export type CompetitorPage = {
  slug: string; // e.g. "vs-vanta"
  name: string; // "Vanta"
  category: string; // hero badge
  h1: string;
  sub: string;
  theirStrengths: string[]; // honest — what they're good at
  rows: CompareRow[]; // the comparison table
  edges: { t: string; d: string }[]; // our genuine differentiators
  chooseThem: string; // honest "pick them if…"
  chooseUs: string; // "pick us if…"
  faq: [string, string][];
  seoTitle: string;
  seoDesc: string;
};

const PENTEST_EDGE = { t: "A real pentest is built in", d: "Exploitation-proven testing on your assets with a named human sign-off — not a checkbox that says 'get a pentest from a vendor'." };
const TWO_GTM_EDGE = { t: "The expert is included — or yours", d: "Run it yourself, have our named vCISO/auditor-liaison/pentester run it for you (managed), or deliver it to clients as an MSP. The human-in-the-loop layer nobody else packages." };
const OSS_EDGE = { t: "OSS-transparent detection", d: "Findings come from best-in-class open-source scanners (nuclei, semgrep, trivy, prowler…), wrapped — you can see and reproduce exactly what ran. No black box." };

export const COMPETITORS: Record<string, CompetitorPage> = {
  vanta: {
    slug: "vs-vanta",
    name: "Vanta",
    category: "vs. Vanta · compliance automation",
    h1: "TensorShield vs. Vanta",
    sub: "Vanta pioneered compliance automation and does it well. But it's an evidence-collector that wires into your other security tools — it isn't the security engine, it doesn't run a pentest, and it doesn't hand you an expert. We're both, in one.",
    theirStrengths: [
      "A mature, polished compliance-automation product with a large customer base",
      "Hundreds of integrations for automated evidence collection",
      "An established auditor and MSP partner network, plus a Trust Center",
      "Strong brand recognition that carries weight with enterprise buyers",
    ],
    rows: [
      { dim: "Compliance frameworks", us: "22 frameworks, control-mapped from real findings", them: "Broad framework coverage (category leader)" },
      { dim: "Security scanning", us: "Built-in: code, cloud, web, API, container, identity", them: "Integrates your other scanners; not a scanner itself" },
      { dim: "Penetration testing", us: "Exploitation-proven, built in, named sign-off", them: "Not included — you buy a pentest separately" },
      { dim: "The expert (vCISO/auditor)", us: "Optional managed expert, or your team, or an MSP", them: "You bring your own; marketplace referral" },
      { dim: "Detection transparency", us: "OSS-transparent, reproducible", them: "Proprietary checks" },
      { dim: "Evidence", us: "Signed, tamper-evident attestation", them: "Automated evidence collection" },
    ],
    edges: [
      { t: "Security AND compliance, one engine", d: "Vanta shows you're compliant by collecting evidence from tools you already pay for. We're the tool too — real scanning across eight asset types feeds the same evidence." },
      PENTEST_EDGE,
      TWO_GTM_EDGE,
    ],
    chooseThem: "You're an established company that already owns a full security stack + a vCISO, want the most mature compliance-automation brand, and just need evidence collection wired together.",
    chooseUs: "You're a founder who needs the actual security work done AND the compliance evidence AND (optionally) an expert to run it — without assembling three separate vendors.",
    faq: [
      ["Is TensorShield a Vanta alternative?", "Yes — for founders who want security scanning, penetration testing, and compliance evidence in one product, optionally with a managed expert. Vanta is excellent at compliance automation but expects you to bring your own scanners, pentest, and security leadership."],
      ["Does TensorShield do automated evidence collection like Vanta?", "Yes — findings across your code, cloud, identity, and apps map to controls automatically and roll up into a signed evidence pack. The difference is the findings are ours (we scan), not just imported from other tools."],
      ["Can you get me SOC 2 like Vanta?", "We get you audit-ready and quarterback the independent auditor. As with Vanta, the attestation itself must come from a licensed CPA firm — neither vendor can issue the report."],
    ],
    seoTitle: "TensorShield vs. Vanta — Security + Compliance in One | TensorShield",
    seoDesc: "An honest TensorShield vs. Vanta comparison. Vanta automates compliance evidence; TensorShield is the security engine + compliance + a built-in pentest + an optional managed expert. See the differences.",
  },
  drata: {
    slug: "vs-drata",
    name: "Drata",
    category: "vs. Drata · compliance automation",
    h1: "TensorShield vs. Drata",
    sub: "Drata is a strong, well-loved compliance-automation platform with deep continuous control monitoring. Like Vanta, it follows the evidence model — it monitors and maps, but it isn't the scanner, the pentest, or the expert. We bring all three.",
    theirStrengths: [
      "Excellent continuous-control-monitoring and a clean product experience",
      "Large integration catalog for automated evidence",
      "Established auditor network and a polished Trust Center",
      "Well-regarded support and onboarding for compliance teams",
    ],
    rows: [
      { dim: "Continuous monitoring", us: "Continuous re-scan + incident detection", them: "Continuous control monitoring (strength)" },
      { dim: "Security scanning", us: "Built-in across 8 asset types", them: "Integrates your scanners; not a scanner" },
      { dim: "Penetration testing", us: "Exploitation-proven, built in", them: "Not included — buy separately" },
      { dim: "The expert", us: "Optional managed vCISO / auditor liaison", them: "Bring your own" },
      { dim: "Frameworks", us: "22, mapped from real findings", them: "Broad (category leader)" },
      { dim: "Detection transparency", us: "OSS-transparent, reproducible", them: "Proprietary" },
    ],
    edges: [
      { t: "We do the security, not just watch it", d: "Drata monitors controls and collects evidence from your stack. We generate the evidence by actually scanning — then monitor it continuously." },
      PENTEST_EDGE,
      TWO_GTM_EDGE,
    ],
    chooseThem: "You have a security team and stack already, want best-in-class continuous control monitoring, and need a mature compliance brand for enterprise buyers.",
    chooseUs: "You want one product that finds the vulnerabilities, proves them with a pentest, maps them to your frameworks, and — if you want — comes with the expert to run it.",
    faq: [
      ["Is TensorShield a Drata alternative?", "For founders who want security + pentest + compliance in one (optionally with a managed expert), yes. Drata is a great fit if you already have your own scanners, pentest vendor, and security leadership and primarily need control monitoring + evidence."],
      ["Does TensorShield monitor controls continuously like Drata?", "Yes — every tenant is re-scanned on a cadence and changes open incidents automatically. We add the detection itself (real scanning + a built-in pentest) on top of the monitoring."],
    ],
    seoTitle: "TensorShield vs. Drata — Honest Comparison | TensorShield",
    seoDesc: "TensorShield vs. Drata, honestly. Drata excels at continuous control monitoring + evidence; TensorShield adds the security scanning, a built-in exploitation-proven pentest, and an optional managed expert.",
  },
  sprinto: {
    slug: "vs-sprinto",
    name: "Sprinto",
    category: "vs. Sprinto · compliance automation",
    h1: "TensorShield vs. Sprinto",
    sub: "Sprinto is a great SMB-focused compliance-automation tool with broad framework breadth and a bring-your-own-framework option. It's compliance-first, though — the security scanning, the pentest, and the expert are still on you.",
    theirStrengths: [
      "SMB/startup-friendly with fast time-to-compliance",
      "Very broad framework coverage, including custom/bring-your-own frameworks",
      "Good automation for evidence and continuous checks",
      "Competitive pricing for the compliance-automation category",
    ],
    rows: [
      { dim: "Framework breadth", us: "22 named + grounded control mapping", them: "Very broad incl. custom (strength)" },
      { dim: "Security scanning", us: "Built-in across 8 asset types", them: "Integrates your scanners" },
      { dim: "Penetration testing", us: "Exploitation-proven, built in", them: "Not included" },
      { dim: "The expert", us: "Optional managed vCISO/pentester", them: "Bring your own" },
      { dim: "Unified security view", us: "Attack paths, unified issues, data-tiering", them: "Compliance-centric" },
      { dim: "Detection transparency", us: "OSS-transparent", them: "Proprietary" },
    ],
    edges: [
      { t: "More than compliance", d: "Sprinto gets you compliant fast. We get you compliant AND actually secure — real scanning, attack-path correlation, and a pentest, not just an evidence trail." },
      PENTEST_EDGE,
      TWO_GTM_EDGE,
    ],
    chooseThem: "Your priority is the broadest framework list (including niche/custom ones) at a low price, and you have security covered elsewhere.",
    chooseUs: "You want compliance plus genuine security depth — vulnerabilities found and proven — and the option of an expert to run the whole thing.",
    faq: [
      ["Is TensorShield a Sprinto alternative?", "For founders who want security depth alongside compliance, yes. If you only need broad, low-cost compliance automation and have security handled, Sprinto is a strong choice."],
      ["Does TensorShield support custom frameworks like Sprinto?", "We cover 22 named frameworks today with grounded control mapping; a bring-your-own-framework capability is the documented next step. Sprinto's custom-framework breadth is currently wider."],
    ],
    seoTitle: "TensorShield vs. Sprinto — Comparison for Startups | TensorShield",
    seoDesc: "TensorShield vs. Sprinto, honestly. Sprinto is broad, SMB-friendly compliance automation; TensorShield adds real security scanning, a built-in pentest, and an optional managed expert.",
  },
  secureframe: {
    slug: "vs-secureframe",
    name: "Secureframe",
    category: "vs. Secureframe · compliance automation",
    h1: "TensorShield vs. Secureframe",
    sub: "Secureframe is a solid compliance-automation platform with good framework coverage and a helpful expert-support model. It's still evidence-first — it doesn't scan your assets, run a pentest, or fully own the security work.",
    theirStrengths: [
      "Good breadth of frameworks and automated evidence collection",
      "Compliance experts available to guide the process",
      "Established auditor relationships and Trust Center",
      "Mature onboarding for first-time compliance teams",
    ],
    rows: [
      { dim: "Expert guidance", us: "Managed expert RUNS it (not just advises)", them: "Compliance-expert guidance (advisory)" },
      { dim: "Security scanning", us: "Built-in across 8 asset types", them: "Integrates your scanners" },
      { dim: "Penetration testing", us: "Exploitation-proven, built in", them: "Not included" },
      { dim: "Frameworks", us: "22, mapped from real findings", them: "Broad coverage" },
      { dim: "Detection transparency", us: "OSS-transparent, signed evidence", them: "Proprietary" },
    ],
    edges: [
      { t: "Our expert runs it, not just advises", d: "Secureframe gives you compliance experts to guide you. On our managed plan a named expert actually does the work — triage, fixes, policies, sign-off — on your behalf." },
      PENTEST_EDGE,
      OSS_EDGE,
    ],
    chooseThem: "You want a mature compliance-automation brand with advisory experts and already have your own security stack and pentest.",
    chooseUs: "You want the security work done for real (scanning + pentest) and an expert who runs the program, not just advises on it.",
    faq: [
      ["Is TensorShield a Secureframe alternative?", "For founders who want security + pentest + a hands-on expert in addition to compliance, yes. Secureframe is a good fit if you mainly need compliance automation with advisory support."],
      ["Does TensorShield provide compliance experts like Secureframe?", "Yes — and on the managed plan they run the program for you rather than advising from the side. Self-serve and MSP-channel options exist too."],
    ],
    seoTitle: "TensorShield vs. Secureframe — Honest Comparison | TensorShield",
    seoDesc: "TensorShield vs. Secureframe, honestly. Secureframe is compliance automation with advisory experts; TensorShield adds real scanning, a built-in pentest, and a managed expert who runs the program.",
  },
  aikido: {
    slug: "vs-aikido",
    name: "Aikido",
    category: "vs. Aikido · developer security",
    h1: "TensorShield vs. Aikido",
    sub: "Aikido is an excellent developer-first security platform — fast, low-noise, great DX across SAST, SCA, secrets, containers, and cloud. We overlap there, then go further: compliance frameworks, a real pentest, identity/SaaS/OSINT posture, and an optional managed expert.",
    theirStrengths: [
      "Outstanding developer experience and fast onboarding",
      "Strong, low-noise app + cloud security across many scanners",
      "Good autofix and PR-based workflow for developers",
      "Transparent, OSS-friendly approach (a value we share)",
    ],
    rows: [
      { dim: "App + cloud scanning", us: "Yes — same OSS-wrapped approach", them: "Yes (their core strength)" },
      { dim: "Compliance frameworks", us: "22, full evidence + auditor flow", them: "Lighter compliance coverage" },
      { dim: "Penetration testing", us: "Exploitation-proven, built in", them: "Not a pentest product" },
      { dim: "Identity / SaaS / OSINT posture", us: "Built-in (operate, SSPM, OSINT)", them: "App/cloud-focused" },
      { dim: "The expert (vCISO/auditor)", us: "Optional managed, or MSP", them: "Self-serve product" },
      { dim: "Exploitation-proven findings", us: "Yes — verified with a PoC", them: "Scanner findings" },
    ],
    edges: [
      { t: "Compliance + an auditor flow", d: "Aikido is dev-security-first. We carry that and add 22 frameworks, signed evidence, and an audit/attestation workflow — so the same findings get you SOC 2, not just a clean dev dashboard." },
      PENTEST_EDGE,
      TWO_GTM_EDGE,
    ],
    chooseThem: "You're a developer-led team that wants the best dev-security DX and doesn't need compliance, a pentest, or a managed expert from the same vendor.",
    chooseUs: "You want dev security AND compliance AND a real pentest AND (optionally) an expert to run it — one product, one bill, one source of truth.",
    faq: [
      ["Is TensorShield an Aikido alternative?", "Yes — we share the OSS-wrapped, low-noise scanning philosophy, then add compliance frameworks, an exploitation-proven pentest, identity/SaaS/OSINT posture, and an optional managed expert. Aikido is excellent if you only need developer-focused app + cloud security."],
      ["Do you share Aikido's transparency?", "Yes — our detection wraps best-in-class open-source tools (nuclei, semgrep, trivy, prowler…), so you can see and reproduce exactly what ran. We consider that a strength we have in common."],
    ],
    seoTitle: "TensorShield vs. Aikido — Dev Security + Compliance + Pentest | TensorShield",
    seoDesc: "TensorShield vs. Aikido, honestly. Aikido is great developer-first app+cloud security; TensorShield shares that and adds 22 compliance frameworks, a built-in exploitation-proven pentest, and a managed expert.",
  },
};

export const COMPETITOR_LIST = Object.values(COMPETITORS);
