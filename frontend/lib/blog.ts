// The blog content model + posts. Content lives as structured blocks (no MDX dependency) rendered by
// the post page with the marketing design system. Each post carries a reader-facing topic category
// and links to the relevant free tool.

export type Block =
  | { t: "p"; text: string }
  | { t: "h2"; text: string }
  | { t: "ul"; items: string[] }
  | { t: "cta"; text: string; href: string; label: string };

export interface Post {
  slug: string;
  title: string;
  description: string;
  category: string; // reader-facing topic
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
    category: "Security questionnaires",
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
    category: "SOC 2",
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
    category: "Sales & security",
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
      { t: "p", text: "You can see your externally-visible posture in 30 seconds with no account at all. Want to know what the full report looks like first? Here's a worked example in the exact format we produce — every finding proven, with evidence, a fix, and the SOC 2 control it affects." },
      { t: "cta", text: "See a sample security assessment report", href: "/sample-report", label: "View the sample report" },
      { t: "p", text: "When you're ready to see the full picture — your code, cloud, and identity — connecting one system is free, and you'll get a prioritized, deal-blocker-first view of exactly what to fix." },
      { t: "cta", text: "See your full posture — free", href: "/signup", label: "Get started free" },
      { t: "p", text: "The next deal that hits a security review shouldn't be the thing that tells you about a gap. Fix it on your schedule, not the buyer's." },
    ],
  },

{
    slug: "india-saas-us-enterprise-security-questionnaire",
    title: "Your US customer sent a security questionnaire to your Indian startup. Here's what they're actually checking",
    description:
      "Selling from Bengaluru into a US enterprise means answering a security review written for US vendors. Here's what those questions map to, which Indian regulations matter to the buyer, and which ones they have never heard of.",
    category: "Selling into US enterprises",
    date: "2026-08-12",
    readMins: 7,
    body: [
      { t: "p", text: "The first enterprise deal is going well until procurement forwards a spreadsheet. Two hundred rows, written by a security team in San Francisco or New York, assuming a vendor in the same country. You are in Bengaluru or Pune, your compliance posture is shaped by Indian law, and roughly a third of the questions do not obviously apply to you." },
      { t: "p", text: "They still have to be answered, and answered in the buyer's frame rather than yours. Here is how the two worlds line up." },
      { t: "h2", text: "What the buyer is actually asking" },
      { t: "p", text: "Almost every enterprise vendor security questionnaire is a restatement of the same handful of concerns. Strip the phrasing and you get:" },
      { t: "ul", items: [
        "Can someone impersonate you? — email authentication (DMARC, SPF, DKIM), domain hygiene, certificate posture.",
        "Is data protected in transit and at rest? — HTTPS everywhere, HSTS, encryption on your databases and object storage.",
        "Who can reach production? — MFA on every admin, SSO, offboarding that actually removes access.",
        "Do you know what you're running? — dependency and container vulnerability management, a patching cadence you can describe.",
        "Has anyone independent tested it? — a penetration test report, dated within the last twelve months.",
        "What happens when something goes wrong? — an incident response plan, a breach notification commitment, and a named human.",
      ] },
      { t: "p", text: "None of that is US-specific. It is the same list whether you are in Austin or Ahmedabad — which is the good news, because it means the work is portable across every deal you will ever do." },
      { t: "h2", text: "Which Indian regulations the buyer cares about" },
      { t: "p", text: "This is where Indian vendors lose time, usually by volunteering the wrong things. A US enterprise buyer's security team is trying to answer one question: if we hand you our customers' data, what is the risk to us? Indian regulation matters to them only where it changes that answer." },
      { t: "ul", items: [
        "CERT-In Directions (2022) — matters, and it is worth raising yourself. It obliges you to report certain classes of incident to the Indian authorities within six hours of noticing them. A buyer reads a mandatory six-hour clock as a stronger commitment than most vendors offer voluntarily. Say so.",
        "The DPDP Act 2023 — matters if you process personal data of people in India. It is India's general data-protection law and it is the closest analogue to the GDPR framing most enterprise questionnaires are built around, so it is the right thing to cite when a row asks about your privacy regime.",
        "RBI Cyber Security Framework — matters only if you sell to, or process data for, Indian regulated financial entities. If your buyer is a US software company, it is noise.",
        "SEBI CSCRF — same: relevant for Indian securities-market entities, irrelevant to a US buyer's risk model.",
      ] },
      { t: "p", text: "The mistake is to answer a US questionnaire with a wall of Indian regulatory detail, which reads as evasion. Answer the question they asked, then note the Indian obligation where it strengthens your position — CERT-In's reporting clock genuinely does." },
      { t: "h2", text: "What they will ask for that Indian law does not give you" },
      { t: "p", text: "There is no Indian equivalent of SOC 2, and this is the single most common stall. SOC 2 is not a law and not a government scheme. It is an attestation performed by a licensed accounting firm against the AICPA's Trust Services Criteria, and a US enterprise buyer will very often treat it as the default proof of a functioning security programme." },
      { t: "p", text: "Two practical consequences. First, no amount of Indian compliance substitutes for it in the buyer's mind — you cannot answer \"are you SOC 2?\" with \"we comply with DPDP\". Second, you do not need the audit to unblock the deal today. What unblocks most deals is evidence that the underlying controls exist and are working, plus a credible date for the audit. Buyers accept that far more often than founders expect, because their actual fear is an unmanaged vendor, not a missing PDF." },
      { t: "p", text: "ISO 27001 is the other common answer, and it travels better internationally than SOC 2 does. If you are selling into both the US and Europe, it is usually the more efficient first certification." },
      { t: "h2", text: "The order that saves the most time" },
      { t: "p", text: "Do the externally-visible work first. Before anyone reads a policy document, the buyer's security team — or their automated vendor-risk tool — will check what they can see from outside: your email authentication, your TLS configuration, your security headers, whether you publish a security contact. Those checks are cheap for them to run and they set the tone for everything that follows. Failing them means starting the conversation on the back foot for reasons that take an afternoon to fix." },
      { t: "p", text: "Then close the internal gaps that map to the six concerns above. Then start the audit, if the deal size justifies it. Running that order in reverse — starting with the audit and discovering your DMARC record was missing the whole time — is how a quarter disappears." },
      { t: "cta", text: "See what a buyer sees from outside your domain — free, no signup", href: "/scan", label: "Run the free scan" },
      { t: "h2", text: "One artifact, reused" },
      { t: "p", text: "The reason this work compounds is that the second questionnaire is mostly the first questionnaire. The controls do not change per buyer; only the phrasing does. If you keep the evidence in a form you can hand over — findings with the tool that proved them, mapped to the control each one affects — then every subsequent review is a lookup rather than a project." },
      { t: "p", text: "That is the whole argument for treating the first security review as infrastructure rather than as a fire. You are going to be asked these questions by every enterprise customer you ever sell to." },
      { t: "cta", text: "See your full posture across code, cloud and identity — free", href: "/signup", label: "Get started free" },
    ],
  },
  {
    slug: "soc2-iso27001-dpdp-which-one-for-your-deal",
    title: "SOC 2, ISO 27001 or DPDP: which one does your deal actually need?",
    description:
      "Indian SaaS founders are told to get all three. Most deals need one. A plain-English guide to which certification your specific buyer is asking for, and what it costs to say yes.",
    category: "Selling into US enterprises",
    date: "2026-08-19",
    readMins: 6,
    body: [
      { t: "p", text: "Ask five advisors and you will get five answers, all of them \"yes, and also the other two\". That is expensive advice. These three things are not alternatives to each other — they answer different questions, asked by different people, for different reasons." },
      { t: "h2", text: "They are not the same kind of thing" },
      { t: "ul", items: [
        "SOC 2 is an attestation. A licensed accounting firm examines your controls and writes a report about what it found. There is no certificate and no pass mark — the buyer reads the auditor's opinion and the exceptions.",
        "ISO 27001 is a certification. An accredited body audits your information security management system against an international standard and issues a certificate with an expiry date.",
        "The DPDP Act is a law. You do not get certified against it; you either comply or you are exposed. It applies because of where your users are, not because a customer asked.",
      ] },
      { t: "p", text: "Conflating them is what produces the \"get all three\" advice. A law is not a sales asset and a sales asset is not optional compliance." },
      { t: "h2", text: "Which one your buyer is actually asking for" },
      { t: "p", text: "In practice the answer is determined almost entirely by who is buying:" },
      { t: "ul", items: [
        "A US enterprise, especially in tech or financial services — SOC 2 Type II. It is the default in that market and their vendor-risk process is usually built around it.",
        "A European or UK buyer, or a multinational — ISO 27001. It travels better internationally and is more often the named requirement outside the US.",
        "Any buyer whose end users are in India, including Indian enterprises — DPDP compliance, regardless of what else you hold. This one is not negotiable by the buyer because it is not theirs to waive.",
        "A regulated Indian entity — sectoral rules on top: RBI's framework for banks and regulated financial entities, SEBI's CSCRF for securities-market entities.",
      ] },
      { t: "p", text: "If you sell only to US software companies, ISO 27001 is a large amount of work that will rarely be asked for. If you sell across the US and Europe, doing ISO 27001 first and mapping it onto SOC 2 later is usually cheaper than the reverse." },
      { t: "h2", text: "Type I and Type II, and why the distinction costs you a quarter" },
      { t: "p", text: "SOC 2 comes in two flavours and founders routinely budget for the wrong one. A Type I report says the controls were designed appropriately at a single point in time. A Type II says they operated effectively across an observation window — typically three to twelve months." },
      { t: "p", text: "Enterprise buyers overwhelmingly want Type II, which means the calendar, not the work, is usually your binding constraint. You cannot compress an observation window. This is the single most common reason a compliance project misses the deal it was started for, and it is entirely avoidable by starting the window early — the controls do not have to be perfect on day one of the window, they have to be running." },
      { t: "h2", text: "What actually unblocks the deal while you wait" },
      { t: "p", text: "None of the above helps the deal that is stuck this month. What does help, in rough order of how often it works:" },
      { t: "ul", items: [
        "Evidence the controls exist and are working — findings, dated, with the tool that produced them and the control each affects. This is what an auditor will ask for anyway, so it is never wasted work.",
        "A recent penetration test report. Frequently a hard requirement, and unlike an audit window it can be produced in weeks.",
        "A trust page a buyer's security team can read without emailing you, covering your subprocessors, data residency, encryption and incident commitments.",
        "A named human who owns security and will sign things. Buyers are assessing whether anyone is actually accountable, and an org chart with a real name on it does more than most founders expect.",
        "A credible audit date. \"Type II window opens in March, report expected in September\" is a far better answer than silence, and buyers regularly proceed on it with a contractual commitment.",
      ] },
      { t: "p", text: "The pattern is that buyers are managing risk, not collecting documents. A vendor who can show what is true today and name what is coming is a manageable risk. A vendor who cannot answer is not, whatever certifications they eventually hold." },
      { t: "cta", text: "See where you stand against SOC 2 — free, no signup", href: "/soc2-readiness", label: "Check your readiness" },
      { t: "h2", text: "The cheapest order" },
      { t: "p", text: "Fix what is visible from the outside. Get the evidence into a form you can hand over. Get a penetration test if a review is already blocking revenue. Open the audit window as early as you can stand, because that clock is the one thing money cannot speed up. Add the second framework only when a real buyer asks for it by name." },
      { t: "p", text: "Doing it in that order means every step is useful to a deal in flight, rather than a nine-month project that produces nothing until the day it finishes." },
      { t: "cta", text: "See your posture across all 25 frameworks — free", href: "/signup", label: "Get started free" },
    ],
  },
];

export function postBySlug(slug: string): Post | undefined {
  return POSTS.find((p) => p.slug === slug);
}
