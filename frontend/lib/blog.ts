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
      ] },
      { t: "p", text: "One more thing gets checked that this list deliberately leaves out: known vulnerabilities in the dependencies you ship. It belongs on a buyer's list, but not on this one — it is not visible from outside your domain, and no scanner can answer it without reading your lockfiles. Anyone who tells you they checked your dependencies from your domain name alone has not checked your dependencies." },
      { t: "p", text: "None of these are unusual to miss for a team shipping fast. They just all surface at once the moment a customer's security review begins — and they're the cheapest things in your whole security program to fix." },
      { t: "h2", text: "See your own score in 30 seconds" },
      { t: "p", text: "You don't have to guess about the externally-visible ones. Our free scanner runs eight read-only checks against your domain — DMARC, SPF and DKIM for email authentication, HTTPS enforcement, HSTS, Content-Security-Policy, clickjacking and MIME protections, and whether you publish a security contact — and gives you a grade plus the precise fix for anything that fails. No signup, nothing intrusive, just the public checks anyone could run. Your dependencies need a connected repository; the domain scan cannot see them and does not claim to." },
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

{
    slug: "dpdp-act-compliance-for-indian-saas",
    title: "The DPDP Act for Indian SaaS: what you actually have to do",
    description:
      "India's data protection law applies to you whether or not a customer asks. A plain-English guide to the duties that matter, what changes for a B2B SaaS company, and how it lands in an enterprise security review.",
    category: "Selling into US enterprises",
    date: "2026-08-21",
    readMins: 7,
    body: [
      { t: "p", text: "Most Indian SaaS founders meet the Digital Personal Data Protection Act the way they meet everything else in compliance: a customer's legal team asks a question they cannot answer. That is the wrong order, because unlike SOC 2 this one is not optional and not customer-driven. It is law, and it applies because of where your users are." },
      { t: "h2", text: "Who it applies to" },
      { t: "p", text: "The Act governs the processing of digital personal data where that data relates to people in India. If you have Indian users, or you process Indian personal data on behalf of a customer, you are in scope — including when your company is incorporated elsewhere and your servers are not in India." },
      { t: "p", text: "For a B2B SaaS company the important nuance is which hat you are wearing. When you decide why and how personal data gets processed — your own signups, your marketing list, your employees — you are a Data Fiduciary and the full set of duties is yours. When you process your customer's data on their instructions, you are a Data Processor and most of the obligations sit with them, flowing to you through the contract. Enterprise buyers will ask you to confirm which one you are for their data. The answer is almost always processor, and saying so clearly is a good answer." },
      { t: "h2", text: "The duties that actually change your product" },
      { t: "ul", items: [
        "Notice and consent — you must tell people what you are collecting and why, in clear language, and consent has to be a real affirmative act. Pre-ticked boxes and bundled consent do not survive this.",
        "Purpose limitation — data collected for one stated purpose cannot quietly become training data, a marketing list, or an analytics feed.",
        "Data principal rights — people can ask what you hold, have it corrected, and have it erased. Whatever your architecture, someone has to be able to answer those requests within a reasonable time, which means knowing where personal data actually lives.",
        "Erasure on withdrawal — when consent is withdrawn or the purpose is served, the data goes. This is the duty that most often collides with a system designed to never delete anything.",
        "Reasonable security safeguards — the Act obliges you to protect the data, and this is where the heaviest consequences sit. It does not enumerate controls, which in practice means you are measured against what a competent organisation your size would do.",
        "Breach notification — you notify the Data Protection Board and affected people. Note this is a separate duty from CERT-In's incident reporting, with a different recipient and a different trigger; satisfying one does not satisfy the other.",
      ] },
      { t: "h2", text: "What an enterprise buyer does with it" },
      { t: "p", text: "A US or European buyer will not audit your DPDP compliance. They will do two things. First, they will map it onto their own frame — DPDP is the closest Indian analogue to the GDPR framing most vendor questionnaires are built around, so citing it is the right answer to a row asking about your privacy regime. Second, they will look for the contractual plumbing: a data-processing agreement, a named list of subprocessors, a documented breach-notification commitment, and a statement of where data is stored." },
      { t: "p", text: "That last point causes more stalls than the law itself. Indian vendors frequently cannot answer \"where does our data live and who else touches it\" without a week of internal archaeology. Building the subprocessor list before someone asks is a few hours of work that pays for itself the first time." },
      { t: "h2", text: "The overlap with the work you are already doing" },
      { t: "p", text: "The reasonable-security-safeguards duty is not a separate project. Encryption in transit and at rest, access control with MFA, patching known vulnerabilities, logging, and an incident response plan are the same controls SOC 2 and ISO 27001 ask for, and the same ones sitting in your customer's questionnaire. Done once, they answer all three." },
      { t: "p", text: "What DPDP adds on top is mostly about knowing your data rather than defending it: what personal data you hold, why, where, who you share it with, and how someone gets it deleted. That inventory is the genuinely new work, and it is worth doing deliberately rather than reconstructing it under deadline." },
      { t: "cta", text: "See which controls you already have — free, no signup", href: "/scan", label: "Run the free scan" },
      { t: "p", text: "None of this is a reason to panic, and none of it is a reason to buy anything. It is a reason to write down what you process and to close the security gaps you already know about, before a regulator or a buyer asks you to do it on their schedule." },
      { t: "cta", text: "Map your posture to DPDP and 24 other frameworks — free", href: "/signup", label: "Get started free" },
    ],
  },
  {
    slug: "certin-six-hour-incident-reporting",
    title: "CERT-In's six-hour rule: what it means when something actually happens",
    description:
      "India obliges you to report certain security incidents within six hours of noticing them. Here's which incidents count, what the report has to contain, and why it is worth telling your enterprise buyers about it.",
    category: "Selling into US enterprises",
    date: "2026-08-22",
    readMins: 6,
    body: [
      { t: "p", text: "The CERT-In Directions issued in April 2022 contain the tightest incident-reporting clock in mainstream data regulation: six hours from noticing a qualifying incident, not six hours from confirming it, and not one business day." },
      { t: "p", text: "Most Indian startups discover this the week it becomes relevant, which is the worst possible week to read a regulation for the first time." },
      { t: "h2", text: "Six hours from when, exactly" },
      { t: "p", text: "The clock starts when you notice the incident or are told about it — not when you have finished investigating. This is the part teams get wrong. The instinct is to establish what happened before saying anything, and that instinct will run you past the deadline every time." },
      { t: "p", text: "The practical consequence is that your first report is expected to be incomplete. You report what you know, and you follow up. A team that understands this reports on time with three known facts; a team that does not misses the window trying to write a complete account." },
      { t: "h2", text: "Which incidents qualify" },
      { t: "p", text: "The Directions list categories rather than a severity threshold, and the list is broader than most founders expect. Among them:" },
      { t: "ul", items: [
        "Unauthorised access to IT systems or data — the category most breaches fall into.",
        "Data breaches and data leaks.",
        "Compromise of critical systems, and website defacement or intrusion.",
        "Malicious code attacks, including ransomware.",
        "Attacks on servers, network appliances, and applications — including denial of service.",
        "Attacks on cloud infrastructure, and on identity or authentication systems.",
      ] },
      { t: "p", text: "Note what is absent: a materiality test. There is no \"only if significant\" carve-out to hide behind, which is why a documented internal triage step — is this a qualifying category, yes or no — is more useful than a severity matrix." },
      { t: "h2", text: "The obligations that are not about incidents" },
      { t: "p", text: "The same Directions carry three standing duties that have nothing to do with any particular breach, and these are the ones quietly ignored:" },
      { t: "ul", items: [
        "Log retention — security logs kept for 180 days, and kept within India.",
        "Clock synchronisation — systems synced to NIC or NPL time sources, so that logs from different systems can actually be correlated.",
        "KYC and subscriber records — applies to VPS, cloud, VPN and similar providers, with a five-year retention period.",
      ] },
      { t: "p", text: "The log retention one has real architectural consequences if your logging is a managed service in another region, and it is far cheaper to decide that at setup than to migrate later." },
      { t: "h2", text: "Why you should raise it with buyers yourself" },
      { t: "p", text: "Here is the part Indian vendors miss. A US enterprise buyer's questionnaire will ask how quickly you commit to notifying them of a breach. The common vendor answer is something like \"without undue delay\" or \"within 72 hours\"." },
      { t: "p", text: "You are subject to a mandatory six-hour reporting duty to a national authority. That is a stronger commitment than almost any vendor offers voluntarily, and it is evidence that you must have detection and escalation capable of meeting it. Volunteering that in a security review converts a piece of Indian regulatory burden into a differentiator. Very few of your competitors will be doing this." },
      { t: "p", text: "The caveat is that you have to be telling the truth. A six-hour duty implies someone is watching, someone is reachable out of hours, and there is a documented path from alert to report. If those do not exist, the honest move is to build them before you cite the obligation." },
      { t: "cta", text: "See what an attacker sees, before you have to report it", href: "/scan", label: "Run the free scan" },
      { t: "p", text: "Incident reporting is one of those obligations that costs almost nothing while nothing is happening and is impossible to retrofit on the day it matters. Write the runbook, name the person, test the path once." },
      { t: "cta", text: "Continuous monitoring, incidents, and a named human — free to start", href: "/signup", label: "Get started free" },
    ],
  },
  {
    slug: "pentest-report-us-enterprise-buyer-expects",
    title: "The penetration test report a US buyer expects — and what Indian vendors usually send",
    description:
      "\"Do you have a recent pentest?\" is one of the most common blockers in an enterprise security review, and one of the easiest to answer badly. What the buyer is checking, and what makes a report fail on sight.",
    category: "Selling into US enterprises",
    date: "2026-08-22",
    readMins: 6,
    body: [
      { t: "p", text: "Somewhere in every enterprise vendor review is a row asking for a recent penetration test. It is one of the few questions where the answer is a document rather than a statement, which means it is one of the few where you can fail on sight." },
      { t: "h2", text: "What the buyer is actually checking" },
      { t: "p", text: "Not the findings. Reviewers are largely indifferent to what your report found, and a report with zero findings makes them more suspicious, not less. What they check, in roughly this order:" },
      { t: "ul", items: [
        "The date. Within twelve months is the usual bar, and older than that often reads as no report at all.",
        "The scope. Which systems were tested, and does that scope include the product they are about to buy? A test scoped to your marketing site does not cover your API.",
        "Who performed it. An independent party, named, with something to lose. A self-assessment is not a penetration test regardless of how thorough it was.",
        "Whether findings were remediated. An open critical from eight months ago is worse than the same critical found last week, because it says something about your process rather than your code.",
        "Retest evidence. Did anybody confirm the fixes actually worked, or does the report simply end?",
      ] },
      { t: "p", text: "That last item is where most reports quietly disappoint. A finding marked \"remediated\" on the vendor's say-so is an assertion. A finding marked remediated with a retest date and a result is evidence, and reviewers can tell the difference at a glance." },
      { t: "h2", text: "What Indian vendors usually send instead" },
      { t: "p", text: "Three substitutes come up again and again, and all three are read as a no:" },
      { t: "ul", items: [
        "A vulnerability scan exported to PDF. Scanners and penetration tests answer different questions — one lists what might be wrong, the other establishes what an attacker could actually do. Reviewers know the difference between a scanner's output and a tester's narrative.",
        "A certificate from a testing body with no report attached. The certificate asserts a test happened; the buyer's security team needs to see scope and findings to know whether it covered anything relevant.",
        "A report scoped to the corporate website when the product is an API. Common, understandable, and immediately disqualifying for the thing being purchased.",
      ] },
      { t: "p", text: "The fourth substitute is silence plus a promise, which works far better than founders expect. \"We do not have one; we have booked a test for March covering the production API\" is a manageable risk. An irrelevant PDF is an unmanageable one, because now the reviewer is also wondering whether you understood the question." },
      { t: "h2", text: "What a usable report contains" },
      { t: "p", text: "Whoever produces it, the artefact a security reviewer can accept has a predictable shape: an executive summary a non-specialist can read, an explicit scope statement naming the systems and the dates, a methodology note, each finding with severity, evidence of exploitation, and a remediation recommendation, and a retest section confirming what was fixed and when. A named human signs it." },
      { t: "p", text: "That structure is not a formality. Every element maps to a question the reviewer has to answer for their own risk register, and a report missing one of them sends them back to you with follow-up questions — which is another week of deal time." },
      { t: "cta", text: "See a worked example in the exact format we produce", href: "/sample-report", label: "View the sample report" },
      { t: "h2", text: "Cadence beats recency theatre" },
      { t: "p", text: "The annual test exists because that is how the consulting engagement was priced, not because attackers work to an annual cycle. A report dated eleven months ago technically clears the bar while describing a system that has since shipped two hundred releases." },
      { t: "p", text: "If you can test continuously and produce the artefact on demand, the twelve-month question stops being a deadline you scramble against. That is the argument for testing being part of your pipeline rather than a purchase you make each spring — and it is a materially better answer to give a buyer than a PDF that happens to be in date." },
      { t: "cta", text: "Exploitation-proven testing, re-tested after every fix", href: "/ai-pentest", label: "See how it works" },
    ],
  },
];

export function postBySlug(slug: string): Post | undefined {
  return POSTS.find((p) => p.slug === slug);
}
