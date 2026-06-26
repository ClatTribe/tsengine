// Email-gated free resources (lead magnets) for the founder ICP. Each is genuinely useful, grounded content —
// a checklist / template a founder can actually use — revealed after an email capture (POST /api/lead, source
// "resource:<slug>"). Rendered by app/(marketing)/resources/[slug] behind <ResourceGate>.

export type ResourceSection = { heading: string; intro?: string; items: string[] };
export type Resource = {
  slug: string;
  kind: "Checklist" | "Template" | "Guide";
  title: string;
  subtitle: string;
  blurb: string; // shown above the email gate (the hook)
  takeaways: string[]; // "what's inside" bullets shown before unlock
  sections: ResourceSection[]; // the gated content
  seoTitle: string;
  seoDesc: string;
};

export const RESOURCES: Record<string, Resource> = {
  "soc2-readiness-checklist": {
    slug: "soc2-readiness-checklist",
    kind: "Checklist",
    title: "The Founder's SOC 2 Readiness Checklist",
    subtitle: "Every control a startup needs in place before the audit — grouped, plain-English, no consultant required.",
    blurb:
      "Most founders start their SOC 2 by paying a consultant $20k to hand them a spreadsheet. Here's that spreadsheet, free. Work top-to-bottom and you'll walk into the audit ready — and you'll know exactly which items a tool can close and which need a human signature.",
    takeaways: [
      "The ~40 controls auditors actually check, in plain English",
      "Which items automate vs. which need a policy or an attestation",
      "The order to do them in so nothing blocks the audit window",
      "What evidence the auditor will ask for, per control",
    ],
    sections: [
      {
        heading: "1 · Access control (the auditor's first stop)",
        intro: "Most SOC 2 findings are access-control gaps. Close these first.",
        items: [
          "Enforce MFA on every employee account — email, code host, cloud console, and every SaaS admin.",
          "Use SSO (Google/Okta/M365) so offboarding is one switch, not ten.",
          "Remove standing admin access; grant least-privilege and review quarterly.",
          "Disable accounts within 24h of an employee leaving — keep the ticket as evidence.",
          "Unique logins only — no shared service accounts a human signs into.",
        ],
      },
      {
        heading: "2 · Change management (code → production)",
        items: [
          "Require pull-request review before merge to the main branch.",
          "Run automated security scanning (SAST/SCA/secrets) in CI on every PR.",
          "Keep a record of who approved and deployed each change (your git history + CI logs).",
          "Separate who can write code from who can approve production releases where headcount allows.",
        ],
      },
      {
        heading: "3 · Infrastructure & data",
        items: [
          "Encrypt data at rest and in transit (TLS everywhere, encrypted volumes/buckets).",
          "Block public access on storage buckets by default; review every public exception.",
          "Centralize logging and retain it (cloud trail / audit logs) for at least 90 days.",
          "Enable automated backups and test a restore once — keep the screenshot.",
          "Scan your cloud config against CIS benchmarks and remediate the highs.",
        ],
      },
      {
        heading: "4 · Vulnerability & vendor management",
        items: [
          "Run continuous vulnerability scanning across code, cloud, and dependencies.",
          "Define remediation SLAs by severity (e.g. critical 7 days, high 30) and track to them.",
          "Get a third-party penetration test — auditors and enterprise buyers both ask for it.",
          "Keep a vendor inventory with each sub-processor's own SOC 2 / DPA on file.",
        ],
      },
      {
        heading: "5 · The human-only controls (a tool can't do these)",
        intro: "These need a person — a policy author, a manager, or an independent auditor. This is where a vCISO or our managed expert earns their keep.",
        items: [
          "Write and publish the core policies (Information Security, Access Control, Incident Response, Vendor, BCP/DR) and have employees acknowledge them.",
          "Run security-awareness training at hire and annually; keep completion records.",
          "Document a risk assessment — list risks, owners, and your accept/mitigate decision.",
          "Run one incident-response tabletop and keep the notes.",
          "Engage an independent licensed CPA firm for the actual SOC 2 attestation — only they can issue the report.",
        ],
      },
    ],
    seoTitle: "Free SOC 2 Readiness Checklist for Startups (PDF) | TensorShield",
    seoDesc:
      "The ~40 controls auditors actually check, in plain English — which automate vs. need a human, the order to do them, and the evidence each needs. Free for founders.",
  },
  "security-questionnaire-template": {
    slug: "security-questionnaire-template",
    kind: "Template",
    title: "Security Questionnaire Response Template",
    subtitle: "The questions enterprise buyers ask — and how to answer each one without stalling the deal.",
    blurb:
      "An enterprise prospect just sent a 120-question security questionnaire and the deal is waiting on it. This template gives you the real questions, grouped, with model answers and the evidence to attach — so you respond in a day, not a fortnight.",
    takeaways: [
      "The questions that show up in ~80% of buyer questionnaires",
      "A model answer for each — and what to attach as proof",
      "How to answer honestly when something's still in progress",
      "Which answers a live security posture can auto-populate for you",
    ],
    sections: [
      {
        heading: "Access control & authentication",
        items: [
          "Do you enforce MFA for all employees? → Yes, via SSO on all corporate and production systems. Attach: IdP policy screenshot.",
          "How is access provisioned and de-provisioned? → SSO-based, least-privilege, removed within 24h of departure; reviewed quarterly. Attach: access-review record.",
          "Do you use role-based access control? → Yes, roles scoped to job function; admin access is limited and logged.",
        ],
      },
      {
        heading: "Data protection",
        items: [
          "Is data encrypted at rest and in transit? → Yes — AES-256 at rest, TLS 1.2+ in transit. Attach: config evidence.",
          "Where is customer data hosted? → Name the cloud + regions; note tenant isolation.",
          "Do you have a data-retention and deletion policy? → Yes; state the retention window and deletion-on-request process.",
          "Who are your sub-processors? → Maintain a current list with each one's SOC 2 / DPA.",
        ],
      },
      {
        heading: "Application & infrastructure security",
        items: [
          "Do you run SAST/DAST/dependency scanning? → Yes, in CI on every change; findings triaged to SLA.",
          "Do you perform penetration testing? → Yes — annual third-party test plus continuous automated testing; summary available under NDA.",
          "How do you manage vulnerabilities? → Continuous scanning with severity-based SLAs; attach your SLA policy.",
          "Is your cloud benchmarked (CIS)? → Yes; highs remediated, posture monitored continuously.",
        ],
      },
      {
        heading: "Governance, compliance & operations",
        items: [
          "Do you have SOC 2 / ISO 27001? → State status honestly: 'SOC 2 Type II' or 'Type I complete, Type II in progress, report DD/MM' — never claim what isn't issued.",
          "Do you have documented security policies? → Yes; list them and offer the index. Attach on request.",
          "Do you have an incident-response plan? → Yes; state your notification commitment (e.g. within 72h).",
          "Do you conduct security-awareness training? → Yes, at hire and annually; completion tracked.",
          "Do you carry cyber-insurance? → State coverage if you have it.",
        ],
      },
      {
        heading: "How to answer honestly when it's in progress",
        intro: "Never overstate — a buyer's security team will verify, and a false 'yes' kills trust faster than an honest 'in progress'.",
        items: [
          "Use 'Yes', 'In progress — target date', or 'Compensating control: …' — not a bare 'No'.",
          "If a control is partial, describe the part you have and the plan for the rest.",
          "Attach evidence for every 'Yes' you can — it pre-empts the follow-up email.",
          "Keep one canonical answer set so every questionnaire is copy-paste, not a rewrite.",
        ],
      },
    ],
    seoTitle: "Security Questionnaire Response Template (Free) | TensorShield",
    seoDesc:
      "The security questions enterprise buyers ask, grouped, with model answers and the evidence to attach — so you respond in a day, not a fortnight. Free for founders.",
  },
};

export const RESOURCE_LIST = Object.values(RESOURCES);
