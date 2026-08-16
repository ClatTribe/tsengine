// The product documentation content.
//
// EVERY STATEMENT HERE WAS VERIFIED AGAINST THE RUNNING PRODUCT before it was written — the
// endpoints were driven, the refusals were triggered, the gates were tripped. Docs that describe an
// intended product rather than the shipped one are worse than no docs: a customer follows them,
// hits something different, and stops trusting the rest of the page.
//
// Where a capability needs something the customer must supply (an LLM key, a completed scan, a
// write scope), the step says so in the step itself rather than in a footnote. That is the same
// discipline the product applies to its own findings: absence of a result is not a result.

export interface DocStep {
  n: string;
  title: string;
  body: string;
  /** What this step needs before it will do anything. Empty when it just works. */
  needs?: string;
}

export interface DocSection {
  id: string;
  title: string;
  intro: string;
  steps?: DocStep[];
  /** Reference rows — term on the left, meaning on the right. */
  rows?: { k: string; v: string }[];
}

export const DOC_SECTIONS: DocSection[] = [
  {
    id: "start",
    title: "Getting started",
    intro:
      "Five minutes from sign-up to your first finding. Nothing here needs a credit card, and nothing writes to your systems until you approve it.",
    steps: [
      {
        n: "1",
        title: "Create your workspace",
        body: "Sign up with your work email. That creates a workspace and makes you its owner — you can invite the rest of your team later from Settings → Team. Members you invite get a one-time password they must change on first sign-in.",
      },
      {
        n: "2",
        title: "Tell us your stage",
        body: "Seed, Series A, B or C+. This is the only onboarding question we ask, and it decides which practices you are measured against on the Readiness page — a seed company held to a Series C bar closes the tab. You can preview another stage at any time without committing to it.",
      },
      {
        n: "3",
        title: "Connect a system",
        body: "GitHub, GitLab, Bitbucket or Azure DevOps for code. AWS, Google Cloud or Azure for infrastructure. Google Workspace, Microsoft 365 or Okta for identity. OAuth is read-only by default — we ask for write scopes only when you enable a fix path that needs them.",
      },
      {
        n: "4",
        title: "Or add a target you own",
        body: "For a domain, web app, API or IP range that no connector covers, add it directly. You must confirm you are authorized to scan it, and for standalone targets you can prove control with a DNS TXT record or a well-known file before active testing is allowed.",
        needs: "A confirmation that you are authorized to scan the target.",
      },
      {
        n: "5",
        title: "Read the first results",
        body: "Findings land on Issues — deduplicated across tools, ranked, and each one explained in plain English: what it is, why it matters, and the fix. The Coverage page shows exactly which tools ran on which asset, so you never have to take coverage on trust.",
      },
    ],
  },
  {
    id: "agents",
    title: "The two agents",
    intro:
      "The scanning, correlation and compliance mapping are deterministic and always run. The two AI agents sit on top of that and need a model — bring your own key under Settings → LLM, or pick a plan that includes one.",
    steps: [
      {
        n: "AI",
        title: "AI Security Engineer — defence",
        body: "Reads across code, cloud, SaaS and identity to find what is genuinely exploitable, explains it in your terms, and writes the fix. It works the estate as a graph, so it can say that a key leaked in a repo reaches a specific cloud role — not just that both exist.",
        needs: "An LLM key. Without one, scanning, correlation and compliance mapping still run; triage, investigation and proposed fixes do not.",
      },
      {
        n: "AI",
        title: "AI Pentester — offence",
        body: "Scoped by rules of engagement you authorize, it works your findings as leads and proves the real ones with a benign proof-of-concept. A finding is only marked exploitation-proven when a deterministic check confirms the demonstration — the model proposes, the framework disposes.",
        needs: "An engagement with authorized targets. Active exploitation additionally needs your explicit, named consent.",
      },
    ],
  },
  {
    id: "approvals",
    title: "Approvals — how changes actually happen",
    intro:
      "Nothing consequential happens without a person. Every proposed change arrives at the Inbox with the finding that justifies it, the diff it would apply, and a plain-English statement of whether it can be undone.",
    rows: [
      { k: "Tier 0–1", v: "Low-risk and reversible — a ticket, a notification. Applied automatically, still recorded in the ledger." },
      { k: "Tier 2", v: "Reversible but consequential — a pull request, a config change. Queued for a human; nothing is applied until someone approves it." },
      { k: "Tier 3", v: "Irreversible or legal — a breach notification draft. Refuses to execute without a named human's signature. It can never auto-apply." },
      { k: "Request changes", v: "Not just approve or reject. Leave a note and the agent re-proposes against it, and the desk shows the thread rather than two unrelated rows." },
      { k: "Kill switch", v: "Halts every autonomous action for the whole workspace at once. It fails closed: the switch beats a pending approval, queued actions wait, and scans are refused with a reason rather than silently doing nothing." },
    ],
  },
  {
    id: "compliance",
    title: "Compliance and evidence",
    intro:
      "Findings map to controls across 22 frameworks as they are emitted. The mapping is annotation, not judgement — we record which controls a technical finding affects, and never tell you that you are compliant.",
    rows: [
      { k: "Coverage, not a score", v: "Each framework reports how many of its technically-assessable controls we have actually assessed — for example \"2 of 9 assessed\". Controls no scanner can evaluate need an auditor, and the report says so." },
      { k: "Reports", v: "A Markdown report per framework, listing each gap with the findings that cite it. It opens with an explicit statement that an automated assessment is not a certification." },
      { k: "Evidence pack", v: "Signed with ed25519 over canonical JSON, covering the findings and the state they were assessed against — so an auditor can re-run the proof rather than trust a screenshot." },
      { k: "Access review", v: "The periodic review SOC 2 CC6.2/CC6.3 asks for. Accounts are rebuilt from current findings each time you open it, and a named person keeps or removes each one. A review with nobody in it is never reported as complete." },
      { k: "Trust Center", v: "A shareable page for your own customers, showing assessment coverage per framework. It only makes claims we can back — a workspace that has not been scanned does not advertise continuous monitoring." },
    ],
  },
  {
    id: "data-in",
    title: "Bringing in what we cannot reach",
    intro:
      "Some surfaces need data from a system we do not have a connector for yet. Each of these accepts a posted snapshot and assesses it with the same grounded checks, and each tells you which checks it could not run on what you sent.",
    rows: [
      { k: "POST /v1/devices/ingest", v: "Laptop and phone posture from your MDM export — disk encryption, screen lock, OS support, EDR." },
      { k: "POST /v1/identity/events", v: "IdP audit events. Detection is correlation-based, so the response names any rule your batch had no material to exercise." },
      { k: "POST /v1/tprm/ingest", v: "Vendor inventory — certifications, data access, DPAs, review dates." },
      { k: "POST /v1/cloud/inventory", v: "Raw cloud state when you would rather post it than grant a role. An inventory with no resources is refused, not stored." },
      { k: "POST /v1/saas/{provider}/snapshot", v: "SaaS configuration for GitHub org, Slack, Zoom, Atlassian, Salesforce, M365 or Google Workspace." },
      { k: "POST /v1/import", v: "Your existing Snyk, Dependabot or SARIF backlog, so day one is not an empty dashboard." },
    ],
  },
  {
    id: "limits",
    title: "What we do not do",
    intro:
      "The fastest way to lose your trust is to let you discover a limit on your own. These are the ones worth knowing before you start.",
    rows: [
      { k: "We are not a SIEM", v: "We export findings as newline-delimited JSON for Splunk, Datadog, Panther or Elastic. We do not ingest and triage your logs." },
      { k: "Mobile is source-only", v: "We scan Android and iOS source in a connected repo. We do not decompile a built APK or IPA." },
      { k: "Compliance is not certification", v: "We produce the evidence and the gap list. An auditor issues the report, and a named human signs anything that carries accountability." },
      { k: "Agents need a model", v: "The deterministic engine runs on every plan. The AI Security Engineer and AI Pentester need an LLM key, and their quality depends on the model you configure." },
    ],
  },
];
