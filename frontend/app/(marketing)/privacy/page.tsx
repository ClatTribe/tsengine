import { pageMeta } from "@/lib/seo";
import { LegalDoc, type LegalSection } from "@/components/marketing/legal-doc";

export const metadata = pageMeta({
  title: "Privacy Policy — TensorShield",
  description: "How TensorShield collects, uses, protects, and shares data — in plain English.",
  path: "/privacy",
});

const SECTIONS: LegalSection[] = [
  {
    h: "Who we are",
    body: [
      "TensorShield ([legal entity name], India) provides an autonomous security and compliance platform. This policy explains what personal and organizational data we process when you use our website and product, and your rights over it. It is written to align with the EU GDPR, India's DPDP Act 2023, and CCPA/CPRA.",
    ],
  },
  {
    h: "Data we collect",
    body: [
      "Account data — your name, work email, organization name, and password (stored only as a salted PBKDF2 hash, never in plaintext).",
      "Connection credentials — when you connect a system (GitHub, Google Workspace, cloud account, etc.), the OAuth tokens we receive to scan it. These are encrypted at rest (AES-256-GCM) the moment they reach us and are never returned to the browser.",
      "Scan data — the security findings, asset inventory, and compliance posture produced by scanning the systems you connect or the targets you add.",
      "Usage and technical data — log, device, and request metadata used to operate, secure, and improve the service.",
      "We do not collect special-category data deliberately, and we ask that you do not upload it.",
    ],
  },
  {
    h: "How we use it",
    body: [
      "To run the security scans and compliance mapping you ask for, prepare remediations, and show you your posture.",
      "To authenticate you, secure the service, prevent abuse, and provide support.",
      "To operate billing and send service communications (and, only with your consent, product updates).",
      "We do not sell your personal information, and we do not use your scan data to train shared models.",
    ],
  },
  {
    h: "AI processing",
    body: [
      "On paid plans, an AI model assists with prioritization, remediation, and explanations. The relevant finding context is sent to the model provider (our configured subprocessor, or your own model if you bring your key) only to generate that response, and is not used by them to train their models. On the Free plan, no AI model runs, so no data leaves for AI processing.",
    ],
  },
  {
    h: "How we protect it",
    body: [
      "Tenant isolation is enforced on every data access, so one customer can never read another's data. Secrets are encrypted at rest; traffic is encrypted in transit (TLS). Access is least-privilege, and every consequential automated or human action is recorded in a signed, tamper-evident ledger.",
    ],
  },
  {
    h: "Sharing & subprocessors",
    body: [
      "We share data only with the vetted subprocessors that help us run the service (hosting, AI, email) and only as needed. The current list is on our Subprocessors page. We may also disclose data where legally required, or to protect rights and safety.",
    ],
  },
  {
    h: "Retention",
    body: [
      "We keep your data for as long as your account is active and as needed to provide the service, then delete or anonymize it within [N days] of account closure, except where a longer period is legally required.",
    ],
  },
  {
    h: "Your rights",
    body: [
      "Depending on your jurisdiction, you may access, correct, export, or delete your personal data, object to or restrict processing, and withdraw consent. Exercise any of these by emailing privacy@tensorshield.io; we respond within the period your law requires.",
    ],
  },
  {
    h: "International transfers",
    body: [
      "We may process data outside your country (e.g. with a subprocessor) under appropriate safeguards such as Standard Contractual Clauses.",
    ],
  },
  {
    h: "Changes & contact",
    body: [
      "We'll update this page and the date above when this policy changes. Questions or requests: privacy@tensorshield.io.",
    ],
  },
];

export default function Privacy() {
  return (
    <LegalDoc
      title="Privacy Policy"
      updated="28 June 2026"
      intro="We keep this short and honest: here's exactly what data TensorShield handles, why, how we protect it, and what control you have over it."
      sections={SECTIONS}
    />
  );
}
