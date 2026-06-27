import { pageMeta } from "@/lib/seo";
import { LegalDoc, type LegalSection } from "@/components/marketing/legal-doc";

export const metadata = pageMeta({
  title: "Data Processing Agreement — TensorShield",
  description: "How TensorShield processes personal data on your behalf as a processor (GDPR Art. 28 / DPDP).",
  path: "/dpa",
});

const SECTIONS: LegalSection[] = [
  {
    h: "Roles",
    body: [
      "For the personal data contained in the systems you connect and the findings we produce, you are the controller (or business) and TensorShield is the processor (or service provider), acting only on your documented instructions. This DPA forms part of, and is governed by, our Terms of Service.",
    ],
  },
  {
    h: "Scope & purpose of processing",
    body: [
      "Subject matter: providing the security scanning, compliance mapping, remediation, and evidence service.",
      "Duration: for the term of your subscription, plus the deletion window below.",
      "Nature & purpose: scanning the targets you authorize, producing findings and posture, and the related platform operations.",
      "Data subjects: your personnel and any individuals whose data appears in the systems you connect.",
      "Data types: account identifiers, connection metadata and tokens, and whatever appears in scan results (we ask you not to feed us special-category data).",
    ],
  },
  {
    h: "Our obligations",
    body: [
      "We process personal data only on your instructions and for the purposes above; we do not sell it or use it to train shared models.",
      "We ensure people authorized to process it are bound by confidentiality.",
      "We implement appropriate technical and organizational measures (see Security measures).",
      "We assist you, taking into account the nature of processing, with data-subject requests, security, breach notification, and DPIAs.",
    ],
  },
  {
    h: "Subprocessors",
    body: [
      "You authorize us to engage the subprocessors listed on our Subprocessors page to help deliver the service. Each is bound by data-protection terms at least as protective as this DPA. We'll give you notice of new subprocessors and a chance to object on reasonable grounds.",
    ],
  },
  {
    h: "Security measures",
    body: [
      "Tenant isolation enforced on every access; OAuth tokens and secrets encrypted at rest (AES-256-GCM); TLS in transit; least-privilege access; a signed, tamper-evident decision ledger; per-tenant kill-switch; and hardened, isolated scan sandboxes. We review and improve these measures over time.",
    ],
  },
  {
    h: "Breach notification",
    body: [
      "We will notify you without undue delay after becoming aware of a personal-data breach affecting your data, with the information you need to meet your own notification obligations.",
    ],
  },
  {
    h: "Data-subject requests & deletion",
    body: [
      "We will help you respond to access, correction, deletion, and portability requests. On termination, we delete or return your personal data within [N days], except where retention is legally required.",
    ],
  },
  {
    h: "International transfers & audit",
    body: [
      "Where data is transferred across borders, we rely on appropriate safeguards such as Standard Contractual Clauses. On reasonable request and notice, we will make available the information needed to demonstrate compliance and, where required, allow for audits subject to confidentiality.",
    ],
  },
  {
    h: "Contact",
    body: ["Data-protection questions or to request a counter-signed copy: privacy@tensorshield.io."],
  },
];

export default function DPA() {
  return (
    <LegalDoc
      title="Data Processing Agreement"
      updated="28 June 2026"
      intro="When we process personal data on your behalf, we do it as your processor. This DPA sets out the GDPR Art. 28 / DPDP terms that govern that — what we process, our obligations, and how we protect it."
      sections={SECTIONS}
    />
  );
}
