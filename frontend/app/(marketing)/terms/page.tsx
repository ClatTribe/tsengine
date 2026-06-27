import { pageMeta } from "@/lib/seo";
import { LegalDoc, type LegalSection } from "@/components/marketing/legal-doc";

export const metadata = pageMeta({
  title: "Terms of Service — TensorShield",
  description: "The terms governing your use of TensorShield, including authorized-scanning rules.",
  path: "/terms",
});

const SECTIONS: LegalSection[] = [
  {
    h: "Agreement",
    body: [
      "These Terms are a binding agreement between you (and the organization you represent) and TensorShield ([legal entity name], India). By creating an account or using the service, you accept them. If you don't agree, don't use the service.",
    ],
  },
  {
    h: "The service",
    body: [
      "TensorShield scans the systems and targets you authorize, identifies security and compliance issues, prepares remediations, and produces evidence. The exact capabilities available depend on your plan (see Pricing).",
    ],
  },
  {
    h: "Your account",
    body: [
      "You're responsible for your account, your team's access, and keeping credentials safe. You must give accurate information and promptly update it. You must be authorized to bind your organization.",
    ],
  },
  {
    h: "Authorized scanning — important",
    body: [
      "You may only point TensorShield at systems, domains, IPs, applications, and accounts that you own or are explicitly authorized to test. You represent and warrant that you have this authorization for every target you add or connect.",
      "You must not use the service to scan, probe, or attack any third party without authorization. Active testing (exploitation-style checks) runs only with your explicit, recorded consent and within the scope you define. Misuse is a material breach and may be unlawful; you are solely responsible for it and will indemnify us against claims arising from your unauthorized use.",
    ],
  },
  {
    h: "Acceptable use",
    body: [
      "Don't use the service to break the law, infringe rights, reverse-engineer or resell it without permission, interfere with its operation, or circumvent its safety controls (including the human-approval gate and kill-switch).",
    ],
  },
  {
    h: "Plans, billing & taxes",
    body: [
      "Paid plans are billed in advance (monthly or annually) at the prices on our Pricing page, exclusive of applicable taxes (including 18% GST in India). Fees are non-refundable except where required by law. We may change prices with notice effective at your next renewal. The Free plan is provided as-is and may change.",
    ],
  },
  {
    h: "Intellectual property",
    body: [
      "We own the platform and everything in it except your data. You keep ownership of your data and grant us only the limited licence needed to operate the service for you. The open-source tools we wrap remain under their own licences.",
    ],
  },
  {
    h: "Disclaimers",
    body: [
      "Security testing is inherently imperfect. The service is provided \"as is\" — we don't warrant that it will find every vulnerability, that findings are exhaustive, or that the service is error-free or uninterrupted. It is not a substitute for your own security judgment.",
    ],
  },
  {
    h: "Limitation of liability",
    body: [
      "To the maximum extent permitted by law, neither party is liable for indirect or consequential damages, and our total liability is capped at the fees you paid in the [12] months before the claim. Nothing here limits liability that cannot be limited by law.",
    ],
  },
  {
    h: "Termination",
    body: [
      "You may stop using the service at any time. We may suspend or terminate access for breach (especially unauthorized scanning) or non-payment. On termination we delete or return your data per the Privacy Policy.",
    ],
  },
  {
    h: "Governing law & contact",
    body: [
      "These Terms are governed by the laws of India, with exclusive jurisdiction in the courts of [city]. Questions: legal@tensorshield.io.",
    ],
  },
];

export default function Terms() {
  return (
    <LegalDoc
      title="Terms of Service"
      updated="28 June 2026"
      intro="The rules for using TensorShield. The one that matters most: only scan what you own or are authorized to test."
      sections={SECTIONS}
    />
  );
}
