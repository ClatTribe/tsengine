// Compliance framework identifiers + labels. Kept in a neutral (non server-only) module so
// both Server Components and client components (the ⌘K palette) can import them.

export const FRAMEWORKS = [
  "soc2",
  "iso27001",
  "pci",
  "hipaa",
  "cis_v8",
  "nist_csf",
  "gdpr",
  "iso27701",
  "nist_800_53",
  "nist_800_171",
  "ccpa",
  "sox",
  "fedramp",
  "dpdp",
  "cmmc",
  "iso42001",
  "nist_ai_rmf",
] as const;

export const FRAMEWORK_LABEL: Record<string, string> = {
  soc2: "SOC 2",
  iso27001: "ISO 27001",
  pci: "PCI-DSS",
  hipaa: "HIPAA",
  cis_v8: "CIS v8",
  nist_csf: "NIST CSF",
  gdpr: "GDPR",
  iso27701: "ISO 27701",
  nist_800_53: "NIST 800-53",
  nist_800_171: "NIST 800-171",
  ccpa: "CCPA",
  sox: "SOX",
  fedramp: "FedRAMP",
  dpdp: "DPDP",
  cmmc: "CMMC 2.0",
  iso42001: "ISO 42001 (AI)",
  nist_ai_rmf: "NIST AI RMF",
};

// FRAMEWORK_DESC — one-line plain-English descriptions, shown on the per-framework drill so
// a non-specialist owner knows what each standard is for.
export const FRAMEWORK_DESC: Record<string, string> = {
  soc2: "Trust Services Criteria — security & confidentiality for service organizations.",
  iso27001: "International standard for an information security management system (ISMS).",
  pci: "Payment Card Industry Data Security Standard — protecting cardholder data.",
  hipaa: "US healthcare Security Rule — safeguards for electronic protected health information.",
  cis_v8: "CIS Critical Security Controls — a prioritized set of defensive safeguards.",
  nist_csf: "NIST Cybersecurity Framework 2.0 — govern, identify, protect, detect, respond, recover.",
  gdpr: "EU General Data Protection Regulation — security of personal-data processing (Art. 32).",
  iso27701: "Privacy extension to ISO 27001 — a Privacy Information Management System (PIMS).",
  nist_800_53: "US federal control catalog for information systems (Rev. 5).",
  nist_800_171: "Protecting Controlled Unclassified Information (CUI) in non-federal systems.",
  ccpa: "California Consumer Privacy Act / CPRA — consumer data rights & reasonable security.",
  sox: "Sarbanes-Oxley IT general controls over financial-reporting systems.",
  fedramp: "US government cloud authorization baseline (Moderate), built on NIST 800-53.",
  dpdp: "India's Digital Personal Data Protection Act 2023 — safeguards for personal data.",
  cmmc: "US DoD Cybersecurity Maturity Model Certification 2.0 (Level 2) — defense supply-chain controls.",
  iso42001: "ISO/IEC 42001:2023 — the AI management-system standard for governing AI risk.",
  nist_ai_rmf: "NIST AI Risk Management Framework 1.0 — govern, map, measure, and manage AI risk.",
};

// FRAMEWORK_CATEGORY groups frameworks for the compliance grid's section headers, so a
// 14-framework list stays scannable instead of a flat wall of cards.
export const FRAMEWORK_CATEGORY: Record<string, string> = {
  soc2: "Security & trust",
  iso27001: "Security & trust",
  cis_v8: "Security & trust",
  nist_csf: "Security & trust",
  pci: "Sector & payments",
  hipaa: "Sector & payments",
  sox: "Sector & payments",
  gdpr: "Privacy",
  iso27701: "Privacy",
  ccpa: "Privacy",
  dpdp: "Privacy",
  cmmc: "Government",
  iso42001: "AI governance",
  nist_ai_rmf: "AI governance",
  nist_800_53: "Government",
  nist_800_171: "Government",
  fedramp: "Government",
};
