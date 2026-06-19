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
  nist_800_53: "Government",
  nist_800_171: "Government",
  fedramp: "Government",
};
