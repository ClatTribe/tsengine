// Compliance framework identifiers + labels. Kept in a neutral (non server-only) module so
// both Server Components and client components (the ⌘K palette) can import them.

export const FRAMEWORKS = ["soc2", "iso27001", "pci", "hipaa", "cis_v8", "nist_csf"] as const;

export const FRAMEWORK_LABEL: Record<string, string> = {
  soc2: "SOC 2",
  iso27001: "ISO 27001",
  pci: "PCI-DSS",
  hipaa: "HIPAA",
  cis_v8: "CIS v8",
  nist_csf: "NIST CSF",
};
