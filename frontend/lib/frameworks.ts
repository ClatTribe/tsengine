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
  "iso27018",
  "iso22301",
  "pipeda",
  "glba",
  "eu_ai_act",
  "certin",
  "rbi",
  "sebi",
  "dora",
  "cyber_essentials",
] as const;

// THE display order for framework category groups — and the ONLY list any page should map over.
//
// Four pages each kept their own hardcoded copy of this array, and every one of them had drifted:
// /frameworks, the nav dropdown and the app compliance page all omitted "India regulatory", and
// /product omitted "AI governance" as well. A page that groups by a hardcoded category list
// SILENTLY DROPS any framework whose category isn't on it — so CERT-In, RBI and SEBI shipped in
// the engine and appeared on no marketing page at all, while pricing was denominated in ₹.
//
// `frameworkGroups()` below is the fix: it derives groups from FRAMEWORK_CATEGORY, renders known
// categories in this order, and APPENDS any unknown category rather than discarding it. Adding a
// framework in a new category now surfaces everywhere by default; hiding one takes a deliberate act.
export const FRAMEWORK_CATEGORY_ORDER = [
  "Security & trust",
  "Sector & payments",
  "Privacy",
  "Government",
  "India regulatory",
  "AI governance",
] as const;

/** Frameworks grouped for display. Never drops a framework whose category is unlisted. */
export function frameworkGroups(): { cat: string; items: string[] }[] {
  const byCat = new Map<string, string[]>();
  for (const f of FRAMEWORKS) {
    const cat = FRAMEWORK_CATEGORY[f] ?? "Other";
    byCat.set(cat, [...(byCat.get(cat) ?? []), f]);
  }
  const known = FRAMEWORK_CATEGORY_ORDER.filter((c) => byCat.has(c)).map((c) => ({ cat: c as string, items: byCat.get(c)! }));
  const extra = [...byCat.keys()]
    .filter((c) => !(FRAMEWORK_CATEGORY_ORDER as readonly string[]).includes(c))
    .map((c) => ({ cat: c, items: byCat.get(c)! }));
  return [...known, ...extra];
}

// THE framework count for all customer-facing copy. Derived, never typed.
//
// Twenty marketing and app strings hardcoded "22" while the engine shipped 25 — the count grew
// when CERT-In, RBI and SEBI landed and the copy never followed. That understated the product to
// exactly the buyer it was added for (pricing is denominated in ₹), and it contradicted
// /frameworks, which renders this array and therefore already showed 25.
export const FRAMEWORK_COUNT = FRAMEWORKS.length;

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
  iso27018: "ISO 27018",
  iso22301: "ISO 22301",
  pipeda: "PIPEDA",
  glba: "GLBA",
  eu_ai_act: "EU AI Act",
  certin: "CERT-In",
  rbi: "RBI CSF",
  sebi: "SEBI CSCRF",
  dora: "EU DORA",
  cyber_essentials: "UK Cyber Essentials",
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
  iso27018: "ISO/IEC 27018:2019 — protecting personally identifiable information in public clouds.",
  iso22301: "ISO 22301:2019 — business continuity management for resilience and recoverability.",
  pipeda: "Canada's PIPEDA — fair-information principles for handling personal data.",
  glba: "US GLBA Safeguards Rule — protecting customer financial information (16 CFR 314).",
  eu_ai_act: "The EU AI Act — risk-based obligations for high-risk AI systems.",
  certin: "CERT-In Directions 2022 — India's mandatory six-hour cyber-incident reporting and log-retention duties.",
  rbi: "RBI Cyber Security Framework — the Reserve Bank of India's Annex I baseline controls for regulated entities.",
  sebi: "SEBI CSCRF — the Cybersecurity and Cyber Resilience Framework for SEBI-regulated entities.",
  dora: "EU DORA (Reg. 2022/2554) — ICT operational resilience for financial entities. Mapped to the ICT-risk articles a finding can actually evidence (identification, protection and prevention, detection, resilience testing); its governance, incident-reporting and contractual duties are procedural and are not claimed.",
  cyber_essentials: "UK Cyber Essentials — the NCSC scheme's five technical controls. Coarse by design, so many findings land on the same control.",
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
  iso27018: "Privacy",
  iso22301: "Security & trust",
  pipeda: "Privacy",
  glba: "Sector & payments",
  eu_ai_act: "AI governance",
  certin: "India regulatory",
  rbi: "India regulatory",
  sebi: "India regulatory",
  dora: "Sector & payments",
  cyber_essentials: "Security & trust",
  nist_800_53: "Government",
  nist_800_171: "Government",
  fedramp: "Government",
};
