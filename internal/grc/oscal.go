package grc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// oscal.go emits the compliance crosswalk as an OSCAL component-definition (NIST's machine-readable controls
// language — the same format FedRAMP runs on). This makes the engine's control coverage INTEROPERABLE: a
// customer's GRC platform or an auditor's tooling ingests "which controls tsengine assesses, across which
// frameworks" directly, instead of a bespoke JSON. Self-contained (no required import of an SSP/assessment-plan),
// so it's a clean standalone artifact. §10: it states only the controls the crosswalk actually maps — never a
// padded catalog. Per-tenant findings-as-evidence (OSCAL Assessment Results) is the documented next artifact.

const oscalVersion = "1.1.2"

// frameworkCatalog maps our framework key to the human title + the catalog source URI an OSCAL
// control-implementation references (the standard the control-ids belong to). Where NIST publishes an official
// OSCAL catalog (800-53) we cite it; otherwise we cite the standard's authority, honestly labelled.
var frameworkCatalog = map[string]struct{ title, source string }{
	"nist_800_53":  {"NIST SP 800-53 Rev 5", "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"},
	"nist_800_171": {"NIST SP 800-171 Rev 2", "https://csrc.nist.gov/publications/detail/sp/800-171/rev-2/final"},
	"nist_csf":     {"NIST CSF 2.0", "https://www.nist.gov/cyberframework"},
	"soc2":         {"AICPA SOC 2 (Trust Services Criteria)", "https://www.aicpa.org/tsc"},
	"pci":          {"PCI DSS v4.0", "https://www.pcisecuritystandards.org/"},
	"hipaa":        {"HIPAA Security Rule", "https://www.hhs.gov/hipaa/for-professionals/security/"},
	"iso27001":     {"ISO/IEC 27001:2022", "https://www.iso.org/standard/27001"},
	"iso27701":     {"ISO/IEC 27701:2019", "https://www.iso.org/standard/71670.html"},
	"iso27018":     {"ISO/IEC 27018:2019", "https://www.iso.org/standard/76559.html"},
	"iso22301":     {"ISO 22301:2019", "https://www.iso.org/standard/75106.html"},
	"iso42001":     {"ISO/IEC 42001:2023", "https://www.iso.org/standard/81230.html"},
	"gdpr":         {"EU GDPR", "https://gdpr-info.eu/"},
	"ccpa":         {"CCPA/CPRA", "https://oag.ca.gov/privacy/ccpa"},
	"cis_v8":       {"CIS Controls v8", "https://www.cisecurity.org/controls/v8"},
	"fedramp":      {"FedRAMP Moderate", "https://www.fedramp.gov/"},
	"cmmc":         {"CMMC 2.0 (Level 2)", "https://dodcio.defense.gov/CMMC/"},
	"sox":          {"SOX (IT General Controls)", "https://www.sec.gov/"},
	"glba":         {"GLBA Safeguards Rule", "https://www.ftc.gov/"},
	"dpdp":         {"India DPDP Act 2023", "https://www.meity.gov.in/"},
	"nist_ai_rmf":  {"NIST AI RMF 1.0", "https://www.nist.gov/itl/ai-risk-management-framework"},
	"eu_ai_act":    {"EU AI Act", "https://artificialintelligenceact.eu/"},
	"pipeda":       {"PIPEDA (Canada)", "https://www.priv.gc.ca/"},
}

// OSCAL component-definition types (the subset we emit). Field tags are the OSCAL kebab-case JSON keys.
type oscalDoc struct {
	ComponentDefinition oscalCompDef `json:"component-definition"`
}
type oscalCompDef struct {
	UUID       string           `json:"uuid"`
	Metadata   oscalMetadata    `json:"metadata"`
	Components []oscalComponent `json:"components"`
}
type oscalMetadata struct {
	Title        string `json:"title"`
	LastModified string `json:"last-modified"`
	Version      string `json:"version"`
	OSCALVersion string `json:"oscal-version"`
}
type oscalComponent struct {
	UUID                   string             `json:"uuid"`
	Type                   string             `json:"type"`
	Title                  string             `json:"title"`
	Description            string             `json:"description"`
	ControlImplementations []oscalControlImpl `json:"control-implementations"`
}
type oscalControlImpl struct {
	UUID                    string         `json:"uuid"`
	Source                  string         `json:"source"`
	Description             string         `json:"description"`
	ImplementedRequirements []oscalImplReq `json:"implemented-requirements"`
}
type oscalImplReq struct {
	UUID        string `json:"uuid"`
	ControlID   string `json:"control-id"`
	Description string `json:"description"`
}

// OSCALComponentDefinition renders the crosswalk's per-framework control coverage as an OSCAL
// component-definition JSON. controlsByFramework is our-framework-key → the control IDs we map (e.g. from
// hooks.ControlsFor over grc.Frameworks). Deterministic: UUIDs are derived from content (stable output, so an
// auditor diffing two exports sees only real changes), and frameworks/controls are sorted.
func OSCALComponentDefinition(controlsByFramework map[string][]string, now time.Time) ([]byte, error) {
	comp := oscalComponent{
		UUID:        detUUID("component:tsengine"),
		Type:        "software",
		Title:       "tsengine (TensorShield) security & compliance engine",
		Description: "Continuously assesses the tenant's assets and maps every finding to the compliance controls it affects (grounded — only where a real control nexus exists).",
	}
	frameworks := make([]string, 0, len(controlsByFramework))
	for fw := range controlsByFramework {
		if len(controlsByFramework[fw]) > 0 {
			frameworks = append(frameworks, fw)
		}
	}
	sort.Strings(frameworks)
	for _, fw := range frameworks {
		cat, ok := frameworkCatalog[fw]
		if !ok {
			cat = struct{ title, source string }{fw, "urn:tsengine:framework:" + fw}
		}
		ci := oscalControlImpl{
			UUID:        detUUID("ci:" + fw),
			Source:      cat.source,
			Description: "Controls tsengine assesses under " + cat.title + ".",
		}
		ctrls := append([]string(nil), controlsByFramework[fw]...)
		sort.Strings(ctrls)
		for _, c := range ctrls {
			ci.ImplementedRequirements = append(ci.ImplementedRequirements, oscalImplReq{
				UUID:        detUUID("ir:" + fw + ":" + c),
				ControlID:   c,
				Description: "Assessed by tsengine via grounded finding→control mapping.",
			})
		}
		comp.ControlImplementations = append(comp.ControlImplementations, ci)
	}
	doc := oscalDoc{ComponentDefinition: oscalCompDef{
		UUID: detUUID("compdef:tsengine"),
		Metadata: oscalMetadata{
			Title:        "tsengine compliance control coverage",
			LastModified: now.UTC().Format(time.RFC3339),
			Version:      now.UTC().Format("2006-01-02"),
			OSCALVersion: oscalVersion,
		},
		Components: []oscalComponent{comp},
	}}
	return json.MarshalIndent(doc, "", "  ")
}

// OSCAL builds the OSCAL component-definition for the engine's full crosswalk coverage (every framework's
// mapped controls, via the injected ControlUniverse). Tenant-independent — it documents what the engine
// assesses, not a tenant's findings (per-tenant findings-as-evidence is the future Assessment-Results artifact).
func (g *GRC) OSCAL(ctx context.Context) ([]byte, error) {
	if g.ControlUniverse == nil {
		return nil, fmt.Errorf("control universe unavailable")
	}
	ctrls := map[string][]string{}
	for _, fw := range Frameworks {
		if c := g.ControlUniverse(fw); len(c) > 0 {
			ctrls[fw] = c
		}
	}
	return OSCALComponentDefinition(ctrls, g.now())
}

// detUUID derives a stable RFC-4122-shaped UUID (v5-like, name-based) from a seed, so the OSCAL output is
// deterministic + diffable. It's a real 36-char UUID string with the version/variant nibbles set.
func detUUID(seed string) string {
	h := sha256.Sum256([]byte("tsengine-oscal:" + seed))
	b := h[:16]
	b[6] = (b[6] & 0x0f) | 0x50 // version 5
	b[8] = (b[8] & 0x3f) | 0x80 // RFC-4122 variant
	s := hex.EncodeToString(b)
	return fmt.Sprintf("%s-%s-%s-%s-%s", s[0:8], s[8:12], s[12:16], s[16:20], s[20:32])
}
