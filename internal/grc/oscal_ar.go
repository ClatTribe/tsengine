package grc

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// OSCAL Assessment-Results — the PER-TENANT findings-as-evidence artifact (the documented next OSCAL
// output alongside the tenant-independent component-definition in oscal.go). Where the component-definition
// says "these are the controls tsengine CAN assess", the assessment-results say "here is what we assessed
// on THIS tenant, and the evidence": each control becomes an OSCAL finding with a satisfied/not-satisfied
// status, and each security finding that drove a gap becomes an OSCAL observation the control finding cites.
// This is the format a FedRAMP/OSCAL-native GRC tool or auditor ingests directly.
//
// Grounded (§10): a control's status comes from its real ControlState; a not-satisfied control's cited
// observations come ONLY from the findings its EvidenceRefs point at (the finding that PROVED the gap), so
// nothing is asserted without a backing finding. Deterministic (detUUID over content) → diffable across runs.

type oscalARDoc struct {
	AssessmentResults oscalAR `json:"assessment-results"`
}
type oscalAR struct {
	UUID     string          `json:"uuid"`
	Metadata oscalMetadata   `json:"metadata"`
	ImportAP oscalImportAP   `json:"import-ap"`
	Results  []oscalARResult `json:"results"`
}
type oscalImportAP struct {
	Href string `json:"href"`
}
type oscalARResult struct {
	UUID         string             `json:"uuid"`
	Title        string             `json:"title"`
	Description  string             `json:"description"`
	Start        string             `json:"start"`
	End          string             `json:"end"`
	Observations []oscalObservation `json:"observations,omitempty"`
	Findings     []oscalARFinding   `json:"findings,omitempty"`
}
type oscalObservation struct {
	UUID        string   `json:"uuid"`
	Description string   `json:"description"`
	Methods     []string `json:"methods"`
	Collected   string   `json:"collected"`
}
type oscalARFinding struct {
	UUID                string            `json:"uuid"`
	Title               string            `json:"title"`
	Description         string            `json:"description"`
	Target              oscalTarget       `json:"target"`
	RelatedObservations []oscalRelatedObs `json:"related-observations,omitempty"`
}
type oscalTarget struct {
	Type     string            `json:"type"`
	TargetID string            `json:"target-id"`
	Status   oscalTargetStatus `json:"status"`
}
type oscalTargetStatus struct {
	State string `json:"state"`
}
type oscalRelatedObs struct {
	ObservationUUID string `json:"observation-uuid"`
}

// OSCALAssessmentResults renders a tenant's assessed control states + the findings that back them as an
// OSCAL 1.1 assessment-results document. states are the tenant's ControlStates (any framework);
// findingsByID resolves an EvidenceRef (finding id) to its finding for the observation text. Deterministic
// + sorted, so an auditor diffing two exports sees only real changes.
func OSCALAssessmentResults(tenantName string, states []platform.ControlState, findingsByID map[string]types.Finding, now time.Time) ([]byte, error) {
	// stable order: by framework then control id.
	ss := append([]platform.ControlState(nil), states...)
	sort.Slice(ss, func(i, j int) bool {
		if ss[i].Framework != ss[j].Framework {
			return ss[i].Framework < ss[j].Framework
		}
		return ss[i].ControlID < ss[j].ControlID
	})

	// observations: one per DISTINCT finding cited by any assessed control (that actually exists).
	obsSeen := map[string]bool{}
	for _, cs := range ss {
		for _, fid := range cs.EvidenceRefs {
			if _, ok := findingsByID[fid]; ok {
				obsSeen[fid] = true
			}
		}
	}
	obsIDs := make([]string, 0, len(obsSeen))
	for id := range obsSeen {
		obsIDs = append(obsIDs, id)
	}
	sort.Strings(obsIDs)
	var observations []oscalObservation
	for _, fid := range obsIDs {
		f := findingsByID[fid]
		collected := now
		if !f.DiscoveredAt.IsZero() {
			collected = f.DiscoveredAt
		}
		desc := fmt.Sprintf("%s — severity %s, tool %s", firstNonEmpty(f.Title, f.RuleID, f.ID), f.Severity, f.Tool)
		if f.Endpoint != "" {
			desc += ", at " + f.Endpoint
		}
		observations = append(observations, oscalObservation{
			UUID:        detUUID("obs:" + fid),
			Description: desc,
			Methods:     []string{"EXAMINE"}, // an automated scan examining the target's state
			Collected:   collected.UTC().Format(time.RFC3339),
		})
	}

	// findings: one per assessed control, satisfied/not-satisfied from its real state, gaps citing the
	// observations that proved them.
	var findings []oscalARFinding
	for _, cs := range ss {
		state := "satisfied"
		if cs.State == platform.ControlGap {
			state = "not-satisfied"
		}
		fw := frameworkTitleFor(cs.Framework)
		af := oscalARFinding{
			UUID:        detUUID("arf:" + cs.Framework + ":" + cs.ControlID),
			Title:       fmt.Sprintf("%s %s — %s", fw, cs.ControlID, state),
			Description: fmt.Sprintf("Control %s under %s is %s as of the latest assessment.", cs.ControlID, fw, state),
			Target: oscalTarget{
				Type:     "objective-id",
				TargetID: cs.ControlID,
				Status:   oscalTargetStatus{State: state},
			},
		}
		for _, fid := range cs.EvidenceRefs {
			if _, ok := findingsByID[fid]; ok {
				af.RelatedObservations = append(af.RelatedObservations, oscalRelatedObs{ObservationUUID: detUUID("obs:" + fid)})
			}
		}
		findings = append(findings, af)
	}

	nowStr := now.UTC().Format(time.RFC3339)
	doc := oscalARDoc{AssessmentResults: oscalAR{
		UUID: detUUID("ar:" + tenantName),
		Metadata: oscalMetadata{
			Title:        "tsengine assessment results — " + tenantName,
			LastModified: nowStr,
			Version:      now.UTC().Format("2006-01-02"),
			OSCALVersion: oscalVersion,
		},
		// OSCAL requires an import-ap reference; tsengine's assessment is continuous (no discrete plan doc),
		// so this names the continuous-assessment program rather than a one-off plan.
		ImportAP: oscalImportAP{Href: "urn:tsengine:assessment-plan:continuous"},
		Results: []oscalARResult{{
			UUID:         detUUID("result:" + tenantName),
			Title:        "Continuous control assessment",
			Description:  "Automated, grounded assessment of the tenant's controls; every not-satisfied control cites the observation (finding) that proves the gap.",
			Start:        nowStr,
			End:          nowStr,
			Observations: observations,
			Findings:     findings,
		}},
	}}
	return json.MarshalIndent(doc, "", "  ")
}

// frameworkTitleFor is the human framework title for the OSCAL text, falling back to the raw key.
func frameworkTitleFor(fw string) string {
	if cat, ok := frameworkCatalog[fw]; ok {
		return cat.title
	}
	return fw
}

// firstNonEmpty returns the first non-empty string (local helper; grc has no shared one).
func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// OSCALAssessmentResults builds the per-tenant findings-as-evidence OSCAL document from the tenant's live
// control posture across every framework + the findings that back the gaps. Tenant-scoped.
func (g *GRC) OSCALAssessmentResults(ctx context.Context, tenantID string) ([]byte, error) {
	var states []platform.ControlState
	for _, fw := range Frameworks {
		cs, err := g.Posture(ctx, tenantID, fw)
		if err != nil {
			return nil, err
		}
		states = append(states, cs...)
	}
	findingsByID := map[string]types.Finding{}
	if fs, err := g.Store.ListFindings(ctx, tenantID, store.FindingFilter{}); err == nil {
		for _, f := range fs {
			findingsByID[f.ID] = f
		}
	}
	tenantName := tenantID
	if t, err := g.Store.GetTenant(ctx, tenantID); err == nil && t.Name != "" {
		tenantName = t.Name
	}
	return OSCALAssessmentResults(tenantName, states, findingsByID, g.now())
}
