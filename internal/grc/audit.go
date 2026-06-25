package grc

import (
	"sort"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// Audit engagement helpers — "audit-ready, not the audit". The product assembles the controls to be
// attested from the tenant's posture; the independent human auditor renders the verdict. These are
// pure, grounded helpers (no LLM, no guessing): the control list comes from the real control state,
// and progress/readiness are tallies over the auditor's recorded attestations.

// SeedAttestations builds the pending control-attestation list for an engagement from the controls
// the tenant actually has for the framework. Deterministic order (by control id). Each starts
// pending — only the named auditor can move it to passed/exception.
func SeedAttestations(framework string, controlIDs []string) []platform.ControlAttestation {
	ids := append([]string(nil), controlIDs...)
	sort.Strings(ids)
	out := make([]platform.ControlAttestation, 0, len(ids))
	seen := map[string]bool{}
	for _, id := range ids {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, platform.ControlAttestation{Framework: framework, ControlID: id, Verdict: platform.AttestPending})
	}
	return out
}

// AuditSummary is the at-a-glance state of an audit engagement.
type AuditSummary struct {
	Total      int  `json:"total"`
	Attested   int  `json:"attested"` // passed + exception
	Passed     int  `json:"passed"`
	Exceptions int  `json:"exceptions"`
	Pending    int  `json:"pending"`
	Percent    int  `json:"percent"` // attested/total, 0–100
	Ready      bool `json:"ready"`   // every control attested AND no open exceptions
}

// SummarizeAudit tallies an engagement's attestations. Grounded in the recorded verdicts.
func SummarizeAudit(e platform.AuditEngagement) AuditSummary {
	s := AuditSummary{Total: len(e.Attestations)}
	for _, c := range e.Attestations {
		switch c.Verdict {
		case platform.AttestPassed:
			s.Passed++
			s.Attested++
		case platform.AttestException:
			s.Exceptions++
			s.Attested++
		default:
			s.Pending++
		}
	}
	if s.Total > 0 {
		s.Percent = s.Attested * 100 / s.Total
	}
	s.Ready = s.Total > 0 && s.Pending == 0 && s.Exceptions == 0
	return s
}
