package grc

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// Security-questionnaire automation (CAIQ / SIG-lite). A standardized question
// set auto-answered from the tenant's live control state — the #1 recurring SMB
// GRC value driver (Vanta/Drata/Sprinto auto-answer security questionnaires at
// 80–95% acceptance). Grounded exactly like the rest of GRC (§18.2 inv. 5): an
// answer is "In Progress" only because a real finding created a control gap;
// "Yes" means no finding contradicts the control. The engine never claims a
// posture it cannot back with evidence.

// QQuestion is one standardized question mapped to the controls that evidence it.
type QQuestion struct {
	ID       string              `json:"id"`
	Domain   string              `json:"domain"`
	Text     string              `json:"text"`
	Controls map[string][]string `json:"controls"` // framework → control IDs
}

// standardQuestionnaire is the built-in CAIQ/SIG-lite set. Control mappings use
// the same IDs the compliance.map hook emits (CLAUDE.md §8), so a real gap on a
// mapped control flips the matching question to "In Progress".
func standardQuestionnaire() []QQuestion {
	return []QQuestion{
		{ID: "AC-1", Domain: "Access Control", Text: "Is multi-factor authentication enforced for administrative and user access?",
			Controls: map[string][]string{"soc2": {"CC6.1"}, "pci": {"8.3.1"}, "cis_v8": {"6.5"}}},
		{ID: "AC-2", Domain: "Access Control", Text: "Are access privileges restricted to least privilege and reviewed regularly?",
			Controls: map[string][]string{"soc2": {"CC6.3"}, "iso27001": {"A.9.2"}}},
		{ID: "CR-1", Domain: "Cryptography", Text: "Is data encrypted in transit (TLS) and at rest?",
			Controls: map[string][]string{"soc2": {"CC6.6", "CC6.7"}, "pci": {"4.2.1"}}},
		{ID: "VM-1", Domain: "Vulnerability Management", Text: "Are systems and dependencies continuously scanned for known vulnerabilities?",
			Controls: map[string][]string{"soc2": {"CC7.1"}, "pci": {"6.2.1", "6.3.1"}, "cis_v8": {"7.5"}}},
		{ID: "VM-2", Domain: "Vulnerability Management", Text: "Are application security issues (injection, XSS, leaked secrets) identified before release?",
			Controls: map[string][]string{"soc2": {"CC8.1"}, "pci": {"6.2.4"}}},
		{ID: "LM-1", Domain: "Logging & Monitoring", Text: "Are security-relevant events logged and monitored for anomalies?",
			Controls: map[string][]string{"soc2": {"CC7.2"}, "nist_csf": {"DE.CM-8"}}},
		{ID: "EM-1", Domain: "Email Security", Text: "Is the sending domain protected against spoofing (SPF, DKIM, DMARC enforced)?",
			Controls: map[string][]string{"cis_v8": {"9.5"}, "nist_csf": {"PR.DS-2"}}},
		{ID: "VR-1", Domain: "Vendor / Third-Party", Text: "Are third-party app integrations inventoried and reviewed for risky scopes?",
			Controls: map[string][]string{"soc2": {"CC9.2"}, "iso27001": {"A.15.1"}}},
		{ID: "IR-1", Domain: "Incident Response", Text: "Are security incidents detected, tracked, and resolved through a defined process?",
			Controls: map[string][]string{"soc2": {"CC7.3", "CC7.4"}, "nist_csf": {"RS.RP-1"}}},
		{ID: "CM-1", Domain: "Configuration", Text: "Are container images and cloud configurations hardened against known misconfigurations?",
			Controls: map[string][]string{"soc2": {"CC6.8"}, "cis_v8": {"4.1"}}},
	}
}

// QAnswer is the auto-derived answer with its grounding.
type QAnswer struct {
	QQuestion
	Answer      string   `json:"answer"`                 // "Yes" | "In Progress"
	GapControls []string `json:"gap_controls,omitempty"` // framework:control entries that are gaps
	EvidenceIDs []string `json:"evidence_ids,omitempty"` // finding IDs behind a non-Yes answer
}

// Questionnaire is the auto-answered result — the attachable procurement deliverable.
type Questionnaire struct {
	TenantID    string    `json:"tenant_id"`
	GeneratedAt time.Time `json:"generated_at"`
	Answers     []QAnswer `json:"answers"`
	Yes         int       `json:"yes"`
	InProgress  int       `json:"in_progress"`
}

// Questionnaire auto-answers the standardized set from the tenant's control state.
func (g *GRC) Questionnaire(ctx context.Context, tenantID string) (*Questionnaire, error) {
	questions := standardQuestionnaire()

	// every framework the questions reference → fetch the tenant's gaps once
	fwSet := map[string]bool{}
	for _, q := range questions {
		for fw := range q.Controls {
			fwSet[fw] = true
		}
	}
	gaps := map[string]map[string][]string{} // framework → controlID → evidence finding IDs
	for fw := range fwSet {
		cs, err := g.Posture(ctx, tenantID, fw)
		if err != nil {
			return nil, err
		}
		m := map[string][]string{}
		for _, c := range cs {
			if c.State == platform.ControlGap {
				m[c.ControlID] = c.EvidenceRefs
			}
		}
		gaps[fw] = m
	}

	res := &Questionnaire{TenantID: tenantID, GeneratedAt: g.now()}
	for _, q := range questions {
		var gapControls, evidence []string
		for fw, ctrls := range q.Controls {
			for _, ctrl := range ctrls {
				if refs, ok := gaps[fw][ctrl]; ok {
					gapControls = append(gapControls, fw+":"+ctrl)
					evidence = append(evidence, refs...)
				}
			}
		}
		ans := QAnswer{QQuestion: q, Answer: "Yes"}
		if len(gapControls) > 0 {
			sort.Strings(gapControls)
			ans.Answer = "In Progress"
			ans.GapControls = gapControls
			ans.EvidenceIDs = dedupeStrings(evidence)
			res.InProgress++
		} else {
			res.Yes++
		}
		res.Answers = append(res.Answers, ans)
	}
	return res, nil
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// RenderQuestionnaireMarkdown is the attachable deliverable a buyer's procurement
// team can read.
func RenderQuestionnaireMarkdown(q *Questionnaire) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Security Questionnaire — %s\n\n", q.TenantID)
	fmt.Fprintf(&b, "_Auto-answered from live control state · %d Yes · %d In Progress · generated %s_\n\n",
		q.Yes, q.InProgress, q.GeneratedAt.Format("2006-01-02"))
	b.WriteString("| # | Domain | Question | Answer | Evidence |\n|---|---|---|---|---|\n")
	for _, a := range q.Answers {
		ev := "—"
		if a.Answer != "Yes" {
			ev = strings.Join(a.GapControls, ", ")
			if len(a.EvidenceIDs) > 0 {
				ev += " (" + strings.Join(a.EvidenceIDs, ", ") + ")"
			}
		}
		fmt.Fprintf(&b, "| %s | %s | %s | **%s** | %s |\n", a.ID, a.Domain, a.Text, a.Answer, ev)
	}
	b.WriteString("\n_Grounded: an \"In Progress\" answer reflects a real finding that created a control gap; " +
		"\"Yes\" means no finding contradicts the control._\n")
	return b.String()
}
