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
// 80–95% acceptance).
//
// AN ANSWER OF "Yes" IS AN ATTESTATION TO SOMEONE ELSE'S PROCUREMENT TEAM, and this
// file used to make them for free. Answers were derived from control GAPS alone:
// a gap meant "In Progress", and everything else fell through to "Yes". A control
// record is only ever created when a finding cites it, so a control that was never
// assessed looks exactly like one that was assessed and clean — and the code
// resolved that ambiguity as "Yes". A brand-new tenant with nothing connected and
// nothing scanned therefore answered "Yes" to all ten questions, including "is MFA
// enforced?", in a document written to unblock an enterprise deal.
//
// "We looked and it was clean" and "we never looked" are different claims (the same
// rule internal/ctoreadiness holds for its observed rows). So an answer is only
// "Yes" when the EVIDENCE SOURCE that can actually answer it has been connected:
// no identity provider, no MFA answer. Otherwise the answer is "Not assessed",
// which is honest, and which a buyer can act on. Under-claiming is recoverable;
// attesting to a control we never examined is not.

// QQuestion is one standardized question mapped to the controls that evidence it.
type QQuestion struct {
	ID       string              `json:"id"`
	Domain   string              `json:"domain"`
	Text     string              `json:"text"`
	Controls map[string][]string `json:"controls"` // framework → control IDs
	// Sources names the evidence sources that can actually answer this question — the
	// connection kinds / asset types whose assessment produces the controls above.
	// Without at least one of them, the honest answer is "Not assessed": we cannot
	// attest to MFA with no identity provider connected, however few findings we hold.
	Sources []string `json:"sources"`
}

// standardQuestionnaire is the built-in CAIQ/SIG-lite set. Control mappings use
// the same IDs the compliance.map hook emits (CLAUDE.md §8), so a real gap on a
// mapped control flips the matching question to "In Progress".
func standardQuestionnaire() []QQuestion {
	return []QQuestion{
		{ID: "AC-1", Domain: "Access Control", Text: "Is multi-factor authentication enforced for administrative and user access?",
			Controls: map[string][]string{"soc2": {"CC6.1"}, "pci": {"8.3.1"}, "cis_v8": {"6.5"}}, Sources: []string{"identity"}},
		{ID: "AC-2", Domain: "Access Control", Text: "Are access privileges restricted to least privilege and reviewed regularly?",
			Controls: map[string][]string{"soc2": {"CC6.3"}, "iso27001": {"A.9.2"}}, Sources: []string{"identity", "cloud"}},
		{ID: "CR-1", Domain: "Cryptography", Text: "Is data encrypted in transit (TLS) and at rest?",
			Controls: map[string][]string{"soc2": {"CC6.6", "CC6.7"}, "pci": {"4.2.1"}}, Sources: []string{"web", "cloud"}},
		{ID: "VM-1", Domain: "Vulnerability Management", Text: "Are systems and dependencies continuously scanned for known vulnerabilities?",
			Controls: map[string][]string{"soc2": {"CC7.1"}, "pci": {"6.2.1", "6.3.1"}, "cis_v8": {"7.5"}}, Sources: []string{"repository", "container", "cloud"}},
		{ID: "VM-2", Domain: "Vulnerability Management", Text: "Are application security issues (injection, XSS, leaked secrets) identified before release?",
			Controls: map[string][]string{"soc2": {"CC8.1"}, "pci": {"6.2.4"}}, Sources: []string{"repository", "web", "api"}},
		{ID: "LM-1", Domain: "Logging & Monitoring", Text: "Are security-relevant events logged and monitored for anomalies?",
			Controls: map[string][]string{"soc2": {"CC7.2"}, "nist_csf": {"DE.CM-8"}}, Sources: []string{"cloud"}},
		{ID: "EM-1", Domain: "Email Security", Text: "Is the sending domain protected against spoofing (SPF, DKIM, DMARC enforced)?",
			Controls: map[string][]string{"cis_v8": {"9.5"}, "nist_csf": {"PR.DS-2"}}, Sources: []string{"domain", "identity"}},
		{ID: "VR-1", Domain: "Vendor / Third-Party", Text: "Are third-party app integrations inventoried and reviewed for risky scopes?",
			Controls: map[string][]string{"soc2": {"CC9.2"}, "iso27001": {"A.15.1"}}, Sources: []string{"identity", "saas"}},
		{ID: "IR-1", Domain: "Incident Response", Text: "Are security incidents detected, tracked, and resolved through a defined process?",
			Controls: map[string][]string{"soc2": {"CC7.3", "CC7.4"}, "nist_csf": {"RS.RP-1"}}, Sources: []string{"cloud", "repository", "web", "identity"}},
		{ID: "CM-1", Domain: "Configuration", Text: "Are container images and cloud configurations hardened against known misconfigurations?",
			Controls: map[string][]string{"soc2": {"CC6.8"}, "cis_v8": {"4.1"}}, Sources: []string{"container", "cloud"}},
	}
}

// The three answers. "Not assessed" exists because the alternative — inferring "Yes"
// from the absence of a finding — attests to a control nobody examined.
const (
	AnswerYes         = "Yes"
	AnswerInProgress  = "In Progress"
	AnswerNotAssessed = "Not assessed"
)

// QAnswer is the auto-derived answer with its grounding.
type QAnswer struct {
	QQuestion
	Answer string `json:"answer"` // AnswerYes | AnswerInProgress | AnswerNotAssessed
	// MissingSources names what would have to be connected for this question to be
	// answerable at all. Present only on a "Not assessed" answer, so the reader is told
	// exactly how to turn it into a real answer.
	MissingSources []string `json:"missing_sources,omitempty"`
	GapControls    []string `json:"gap_controls,omitempty"` // framework:control entries that are gaps
	EvidenceIDs    []string `json:"evidence_ids,omitempty"` // finding IDs behind a non-Yes answer
}

// Questionnaire is the auto-answered result — the attachable procurement deliverable.
type Questionnaire struct {
	TenantID    string    `json:"tenant_id"`
	GeneratedAt time.Time `json:"generated_at"`
	Answers     []QAnswer `json:"answers"`
	Yes         int       `json:"yes"`
	InProgress  int       `json:"in_progress"`
	// NotAssessed counts questions we refused to answer for want of an evidence source.
	// Deliberately a FIRST-CLASS number, not a footnote: a questionnaire that is mostly
	// "Not assessed" must look mostly unanswered to whoever sends it.
	NotAssessed int `json:"not_assessed"`
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

	// What has actually been connected/onboarded for this tenant — the proof that a
	// question's evidence source exists at all.
	sources, err := g.assessedSources(ctx, tenantID)
	if err != nil {
		return nil, err
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
		ans := QAnswer{QQuestion: q, Answer: AnswerYes}
		switch {
		case len(gapControls) > 0:
			// A real finding opened a gap on a mapped control — the strongest, most
			// specific answer, and it stands whether or not the source is connected.
			sort.Strings(gapControls)
			ans.Answer = AnswerInProgress
			ans.GapControls = gapControls
			ans.EvidenceIDs = dedupeStrings(evidence)
			res.InProgress++
		case !assessed(q.Sources, sources):
			// Nothing that could answer this question has been connected. Saying "Yes"
			// here would attest to a control we never examined.
			ans.Answer = AnswerNotAssessed
			ans.MissingSources = missing(q.Sources, sources)
			res.NotAssessed++
		default:
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
	fmt.Fprintf(&b, "_Auto-answered from live control state · %d Yes · %d In Progress · %d Not assessed · generated %s_\n\n",
		q.Yes, q.InProgress, q.NotAssessed, q.GeneratedAt.Format("2006-01-02"))
	// Say it above the table, not in a footnote: a reader must not skim a mostly-unanswered
	// questionnaire and come away thinking it was answered.
	if q.NotAssessed > 0 {
		fmt.Fprintf(&b, "> **%d of %d questions are not answered yet.** Nothing that can evidence them has been "+
			"connected, so they are reported as *Not assessed* rather than assumed compliant. The missing "+
			"source is named on each row.\n\n", q.NotAssessed, len(q.Answers))
	}
	b.WriteString("| # | Domain | Question | Answer | Evidence |\n|---|---|---|---|---|\n")
	for _, a := range q.Answers {
		ev := "—"
		switch a.Answer {
		case AnswerInProgress:
			ev = strings.Join(a.GapControls, ", ")
			if len(a.EvidenceIDs) > 0 {
				ev += " (" + strings.Join(a.EvidenceIDs, ", ") + ")"
			}
		case AnswerNotAssessed:
			ev = "connect " + strings.Join(a.MissingSources, " or ") + " to answer this"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | **%s** | %s |\n", a.ID, a.Domain, a.Text, a.Answer, ev)
	}
	b.WriteString("\n_Grounded: \"In Progress\" reflects a real finding that opened a control gap. \"Yes\" means the " +
		"evidence source was connected AND no finding contradicts the control. \"Not assessed\" means we have not " +
		"looked — never that we looked and found nothing._\n")
	return b.String()
}

// assessedSources returns the evidence sources this tenant actually has — derived from
// its connections and monitored assets. Grounded: a source counts only because a real
// connection or asset of that kind exists, never because a question expected one.
func (g *GRC) assessedSources(ctx context.Context, tenantID string) (map[string]bool, error) {
	out := map[string]bool{}
	conns, err := g.Store.ListConnections(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	for _, c := range conns {
		switch c.Kind {
		case platform.ConnGitHub:
			out["repository"] = true
		case platform.ConnAWS, platform.ConnGCP, platform.ConnAzure:
			out["cloud"] = true
		case platform.ConnGWorkspace, platform.ConnM365, platform.ConnOkta:
			out["identity"] = true
			out["domain"] = true // the IdP's verified domains carry the email-auth posture
		case platform.ConnSlack:
			out["saas"] = true
		}
	}
	assets, err := g.Store.ListAssets(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	for _, a := range assets {
		switch a.Type {
		case "repository":
			out["repository"] = true
		case "container_image":
			out["container"] = true
		case "web_application":
			out["web"] = true
		case "api":
			out["api"] = true
		case "domain":
			out["domain"] = true
		case "cloud_account":
			out["cloud"] = true
		case "workspace":
			out["identity"] = true
		}
	}
	return out, nil
}

// assessed reports whether ANY of a question's evidence sources is present. Any is
// enough: one connected identity provider genuinely answers the MFA question, and
// demanding all of them would under-report as badly as the old code over-reported.
func assessed(want []string, have map[string]bool) bool {
	if len(want) == 0 {
		return false // a question with no declared source can never be attested to
	}
	for _, w := range want {
		if have[w] {
			return true
		}
	}
	return false
}

// missing lists the sources that would make an unanswerable question answerable.
func missing(want []string, have map[string]bool) []string {
	var out []string
	for _, w := range want {
		if !have[w] {
			out = append(out, w)
		}
	}
	sort.Strings(out)
	return out
}
