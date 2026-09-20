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

// QEvidence is HOW a question can be answered. The two are NOT interchangeable, and keeping
// them apart is what lets the corpus grow past the handful of things a scanner sees without
// the document quietly becoming a set of claims nobody checked.
//
// This mirrors internal/ctoreadiness, which had to make the same distinction for the same
// reason. The rule there and here: an OBSERVED question is never answered by someone typing,
// and an ATTESTED question is never inferred from findings.
type QEvidence string

const (
	// QObserved — a detector answers it. The answer is derived from control state and the
	// evidence source that produced it, and a human cannot overrule it by asserting otherwise.
	QObserved QEvidence = "observed"
	// QAttested — no scan can see it (background checks, physical security, whether the DR
	// plan was actually tested). A named human answers, and the answer is labelled as theirs.
	//
	// This is not a lesser answer — it is how every vendor answers these, and a questionnaire
	// that omitted them would be answering a different, easier document than the one a buyer
	// sent. What would be dishonest is rendering it identically to an evidenced one.
	QAttested QEvidence = "attested"
)

// QQuestion is one standardized question mapped to the controls that evidence it.
type QQuestion struct {
	ID       string              `json:"id"`
	Domain   string              `json:"domain"`
	Text     string              `json:"text"`
	Evidence QEvidence           `json:"evidence"`
	Controls map[string][]string `json:"controls,omitempty"` // framework → control IDs (observed only)
	// Sources names the evidence sources that can actually answer this question — the
	// connection kinds / asset types whose assessment produces the controls above.
	// Without at least one of them, the honest answer is "Not assessed": we cannot
	// attest to MFA with no identity provider connected, however few findings we hold.
	//
	// Empty on an ATTESTED question: there is no source, which is the whole reason it needs
	// a human.
	Sources []string `json:"sources,omitempty"`
	// Why explains an ATTESTED question — what we would have to be able to see to answer it
	// ourselves. Stated so a reader can tell "nobody has looked" from "nothing can look".
	Why string `json:"why,omitempty"`
}

// The three answers. "Not assessed" exists because the alternative — inferring "Yes"
// from the absence of a finding — attests to a control nobody examined.
const (
	AnswerYes         = "Yes"
	AnswerInProgress  = "In Progress"
	AnswerNotAssessed = "Not assessed"
	// AnswerNo is only ever reachable by a human ATTESTING that a practice is not in place.
	// It exists because a questionnaire that could not say no would be a form with one
	// possible answer, and a vendor honestly reporting "we do not run background checks" is
	// giving the buyer exactly the information they asked for.
	AnswerNo = "No"
	// AnswerNeedsYou is an ATTESTED question nobody has answered yet. Deliberately distinct
	// from "Not assessed": that one means no evidence source is connected and is fixable by
	// connecting one, this one means a person has to answer and no amount of connecting will
	// do it. Rendered alike, the reader is told to fix the wrong thing.
	AnswerNeedsYou = "Needs your answer"
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
	// AttestedBy/AttestedAt/AttestedNote record WHO answered an attested question and when.
	// Carried on the answer so the rendered document can say it: an assertion and an
	// observation must never look alike to a buyer, and the name is what separates them.
	AttestedBy   string `json:"attested_by,omitempty"`
	AttestedAt   string `json:"attested_at,omitempty"`
	AttestedNote string `json:"attested_note,omitempty"`
}

// Questionnaire is the auto-answered result — the attachable procurement deliverable.
type Questionnaire struct {
	TenantID string `json:"tenant_id"`
	// Org is the display name for the rendered document. Set by callers whose audience is
	// external (the Trust Center); empty in-app, where the tenant id is what the caller has and
	// nobody outside sees it.
	Org         string    `json:"org,omitempty"`
	GeneratedAt time.Time `json:"generated_at"`
	Answers     []QAnswer `json:"answers"`
	Yes         int       `json:"yes"`
	InProgress  int       `json:"in_progress"`
	// NotAssessed counts questions we refused to answer for want of an evidence source.
	// Deliberately a FIRST-CLASS number, not a footnote: a questionnaire that is mostly
	// "Not assessed" must look mostly unanswered to whoever sends it.
	NotAssessed int `json:"not_assessed"`
	// No and NeedsYou belong to the ATTESTED half. They are counted separately from the
	// observed ones rather than folded in, for the reason ctoreadiness gives for refusing a
	// single percentage: a number that mixed "a scanner confirmed this" with "somebody typed
	// yes" would be a figure nobody could act on, and it would RISE as a customer connected
	// less and asserted more.
	No       int `json:"no"`
	NeedsYou int `json:"needs_you"`
	// Observed/Attested are the corpus split, so a reader can size the two halves without
	// counting rows.
	Observed int `json:"observed"`
	Attested int `json:"attested"`
	// ObservedYes is the Yes count from the EVIDENCED half alone — the only figure a percentage
	// may legitimately be built from.
	//
	// It is reported rather than left to the caller to derive, because deriving it means
	// subtracting the attested yeses out of Yes, which is arithmetic that silently goes wrong the
	// moment a counter changes. A UI computing it would produce a number that mixes tiers: adding
	// attested questions makes it fall although nothing got worse, and answering them makes it
	// rise on typed assertions while the label still says "from evidence".
	ObservedYes int `json:"observed_yes"`
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

	// The tenant's own answers to the questions no scan can reach.
	attestations := map[string]platform.QuestionnaireAttestation{}
	if t, err := g.Store.GetTenant(ctx, tenantID); err == nil {
		attestations = t.QuestionnaireAttestations
	}

	res := &Questionnaire{TenantID: tenantID, GeneratedAt: g.now()}
	for _, q := range questions {
		// ATTESTED questions are resolved FIRST and never consult control state. The control
		// mapping on them exists so the answer can cite which control it speaks to in the
		// evidence pack — it is not a route to inferring the answer. Letting a finding decide
		// "have your employees had background checks?" would invent an observation out of an
		// unrelated one.
		if q.Evidence == QAttested {
			res.Attested++
			ans := QAnswer{QQuestion: q, Answer: AnswerNeedsYou}
			if a, ok := attestations[q.ID]; ok {
				ans.AttestedBy, ans.AttestedAt, ans.AttestedNote = a.By, a.At, a.Note
				if a.InPlace {
					ans.Answer = AnswerYes
					res.Yes++
				} else {
					ans.Answer = AnswerNo
					res.No++
				}
			} else {
				res.NeedsYou++
			}
			res.Answers = append(res.Answers, ans)
			continue
		}

		res.Observed++
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
			res.ObservedYes++
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
	// Org when the caller supplied it, else the tenant id. This document is now handed to a
	// BUYER through the Trust Center, and there it was titling itself with an internal
	// identifier ("ten-6302143adb9e") — which tells the reader nothing, exposes a key they have
	// no business seeing, and reads as unfinished on the one page whose whole job is to be
	// believed. In-app the id was harmless; the moment the audience changed it stopped being.
	who := q.Org
	if who == "" {
		who = q.TenantID
	}
	fmt.Fprintf(&b, "# Security Questionnaire — %s\n\n", who)
	fmt.Fprintf(&b, "_%d questions · %d answered from live evidence, %d answered by a named person · generated %s_\n\n",
		len(q.Answers), q.Observed, q.Attested, q.GeneratedAt.Format("2006-01-02"))
	fmt.Fprintf(&b, "**%d Yes · %d No · %d In Progress · %d Not assessed · %d awaiting our answer**\n\n",
		q.Yes, q.No, q.InProgress, q.NotAssessed, q.NeedsYou)

	// Both admissions go ABOVE the table, and they are SEPARATE. A reader must not skim a
	// mostly-unanswered questionnaire and come away thinking it was answered — and the two
	// kinds of unanswered need different action: one is fixed by connecting a system, the
	// other by a person sitting down and answering. Merged, the reader is told to fix the
	// wrong thing.
	if q.NotAssessed > 0 {
		fmt.Fprintf(&b, "> **%d question(s) have no evidence source connected.** They are reported as *Not assessed* "+
			"rather than assumed compliant. The missing source is named on each row.\n\n", q.NotAssessed)
	}
	if q.NeedsYou > 0 {
		fmt.Fprintf(&b, "> **%d question(s) are still awaiting an answer from us.** No scan can establish these, so "+
			"they need a person; they are shown unanswered rather than filled in.\n\n", q.NeedsYou)
	}

	b.WriteString("| # | Domain | Question | Answer | Basis |\n|---|---|---|---|---|\n")
	for _, a := range q.Answers {
		basis := "—"
		switch {
		case a.Evidence == QAttested && a.AttestedBy != "":
			// The name is the whole point. Rendered without it, an assertion is
			// indistinguishable from something a scanner established.
			basis = "stated by " + a.AttestedBy
			if when := attestedOn(a.AttestedAt); when != "" {
				basis += " on " + when
			}
			if a.AttestedNote != "" {
				basis += " — " + a.AttestedNote
			}
		case a.Evidence == QAttested:
			basis = "needs an answer from us"
			if a.Why != "" {
				basis += " (" + a.Why + ")"
			}
		case a.Answer == AnswerInProgress:
			basis = strings.Join(a.GapControls, ", ")
			if len(a.EvidenceIDs) > 0 {
				basis += " (" + strings.Join(a.EvidenceIDs, ", ") + ")"
			}
		case a.Answer == AnswerNotAssessed:
			basis = "connect " + strings.Join(a.MissingSources, " or ") + " to answer this"
		case a.Answer == AnswerYes:
			basis = "continuous scanning, no finding contradicts it"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | **%s** | %s |\n", a.ID, a.Domain, a.Text, a.Answer, basis)
	}
	b.WriteString("\n_How to read this. **Yes** on an evidenced question means the source is connected and no " +
		"finding contradicts the control; **In Progress** means a real finding opened a control gap; " +
		"**Not assessed** means we have not looked, never that we looked and found nothing. Rows marked " +
		"\"stated by\" are answered by a named person because no scan can establish them — they are an " +
		"assertion, and are labelled as one rather than presented as evidence._\n")
	return b.String()
}

// attestedOn renders a stored RFC3339 attestation time as a date a person would write.
//
// The raw timestamp is correct and unreadable, and this document is handed to someone else's
// procurement team; a machine-format string in the middle of a sentence reads as a leaked
// internal field. An unparseable value is passed through rather than dropped — losing WHEN an
// answer was given would be worse than showing it awkwardly, because the age of an attestation
// is part of how much it is worth.
func attestedOn(raw string) string {
	if raw == "" {
		return ""
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return raw
	}
	return t.UTC().Format("2 Jan 2006")
}

// knownSources is the complete vocabulary assessedSources can produce.
//
// It exists so a question cannot name a source that will never appear. That is not a
// hypothetical: a "data" source was briefly added for the warehouse question, and nothing could
// ever set it — internal/dataplatform arrives as a posted snapshot that stamps no posture
// source — so the question would have read "Not assessed · connect data to answer this" forever,
// telling the reader to connect something that does not exist as a connectable thing. The
// corpus test checks every declared source against this list.
var knownSources = map[string]bool{
	"repository": true, "container": true, "web": true, "api": true, "domain": true,
	"ip": true, "cloud": true, "identity": true, "saas": true, "device": true, "vendor": true,
	"training": true,
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
	// The snapshot-driven posture assessors have no connection and no asset — a vendor
	// portfolio or a device fleet arrives as a posted inventory. Tenant.PostureAssessed is
	// stamped only after a real ingest, which is exactly the "we looked" proof this needs: a
	// grounded assessor yields ZERO findings on a clean fleet, so an empty findings list cannot
	// distinguish a compliant estate from one that was never sent. Without reading this, every
	// device, vendor and SaaS question would sit at "Not assessed" for a customer who had
	// actually ingested the data.
	if t, err := g.Store.GetTenant(ctx, tenantID); err == nil {
		for source := range t.PostureAssessed {
			switch source {
			case "deviceposture":
				out["device"] = true
			case "tprm":
				out["vendor"] = true
			case "sspm":
				out["saas"] = true
			case "osint":
				out["domain"] = true
			case "clouddrift":
				out["cloud"] = true
			case "training":
				// Stamped by the monitoring pass ONLY when a roster exists — an empty roster returns
				// early, so this can never be set for a company whose workforce we cannot see. That is
				// what makes the training question safe to answer from observation rather than from a
				// person's word for it.
				out["training"] = true
			}
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
		case "ip_address":
			out["ip"] = true
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
