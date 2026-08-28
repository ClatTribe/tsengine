package bench

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/cloudagent"
	"github.com/ClatTribe/tsengine/internal/cloudengine"
	"github.com/ClatTribe/tsengine/internal/estategraph"
)

// crosssurface_agent.go — does the AI Security Engineer find the CROSS-ASSET attack path?
//
// WHY THIS EXISTS. ScoreCrossSurface measures the SUBSTRATE: whether the joined data model can
// establish a path neither surface holds alone. That is a necessary check and it needs no model.
// But the product's claim is about the ENGINEER — one agent reasoning across code, cloud and
// identity — and `cloudagent.Context` has carried `Estate` (a walkable cross-surface graph) and
// `Bridges` (grounded code→cloud footholds) for some time, wired in production by
// platformapi/cloudinvestigate.go, exercised by NO benchmark with a model in the loop.
//
// Every agent number this repo can currently quote comes from a CLOUD-ONLY account, where both
// fields are empty. So the differentiating capability — the wedge — was measured by nothing, while
// single-surface cloud reasoning was measured repeatedly. This closes that.
//
// THE DISCRIMINATION IS GENUINE, NOT RIGGED. In the leaked-key fixture the cloud account is
// complete and correct: deploy-role can read the customer-PII bucket, but no public compute runs as
// it and no trust policy admits an outsider. A cloud-only agent that reports "no internet-reachable
// path" is RIGHT on the evidence it has. The path exists only because a long-lived key for that
// role sits in a public repository — a fact on the CODE surface. So the two arms are not "a good
// agent vs a bad one"; they are the same agent given one surface or two, and the delta is the
// capability under test.
//
// GROUNDING IS UNCHANGED (§10). The agent still records issues against the CLOUD graph and
// record_issue still refuses a path whose edges do not exist. A bridge tells the agent WHERE to
// look; it never authorises an ungrounded finding. An invented chain scores zero here, exactly as
// it does in production.

// CrossSurfaceAgentScore is one arm of the head-to-head.
type CrossSurfaceAgentScore struct {
	Scenario string `json:"scenario"`
	// Arm is "cloud_only" (no Estate/Bridges) or "estate_aware" (both supplied).
	Arm string `json:"arm"`
	// ReportedChain is whether the agent's output actually names the cross-surface route — the
	// code-side origin AND the cloud crown. Naming only the crown is not the capability: a
	// cloud-only agent can see the bucket, it just cannot say how anyone reaches it.
	ReportedChain bool `json:"reported_chain"`
	// Issues is how many issues the agent recorded (all grounded — record_issue refuses otherwise).
	Issues int `json:"issues"`
	// Invented is any issue whose target is not the fixture's crown. Non-zero DISQUALIFIES the arm:
	// a cross-surface story bought with a hallucinated node is worse than no story.
	Invented int `json:"invented"`
	// Summary is the agent's executive summary, kept for the audit trail.
	Summary string `json:"summary,omitempty"`
	// Err records a run that could not be scored (no model, transport failure) — reported as
	// UNSCORED, never as a capability failure.
	Err string `json:"err,omitempty"`
}

// Scored reports whether this arm actually evaluated the agent.
func (s CrossSurfaceAgentScore) Scored() bool { return s.Err == "" }

// CrossSurfaceAgentResult is the head-to-head: the SAME agent and model, one surface vs two.
type CrossSurfaceAgentResult struct {
	Scenario  string                 `json:"scenario"`
	Question  string                 `json:"question,omitempty"`
	CloudOnly CrossSurfaceAgentScore `json:"cloud_only"`
	Estate    CrossSurfaceAgentScore `json:"estate_aware"`
	// Lift is the capability claim: the estate-aware arm reported the chain and the cloud-only arm
	// did not, with neither arm inventing anything.
	Lift bool `json:"lift"`
	// SubstrateLift is ScoreCrossSurface's verdict on the same fixture — the floor. If the substrate
	// cannot establish the path either, an agent failure says nothing about the agent, so the run is
	// not discriminating (the same completeness rule the cloud head-to-head uses).
	SubstrateLift bool `json:"substrate_lift"`
	// Discriminating is whether this run could evaluate the agent at all.
	Discriminating bool `json:"discriminating"`
}

// RunCrossSurfaceAgent runs the engineer twice over one fixture — once blind to code, once with the
// joined estate — and reports whether the second finds what the first cannot.
func RunCrossSurfaceAgent(ctx context.Context, fx CrossSurfaceFixture, llm cloudengine.LLM, maxIters int) CrossSurfaceAgentResult {
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	res := CrossSurfaceAgentResult{Scenario: fx.Name, Question: fx.Question}

	// The substrate floor first: it is LLM-free, so a non-discriminating fixture is caught before
	// any model budget is spent.
	sub := ScoreCrossSurface(fx)
	res.SubstrateLift = sub.Lift
	res.Discriminating = sub.Lift

	if maxIters <= 0 {
		maxIters = 24
	}
	est := BuildCrossSurfaceEstate(fx, now)

	// Arm A — cloud only: exactly what a cloud scanner's agent sees. No Estate, no Bridges.
	res.CloudOnly = runCrossSurfaceArm(ctx, "cloud_only", fx, llm, maxIters, nil, nil)
	// Arm B — estate aware: the joined graph plus the grounded bridge hint, as production wires it.
	res.Estate = runCrossSurfaceArm(ctx, "estate_aware", fx, llm, maxIters, est, crossSurfaceBridges(fx, est))

	res.Lift = res.Estate.Scored() && res.CloudOnly.Scored() &&
		res.Estate.ReportedChain && !res.CloudOnly.ReportedChain &&
		res.Estate.Invented == 0
	return res
}

// crossSurfaceBridges renders the grounded code→cloud footholds the way platformapi does: a hint
// naming WHERE an attacker already stands, never a path to the crown.
func crossSurfaceBridges(fx CrossSurfaceFixture, est *estategraph.Graph) []string {
	var out []string
	for _, f := range fx.CodeFindings {
		out = append(out, fmt.Sprintf("%s (%s) — a credential exposed on the code surface; treat the cloud principal it authenticates as attacker-controlled", f.Title, f.Endpoint))
	}
	if est == nil {
		return out
	}
	return out
}

func runCrossSurfaceArm(ctx context.Context, arm string, fx CrossSurfaceFixture, llm cloudengine.LLM,
	maxIters int, est *estategraph.Graph, bridges []string) CrossSurfaceAgentScore {
	sc := CrossSurfaceAgentScore{Scenario: fx.Name, Arm: arm}
	cc := &cloudagent.Context{Snap: fx.Cloud, Estate: est, Bridges: bridges}
	rep, err := cloudagent.Investigate(ctx, llm, cc, cloudagent.Options{MaxIters: maxIters, MaxHyp: 20})
	if err != nil {
		sc.Err = err.Error()
		return sc
	}
	sc.Summary = rep.Summary
	sc.Issues = len(rep.Issues)
	for _, is := range rep.Issues {
		if is.Target != fx.Crown {
			sc.Invented++
		}
	}
	sc.ReportedChain = reportsCrossSurfaceChain(rep, fx)
	return sc
}

// reportsCrossSurfaceChain asks whether the agent actually told the cross-surface story: it must
// reach the crown AND attribute the entry to the code-side origin. Reaching the crown alone is not
// the capability — the cloud-only arm can see the bucket, it just cannot say how anyone gets in.
func reportsCrossSurfaceChain(rep *cloudagent.Report, fx CrossSurfaceFixture) bool {
	reachedCrown := false
	for _, is := range rep.Issues {
		if is.Target == fx.Crown {
			reachedCrown = true
			break
		}
	}
	if !reachedCrown {
		return false
	}
	// The code-side origin, in the agent's own words: the leaked-credential fact, or the repository
	// it came from. Matched on the fixture's OWN finding text so the check cannot be satisfied by
	// boilerplate the prompt already contains.
	hay := strings.ToLower(rep.Summary)
	for _, is := range rep.Issues {
		hay += " " + strings.ToLower(is.Rationale) + " " + strings.ToLower(strings.Join(is.Evidence, " "))
	}
	for _, f := range fx.CodeFindings {
		for _, needle := range crossSurfaceOriginTerms(f.Endpoint, f.Title) {
			if needle != "" && strings.Contains(hay, needle) {
				return true
			}
		}
	}
	return false
}

// crossSurfaceOriginTerms are the distinctive tokens that mark the CODE origin — the repo path and
// the credential language from the fixture's own finding. Deliberately narrow: a generic word like
// "key" appears in ordinary cloud prose and would credit the cloud-only arm for saying nothing.
func crossSurfaceOriginTerms(endpoint, title string) []string {
	var terms []string
	if e := strings.ToLower(strings.TrimSpace(endpoint)); e != "" {
		terms = append(terms, e)
		if i := strings.LastIndex(e, "/"); i >= 0 && i+1 < len(e) {
			terms = append(terms, e[i+1:]) // deploy.py
		}
		if strings.Contains(e, "github.com/") {
			terms = append(terms, "repository", "repo")
		}
	}
	if t := strings.ToLower(title); strings.Contains(t, "committed") || strings.Contains(t, "leaked") {
		terms = append(terms, "committed", "leaked")
	}
	return terms
}

// RenderCrossSurfaceAgent renders the head-to-head.
func RenderCrossSurfaceAgent(r CrossSurfaceAgentResult) string {
	var b strings.Builder
	b.WriteString("=== AI Security Engineer — CROSS-ASSET attack path (code → cloud) ===\n")
	fmt.Fprintf(&b, "scenario: %s\n", r.Scenario)
	if r.Question != "" {
		fmt.Fprintf(&b, "question: %s\n", r.Question)
	}
	b.WriteString("\nSame agent, same model — the only difference is whether it can see the code surface.\n\n")
	for _, a := range []CrossSurfaceAgentScore{r.CloudOnly, r.Estate} {
		if !a.Scored() {
			fmt.Fprintf(&b, "  %-13s UNSCORED (%s)\n", a.Arm, a.Err)
			continue
		}
		fmt.Fprintf(&b, "  %-13s chain reported: %-5v  issues: %d  invented: %d\n",
			a.Arm, a.ReportedChain, a.Issues, a.Invented)
	}
	b.WriteString("\n")
	if !r.Discriminating {
		b.WriteString("NOT DISCRIMINATING: the substrate itself cannot establish this path, so an agent\n" +
			"failure here says nothing about the agent. Fix the fixture before reading the arms.\n")
		return b.String()
	}
	if r.Lift {
		b.WriteString("LIFT: the estate-aware arm reported the cross-surface chain the cloud-only arm could\n" +
			"not — and invented nothing. This is the wedge capability, measured.\n")
	} else {
		b.WriteString("NO LIFT: seeing the code surface did not let the agent tell the cross-surface story.\n" +
			"The substrate CAN establish it (that is what discriminating means), so this is an agent\n" +
			"or prompt gap, not a data gap.\n")
	}
	return b.String()
}
