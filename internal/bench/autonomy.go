package bench

import (
	"fmt"
	"strings"
)

// autonomy.go measures the thing the product is actually selling: HOW MUCH OF THE JOB RUNS WITHOUT A
// HUMAN, with the human reserved for approvals.
//
// WHY THIS IS NOT THE EFFICACY SCORECARD. scorecard.go asks "does the output clear a quality bar" —
// necessary, and not the same question. A task can score 1.00 and still demand that a person type its
// inputs every time, which is the difference between an engineer you employ and a tool you operate.
// Efficacy is about QUALITY; this is about WHO DOES THE WORK.
//
// THE LEVELS, and why "approval" counts as success. The target state is explicitly not "no human" — it
// is "human only for approvals", the Claude Code model: the agent works, and a person signs off on side
// effects. So an approval gate is the DESIGN, not a shortfall. What counts against us is a task where
// the agent cannot proceed until a human hands it information the product already has, or does not
// attempt the task at all.
//
//	autonomous  the agent completes it; nobody is asked anything
//	approval    the agent completes it and a human says yes/no — THE TARGET STATE, counts as success
//	human_input the agent cannot proceed until a person supplies data or config — A GAP
//	human_does  the agent does not attempt it — THE LARGEST GAP
//
// EVERY LEVEL CITES WHERE IT IS DETERMINED. A self-assessment of one's own autonomy is worth nothing
// unless a reader can check it, so each entry names the file or endpoint that decides the level. Where
// this file and the code disagree, the code is right and this file is a bug.

// AutonomyLevel is what the product needs from a human to finish one task.
type AutonomyLevel string

const (
	LevelAutonomous AutonomyLevel = "autonomous"
	LevelApproval   AutonomyLevel = "approval"
	LevelHumanInput AutonomyLevel = "human_input"
	LevelHumanDoes  AutonomyLevel = "human_does"
)

// counts reports whether a level counts toward the autonomy number. Approval counts: the goal is not to
// remove the human, it is to reduce the human to a decision.
func (l AutonomyLevel) counts() bool { return l == LevelAutonomous || l == LevelApproval }

// AutonomyTask is one measurable unit of one of the two jobs.
type AutonomyTask struct {
	ID  string // T1…T8 (engineer) · P1…P8 (pentester)
	Job string // "engineer" | "pentester"
	// Name is the task in the practitioner's own words, not ours.
	Name  string
	Level AutonomyLevel
	// Evidence names the file, endpoint or test that DETERMINES the level, so the claim is checkable.
	Evidence string
	// Gap states what a human currently has to do, and is required whenever Level does not count.
	// Empty on a counting level.
	Gap string
}

// EngineerAutonomy is the defensive job — the eight tasks scorecard.go already grades for quality,
// re-asked as "who does the work".
func EngineerAutonomy() []AutonomyTask {
	return []AutonomyTask{
		{ID: "T1", Job: "engineer", Name: "Triage — is this real, does it matter?",
			Level: LevelAutonomous, Evidence: "runner.RescanTenant → crossdetect + triage on every pass; no human touch"},
		{ID: "T2", Job: "engineer", Name: "Localize — where is the fix?",
			Level: LevelAutonomous, Evidence: "vulnLocalizer (agent tool) + GET /v1/findings/{id}/localize; grounded in repo contents"},
		{ID: "T3", Job: "engineer", Name: "Assess — is it reachable/exploitable?",
			Level: LevelHumanInput, Evidence: "pentest.SelectForProof requires an ownership-VERIFIED target (ownership_gate.go)",
			Gap: "Proof is skipped entirely until a human completes the DNS/well-known ownership challenge per asset. " +
				"Correct as a safety gate — we must not attack what we cannot show the customer owns — but it is " +
				"a human input, and an unverified estate is silently unprovable rather than visibly blocked."},
		{ID: "T4", Job: "engineer", Name: "Fix — produce the change",
			Level: LevelApproval, Evidence: "remediate.Propose → hitl.Desk; tier ≥ GateTier queues for a named human"},
		{ID: "T5", Job: "engineer", Name: "Verify — did the fix hold?",
			Level: LevelAutonomous, Evidence: "retest.Verify inside runner.RescanTenant; deterministic re-test, no human"},
		{ID: "T6", Job: "engineer", Name: "Answer — query the estate",
			Level: LevelAutonomous, Evidence: "estateSearch (agent tool) + GET /v1/ask; no model, answers from stored findings"},
		{ID: "T7", Job: "engineer", Name: "Report — evidence an auditor accepts",
			Level: LevelApproval, Evidence: "grc report generated unattended; ControlAttestation needs a NAMED auditor (§18.4)"},
		{ID: "T8", Job: "engineer", Name: "Hand off — raise what isn't ours",
			Level: LevelApproval, Evidence: "ticketFiler → hitl.Desk at tier 1; auto-delivers unless halted"},
	}
}

// PentesterAutonomy is the offensive job. It had never been decomposed — the efficacy scorecard grades
// the pentester with ONE number (XBOW flag capture), which measures exploitation and says nothing about
// how much of an ENGAGEMENT runs unattended. Scope, authorization, reporting and retest are most of the
// work of a real pentest and none of them are exploitation.
func PentesterAutonomy() []AutonomyTask {
	return []AutonomyTask{
		{ID: "P1", Job: "pentester", Name: "Scope — what am I allowed to touch?",
			Level: LevelHumanInput, Evidence: "components/pentest/new-engagement.tsx — `targets` is a free-text textarea",
			Gap: "A human retypes the scope as text, even though the tenant's assets are already known, " +
				"already inventoried, and (for proof) already ownership-verified. The product makes you " +
				"tell it what it knows."},
		{ID: "P2", Job: "pentester", Name: "Authorize — signed rules of engagement",
			Level: LevelApproval, Evidence: "pentest.RoE.ActiveAuthorized() — AllowActive + named AuthorizedBy + recorded Consent"},
		{ID: "P3", Job: "pentester", Name: "Discover — map the attack surface",
			Level: LevelAutonomous, Evidence: "L1 recon→fan-out (katana/subfinder/naabu) + cmd/tsbench discover; deterministic prepass"},
		{ID: "P4", Job: "pentester", Name: "Exploit — prove it, don't guess",
			Level: LevelAutonomous, Evidence: "pentest ActiveDriver / webagent under RoE.Check; predicate-gated upgrade to verified"},
		{ID: "P5", Job: "pentester", Name: "Chain — escalate and measure blast radius",
			Level: LevelAutonomous, Evidence: "crossdetect.Correlate + cloudgraph attack paths; runs on every pass"},
		{ID: "P6", Job: "pentester", Name: "Report — the VAPT deliverable",
			Level: LevelAutonomous, Evidence: "runner sets StatusReporting; grc.VAPTReport renders unattended"},
		{ID: "P7", Job: "pentester", Name: "Retest — did the fix actually close it?",
			Level: LevelHumanInput, Evidence: "handleRunPentest → eng.Retest(); only ever entered by a human pressing Run",
			Gap: "A completed engagement never re-tests itself. pentest.Schedule (Cadence/Due/NextRunAt) exists " +
				"and nothing drives it from the monitoring pass, so 'we fixed it, confirm the exploit is dead' " +
				"waits on someone remembering."},
		{ID: "P8", Job: "pentester", Name: "Sign off — a named human stands behind it",
			Level: LevelApproval, Evidence: "POST /v1/pentest/{id}/signoff — refuses without a named signer (§18.4)"},
	}
}

// AllAutonomyTasks is both jobs, engineer first.
func AllAutonomyTasks() []AutonomyTask {
	return append(EngineerAutonomy(), PentesterAutonomy()...)
}

// AutonomyScore is the composite.
type AutonomyScore struct {
	Total, Autonomous, Approval, HumanInput, HumanDoes int
}

// Percent is the headline: the share of the job that runs without a human handing it anything.
func (s AutonomyScore) Percent() float64 {
	if s.Total == 0 {
		return 0
	}
	return float64(s.Autonomous+s.Approval) / float64(s.Total) * 100
}

// ScoreAutonomy tallies a task set.
func ScoreAutonomy(tasks []AutonomyTask) AutonomyScore {
	var s AutonomyScore
	for _, t := range tasks {
		s.Total++
		switch t.Level {
		case LevelAutonomous:
			s.Autonomous++
		case LevelApproval:
			s.Approval++
		case LevelHumanInput:
			s.HumanInput++
		case LevelHumanDoes:
			s.HumanDoes++
		}
	}
	return s
}

// RenderAutonomy renders the report, gaps first.
func RenderAutonomy(tasks []AutonomyTask) string {
	all := ScoreAutonomy(tasks)
	eng := ScoreAutonomy(filterJob(tasks, "engineer"))
	pen := ScoreAutonomy(filterJob(tasks, "pentester"))

	var b strings.Builder
	b.WriteString("# Autonomy — how much of the job runs without a human\n\n")
	fmt.Fprintf(&b, "**Autonomy: %.0f%%** (%d of %d tasks need no human input) — AI Security Engineer %.0f%% · AI Pentester %.0f%%\n\n",
		all.Percent(), all.Autonomous+all.Approval, all.Total, eng.Percent(), pen.Percent())
	fmt.Fprintf(&b, "%d run unattended · %d stop for an approval (the target state) · **%d wait on a human to supply something** · %d not attempted\n\n",
		all.Autonomous, all.Approval, all.HumanInput, all.HumanDoes)
	b.WriteString("An approval counts as success: the goal was never \"no human\", it is \"human only for ")
	b.WriteString("approvals\". What counts against us is a task where the agent cannot start until a person ")
	b.WriteString("hands it something the product already knows.\n\n")

	if gaps := gapsIn(tasks); len(gaps) > 0 {
		b.WriteString("## The gaps, in the order they cost the most\n\n")
		for _, t := range gaps {
			fmt.Fprintf(&b, "- **%s %s** (%s) — %s\n", t.ID, t.Name, t.Level, t.Gap)
		}
		b.WriteString("\n")
	}

	b.WriteString("| | Job | Task | Level | Determined by |\n|---|---|---|---|---|\n")
	for _, t := range tasks {
		mark := t.Level
		if !t.Level.counts() {
			mark = AutonomyLevel("**" + string(t.Level) + "**")
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", t.ID, t.Job, t.Name, mark, t.Evidence)
	}
	return b.String()
}

func filterJob(tasks []AutonomyTask, job string) []AutonomyTask {
	var out []AutonomyTask
	for _, t := range tasks {
		if t.Job == job {
			out = append(out, t)
		}
	}
	return out
}

func gapsIn(tasks []AutonomyTask) []AutonomyTask {
	var out []AutonomyTask
	for _, t := range tasks {
		if !t.Level.counts() {
			out = append(out, t)
		}
	}
	return out
}
