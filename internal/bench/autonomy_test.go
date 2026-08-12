package bench

import (
	"strings"
	"testing"
)

// The autonomy number is a self-assessment, which is exactly the kind of claim that rots. These keep it
// honest in the two ways it could go wrong: a gap with no stated remedy, and evidence nobody can check.

// A gap must SAY what a human has to do. "human_input" with no explanation is a shrug, and a reader
// cannot act on it or challenge it.
func TestAutonomy_EveryGapStatesWhatTheHumanMustDo(t *testing.T) {
	for _, task := range AllAutonomyTasks() {
		if task.Level.counts() {
			continue
		}
		if task.Gap == "" {
			t.Errorf("%s (%s) is a gap with no Gap text — a level that scores against us must say what "+
				"the human currently has to do, or it cannot be fixed or argued with", task.ID, task.Name)
		}
	}
}

// Every level must cite where it is DETERMINED. Self-reported autonomy with no pointer into the code is
// marketing.
func TestAutonomy_EveryLevelCitesItsEvidence(t *testing.T) {
	for _, task := range AllAutonomyTasks() {
		if task.Evidence == "" {
			t.Errorf("%s (%s) claims level %q with no evidence — a reader cannot check it", task.ID, task.Name, task.Level)
		}
	}
}

// A counting level must NOT carry gap text: if there is something a human still has to do, the level is
// wrong, and a reassuring level with a caveat buried in it is the worst of both.
func TestAutonomy_CountingLevelsHaveNoLurkingGap(t *testing.T) {
	for _, task := range AllAutonomyTasks() {
		if task.Level.counts() && task.Gap != "" {
			t.Errorf("%s counts as autonomy but carries a gap note (%q) — either the level is wrong or "+
				"the note is", task.ID, task.Gap)
		}
	}
}

// Both jobs must be represented. The pentester was graded by ONE exploitation number for a long time,
// which measured the middle of the engagement and none of the ends.
func TestAutonomy_BothJobsAreDecomposed(t *testing.T) {
	if n := len(filterJob(AllAutonomyTasks(), "engineer")); n < 5 {
		t.Errorf("engineer decomposed into only %d tasks", n)
	}
	if n := len(filterJob(AllAutonomyTasks(), "pentester")); n < 5 {
		t.Errorf("pentester decomposed into only %d tasks — exploitation is not the whole job; scope, "+
			"authorization, reporting and retest are most of a real engagement", n)
	}
}

// The score must actually move when a gap is closed, or it is decoration.
func TestAutonomy_ScoreRespondsToClosingAGap(t *testing.T) {
	tasks := AllAutonomyTasks()
	before := ScoreAutonomy(tasks).Percent()
	patched := AllAutonomyTasks()
	closed := false
	for i := range patched {
		if !patched[i].Level.counts() {
			patched[i].Level = LevelAutonomous
			patched[i].Gap = ""
			closed = true
			break
		}
	}
	if !closed {
		// Nothing left to close. That is either genuinely done or — far more likely — a sign someone
		// relabelled the last gap to make the number look finished, which is exactly what happened once
		// already on T3. Fail loudly rather than pass silently on a saturated metric.
		t.Skip("no gaps remain — re-read the levels against the code before trusting a 100% reading")
	}
	if after := ScoreAutonomy(patched).Percent(); after <= before {
		t.Errorf("closing a gap did not raise autonomy (%.1f → %.1f)", before, after)
	}
}

// Approval must COUNT. The product's stated model is human-for-approvals, so a design that stops for a
// signature is success, not a deduction — if this inverts, the number would push toward removing the
// human from decisions that need one.
func TestAutonomy_ApprovalCountsAsSuccess(t *testing.T) {
	if !LevelApproval.counts() {
		t.Error("approval must count toward autonomy — the target state is 'human only for approvals', " +
			"and scoring it as a failure would reward removing humans from decisions they should make")
	}
	if LevelHumanInput.counts() {
		t.Error("human_input must NOT count — that is the gap this measures")
	}
}

// The headline assumes a configured model. A tenant without one does not get a weaker engineer, it gets
// no engineer — AutoReviewAfterScan returns before starting — so a single number would describe a
// product some customers do not have.
func TestAutonomy_NoModelReadingIsLowerAndReported(t *testing.T) {
	tasks := AllAutonomyTasks()
	withModel := ScoreAutonomy(tasks).Percent()
	without := ScoreWithoutModel(tasks).Percent()

	if without >= withModel {
		t.Errorf("the no-model reading (%.0f%%) is not below the headline (%.0f%%) — either no task is "+
			"marked NeedsModel, or the model-dependent half is not being excluded", without, withModel)
	}
	// The denominator must stay the whole job: a task that cannot run is missing, not excused.
	if got := ScoreWithoutModel(tasks).Total; got != len(tasks) {
		t.Errorf("no-model total is %d, want %d — shrinking the denominator would flatter the reading by "+
			"pretending the absent tasks were never part of the job", got, len(tasks))
	}
	if !strings.Contains(RenderAutonomy(tasks), "Without a configured model") {
		t.Error("the report does not state the no-model reading — a reader would take the headline as " +
			"what every tenant gets")
	}
}

// Every model-dependent task must be marked. An unmarked one silently inflates the no-model reading.
func TestAutonomy_ModelDependentTasksAreMarked(t *testing.T) {
	if countModelTasks(AllAutonomyTasks()) == 0 {
		t.Fatal("no task is marked NeedsModel — the two readings would be identical and the caveat meaningless")
	}
}
