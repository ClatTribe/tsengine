package bench

import "testing"

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
	before := ScoreAutonomy(AllAutonomyTasks()).Percent()
	patched := AllAutonomyTasks()
	for i := range patched {
		if !patched[i].Level.counts() {
			patched[i].Level = LevelAutonomous
			patched[i].Gap = ""
			break
		}
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
