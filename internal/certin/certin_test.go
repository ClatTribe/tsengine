package certin

import (
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

var cats = []string{"Annexure I: Data breach / data leak"}

func inc(opened time.Time) platform.Incident {
	return platform.Incident{
		ID: "inc-1", Title: "Public S3 bucket exposes customer records",
		Severity: "critical", Status: platform.IncidentOpen, Key: "s3::acme-pii",
		RuleID: "prowler::s3_bucket_public_access", FindingID: "f-1", OpenedAt: opened,
	}
}

// The clock: six hours from noticing, counted down in minutes.
func TestSixHourWindow(t *testing.T) {
	opened := time.Date(2026, 8, 18, 10, 0, 0, 0, time.UTC)
	st, ok := Evaluate(inc(opened), cats, time.Time{}, opened.Add(90*time.Minute))
	if !ok {
		t.Fatal("a reportable incident must evaluate")
	}
	if want := opened.Add(6 * time.Hour); !st.DueAt.Equal(want) {
		t.Errorf("DueAt = %s, want %s", st.DueAt, want)
	}
	if st.MinutesLeft != 270 { // 6h - 1h30 = 4h30 = 270m
		t.Errorf("MinutesLeft = %d, want 270", st.MinutesLeft)
	}
	if st.Breached {
		t.Error("inside the window must not be a breach")
	}
}

// Past six hours and unreported IS the regulatory breach.
func TestBreachAfterSixHours(t *testing.T) {
	opened := time.Date(2026, 8, 18, 10, 0, 0, 0, time.UTC)
	st, _ := Evaluate(inc(opened), cats, time.Time{}, opened.Add(7*time.Hour))
	if !st.Breached {
		t.Error("unreported past six hours must breach — that is the regulatory failure")
	}
	if st.MinutesLeft >= 0 {
		t.Errorf("MinutesLeft = %d, want negative once the window closed", st.MinutesLeft)
	}
}

// THE GROUNDING REFUSAL. An incident with no CERT-In annotation carries NO reporting
// duty — we must never tell a customer they are late to a regulator for an incident
// that was never reportable.
func TestNoAnnotationNoDuty(t *testing.T) {
	opened := time.Date(2026, 8, 18, 10, 0, 0, 0, time.UTC)
	if _, ok := Evaluate(inc(opened), nil, time.Time{}, opened.Add(99*time.Hour)); ok {
		t.Error("an unannotated incident must NOT produce a CERT-In obligation")
	}
	if _, ok := Prepare(inc(opened), nil, opened); ok {
		t.Error("Prepare must refuse an incident with no reportable category")
	}
}

// Filing discharges the duty — even late. A filed report is not a standing breach.
func TestFilingDischargesTheDuty(t *testing.T) {
	opened := time.Date(2026, 8, 18, 10, 0, 0, 0, time.UTC)
	late := opened.Add(8 * time.Hour)
	st, _ := Evaluate(inc(opened), cats, late, opened.Add(20*time.Hour))
	if !st.Reported {
		t.Fatal("a filed report must be recorded as reported")
	}
	if st.Breached {
		t.Error("a filed (even late) report is a discharged duty, not a standing breach")
	}
}

// Resolving the underlying issue does NOT retire the duty to have told the regulator —
// otherwise a fast fix would hide a missed filing.
func TestResolvedStillReportable(t *testing.T) {
	opened := time.Date(2026, 8, 18, 10, 0, 0, 0, time.UTC)
	i := inc(opened)
	i.Status = platform.IncidentResolved
	st, ok := Evaluate(i, cats, time.Time{}, opened.Add(7*time.Hour))
	if !ok || !st.Breached {
		t.Error("a resolved-but-never-reported incident must still show the missed filing")
	}
}

// The draft states only what the incident establishes, and explicitly hands the
// entity-specific fields to the human filer rather than inventing them.
func TestPrepareIsGroundedAndLeavesEntityFieldsToTheFiler(t *testing.T) {
	opened := time.Date(2026, 8, 18, 10, 0, 0, 0, time.UTC)
	r, ok := Prepare(inc(opened), cats, opened)
	if !ok {
		t.Fatal("a reportable incident must prepare")
	}
	for _, want := range []string{
		"Direction (ii)", "within six hours",
		"Annexure I: Data breach / data leak",
		"Public S3 bucket exposes customer records",
		"TO BE COMPLETED BY THE FILER",
	} {
		if !strings.Contains(r.Body, want) {
			t.Errorf("draft missing %q", want)
		}
	}
	if !r.DueAt.Equal(opened.Add(6 * time.Hour)) {
		t.Errorf("draft DueAt = %s, want +6h", r.DueAt)
	}
}
