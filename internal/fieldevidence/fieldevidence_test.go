package fieldevidence

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

func obs(tenant, class string, contradicted bool, n int) []Observation {
	var out []Observation
	for i := 0; i < n; i++ {
		out = append(out, Observation{Tenant: tenant, Class: class, Contradicted: contradicted})
	}
	return out
}

// THE property: a class whose clean re-scans have been contradicted stops being sufficient evidence.
func TestRescanSufficient_ContradictedClassIsNoLongerSufficient(t *testing.T) {
	var o []Observation
	for _, tn := range []string{"t1", "t2", "t3"} {
		o = append(o, obs(tn, "nuclei::sqli", true, 2)...)  // 6 contradicted
		o = append(o, obs(tn, "nuclei::sqli", false, 2)...) // 6 agreed
	}
	c := Aggregate(o, Options{})
	sufficient, known := c.RescanSufficient("nuclei::sqli")
	if !known {
		t.Fatal("12 observations across 3 tenants must be known")
	}
	if sufficient {
		t.Errorf("a 50%% contradiction rate must make a clean re-scan insufficient")
	}
	if d := c.Distrusted(); len(d) != 1 || d[0].Class != "nuclei::sqli" {
		t.Errorf("the class must be reportable as distrusted, got %+v", d)
	}
}

// The mirror, which matters just as much: a class with a CLEAN record must keep today's behaviour.
// A corpus that only ever tightens is still wrong if it tightens on everything.
func TestRescanSufficient_CleanRecordStaysSufficient(t *testing.T) {
	var o []Observation
	for _, tn := range []string{"t1", "t2", "t3"} {
		o = append(o, obs(tn, "nuclei::headers", false, 3)...)
	}
	c := Aggregate(o, Options{})
	sufficient, known := c.RescanSufficient("nuclei::headers")
	if !known || !sufficient {
		t.Fatalf("a clean record must be known and sufficient, got sufficient=%v known=%v", sufficient, known)
	}
	if len(c.Distrusted()) != 0 {
		t.Error("a clean class must not be reported as distrusted")
	}
}

// Absence declares itself. Unknown must never read as trustworthy OR as suspect — the caller's
// default for unknown is the status quo, so an empty corpus changes nothing at all.
func TestRescanSufficient_AbsenceIsUnknownNotAVerdict(t *testing.T) {
	cases := []struct {
		name string
		c    *Corpus
	}{
		{"nil corpus", nil},
		{"empty corpus", Aggregate(nil, Options{})},
		{"below the observation floor", Aggregate(obs("t1", "x", true, 2), Options{MinContributors: 1})},
		{"below the contributor floor", Aggregate(obs("t1", "x", true, 20), Options{})},
	}
	for _, tc := range cases {
		sufficient, known := tc.c.RescanSufficient("x")
		if known {
			t.Errorf("%s: must be UNKNOWN, not a verdict", tc.name)
		}
		if !sufficient {
			t.Errorf("%s: unknown must leave behaviour unchanged, so sufficient must stay true", tc.name)
		}
	}
}

// One estate must not decide a shared statistic for everyone.
func TestAggregate_PerTenantCapBoundsOneEstatesInfluence(t *testing.T) {
	var o []Observation
	o = append(o, obs("loud", "c", true, 100)...) // one tenant screaming
	for _, tn := range []string{"a", "b"} {
		o = append(o, obs(tn, "c", false, 5)...)
	}
	c := Aggregate(o, Options{MaxPerTenant: 5})
	e, _ := c.Evidence("c")
	if e.Contradicted > 5 {
		t.Errorf("one tenant contributed %d contradictions past a cap of 5", e.Contradicted)
	}
	if e.CleanRescans != 15 {
		t.Errorf("want 15 counted observations (3 tenants x 5), got %d", e.CleanRescans)
	}
	// With the cap the rate is 5/15 = 33%. Without it, 100/110 = 91% — one estate deciding for all.
	if got := e.ContradictionRate(); got > 0.4 {
		t.Errorf("the cap must bound the rate, got %.2f", got)
	}
}

// An observation is a LABELLED example: it requires that a re-attack actually ran. An action verified
// by re-scan alone is not evidence that the re-scan was right.
func TestFromActions_OnlyCountsLabelledExamples(t *testing.T) {
	acts := []platform.Action{
		{FindingKeys: []string{"r1|https://a"}, Verification: &platform.FixVerification{
			Status: platform.FixStatusFixed, RescanSaidFixed: true}},
		{FindingKeys: []string{"r2|https://b"}, Verification: &platform.FixVerification{
			Status: platform.FixStatusFixed, RescanSaidFixed: true,
			Disagreement: platform.DisagreeRescanMissedLiveExploit}},
		// re-scan only, no re-attack ran → NOT an observation
		{FindingKeys: []string{"r3|https://c"}, Verification: &platform.FixVerification{
			Status: platform.FixStatusFixed}},
		{FindingKeys: []string{"r4|https://d"}}, // never verified
	}
	got := FromActions("t1", acts)
	if len(got) != 2 {
		t.Fatalf("want 2 labelled examples, got %d: %+v", len(got), got)
	}
	byClass := map[string]bool{}
	for _, o := range got {
		byClass[o.Class] = o.Contradicted
	}
	if byClass["r1"] != false || byClass["r2"] != true {
		t.Errorf("contradiction must follow the recorded disagreement, got %+v", byClass)
	}
}

// One verification event is one observation, however many findings it claimed — otherwise a single
// remediation spanning five findings outvotes five separate ones.
func TestFromActions_OneObservationPerClassNotPerKey(t *testing.T) {
	got := FromActions("t1", []platform.Action{{
		FindingKeys:  []string{"r1|https://a", "r1|https://b", "r1|https://c", "r2|https://d"},
		Verification: &platform.FixVerification{RescanSaidFixed: true},
	}})
	if len(got) != 2 {
		t.Fatalf("want one observation per DISTINCT class (r1, r2), got %d: %+v", len(got), got)
	}
}

// The class is world-state; the endpoint is the customer's. Nothing tenant-identifying may reach the
// published record.
func TestClassOf_DropsTheCustomerHalfAndEvidenceCarriesNoTenant(t *testing.T) {
	if got := ClassOf("nuclei::sqli|https://acme.example.com/search?q=1"); got != "nuclei::sqli" {
		t.Fatalf("ClassOf must keep only the rule id, got %q", got)
	}
	c := Aggregate(obs("acme-corp", "nuclei::sqli", true, 9), Options{MinContributors: 1})
	e, _ := c.Evidence("nuclei::sqli")
	if strings.Contains(e.Class, "acme") {
		t.Error("published evidence must carry no tenant identifier")
	}
}

// A tenant reading its own record discloses nothing, so the anonymity gate must not silence it —
// but the EVIDENCE floor still applies, because one estate's anecdote is still an anecdote.
func TestForTenant_WaivesAnonymityButNotTheEvidenceFloor(t *testing.T) {
	acts := make([]platform.Action, 0, 9)
	for i := 0; i < 9; i++ {
		acts = append(acts, platform.Action{
			FindingKeys: []string{"r1|https://a" + string(rune('a'+i))},
			Verification: &platform.FixVerification{RescanSaidFixed: true,
				Disagreement: platform.DisagreeRescanMissedLiveExploit},
		})
	}
	if _, known := ForTenant("t1", acts, Options{}).RescanSufficient("r1"); !known {
		t.Error("a tenant's own 9 labelled examples must be usable despite MinContributors=3")
	}
	if _, known := ForTenant("t1", acts[:2], Options{}).RescanSufficient("r1"); known {
		t.Error("two examples is still an anecdote — the evidence floor must hold")
	}
}

// FromActions treats RescanSaidFixed as proof a re-attack ran, which is true only while exactly one
// place writes it. A second writer that set it WITHOUT running a re-attack would fill this corpus
// with unlabelled rows, every one counted as "the re-scan was right" — quietly restoring trust in a
// check nobody verified.
func TestRescanSaidFixedHasOneWriter(t *testing.T) {
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root = filepath.Dir(filepath.Dir(root)) // internal/fieldevidence -> repo root
	var writers []string
	err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		if strings.Contains(string(b), "RescanSaidFixed:") {
			rel, _ := filepath.Rel(root, path)
			writers = append(writers, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(writers) == 0 {
		t.Fatal("no writer of RescanSaidFixed found at all: this guard cannot see its subject")
	}
	if len(writers) != 1 || writers[0] != filepath.Join("internal", "retest", "reattack.go") {
		t.Errorf("RescanSaidFixed must be written ONLY by the re-attack path (which has both kinds of "+
			"evidence in hand). Writers found: %v.\nIf a new one is legitimate, it must also prove a "+
			"re-attack ran, or fieldevidence.FromActions will count unlabelled rows as agreements.", writers)
	}
}

// The per-tenant cap exists to stop ONE estate deciding a shared statistic. Applied to a tenant's own
// corpus it truncates their history in ARRIVAL ORDER and distorts the rate it is meant to compute:
// six contradictions followed by twenty clean re-scans would count the first five only and read as
// 100% contradicted instead of 23% — refusing to confirm a class that is mostly fine.
func TestForTenant_CapDoesNotTruncateATenantsOwnHistory(t *testing.T) {
	var acts []platform.Action
	add := func(n int, contradicted bool) {
		for i := 0; i < n; i++ {
			v := &platform.FixVerification{RescanSaidFixed: true}
			if contradicted {
				v.Disagreement = platform.DisagreeRescanMissedLiveExploit
			}
			acts = append(acts, platform.Action{
				FindingKeys:  []string{"r1|e" + strings.Repeat("x", len(acts))},
				Verification: v,
			})
		}
	}
	add(2, true)   // the contradictions arrive first...
	add(60, false) // ...and the far larger clean record follows
	c := ForTenant("t1", acts, Options{})
	e, ok := c.Evidence("r1")
	if !ok {
		t.Fatal("the class must be known")
	}
	if e.CleanRescans != 62 || e.Contradicted != 2 {
		t.Fatalf("the tenant's whole history must count, got %d rescans / %d contradicted",
			e.CleanRescans, e.Contradicted)
	}
	// 2/62 = 3%, well under the threshold: this class is fine and must stay confirmable. Under the
	// capped behaviour only the first 5 counted — 2 contradicted of 5 = 40% — so a healthy class was
	// refused confirmation entirely on an artefact of arrival order.
	if sufficient, known := c.RescanSufficient("r1"); !known || !sufficient {
		t.Errorf("a mostly-clean class must stay sufficient (rate %.2f), got sufficient=%v known=%v",
			e.ContradictionRate(), sufficient, known)
	}
}
