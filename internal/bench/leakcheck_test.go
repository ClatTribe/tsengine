package bench

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// The check is only worth having if it catches the leaks that were found by hand. These replay the
// real ones, including the two I authored myself.

func TestDetectLabelLeak_CatchesTheWAVSEPPathTell(t *testing.T) {
	// Every WAVSEP false-positive case carries "FalsePositive" in its URL; no true case does. A
	// one-line grep scores 1.00, which is why an EXTERNAL corpus is no protection on its own.
	var cases []LeakCase
	for i := 0; i < 40; i++ {
		cases = append(cases, LeakCase{
			Input:    fmt.Sprintf("/wavsep/active/SQLI/SQLI-Detection-GET/Case%02d-InjectionInSelect.jsp sqli 89", i),
			Positive: true,
		})
	}
	for i := 0; i < 12; i++ {
		cases = append(cases, LeakCase{
			Input:    fmt.Sprintf("/wavsep/active/LFI/LFI-FalsePositives-GET/Case%02d-LFI-FalsePositive-Forward.jsp lfi 22", i),
			Positive: false,
		})
	}
	got := DetectLabelLeak(cases)
	if !got.Leaked {
		t.Errorf("missed the WAVSEP path tell: %s", got.Detail)
	}
	if got.Separation < 0.99 {
		t.Errorf("token %q separates at only J=%.2f — expected a total giveaway", got.Token, got.Separation)
	}
}

// KNOWN LIMITATION, pinned so nobody mistakes this check for a guarantee.
//
// The first triage corpus leaked by stating the CONCLUSION across a PHRASE ("not referenced outside
// _test.go files and points at no live account") rather than in one distinctive token. Single-token
// separation tops out at J=0.67 there, under the 0.80 bar — so this check would NOT have caught the
// very leak that motivated it.
//
// It catches the blunt kind (a giveaway word like FalsePositive) and misses distributed phrasing. That
// is worth having and worth not overselling: a clean report means one failure mode is absent, not that
// the corpus is sound.
func TestDetectLabelLeak_MissesDistributedPhrasingLeaks(t *testing.T) {
	cases := []LeakCase{
		{Input: "SQL injection in search: a value from the HTTP request is concatenated into the statement", Positive: true},
		{Input: "AWS access key committed: a long-lived key used to authenticate the deployment job", Positive: true},
		{Input: "Bucket readable by anyone: the policy grants read to all principals", Positive: true},
		{Input: "AWS key in fixture: it is not referenced outside _test.go files and points at no live account", Positive: false},
		{Input: "API key in docs: the placeholder value published in the provider's quickstart, not a live account", Positive: false},
		{Input: "Vulnerable legacy library: excluded by the build constraint and no target imports it, not live", Positive: false},
	}
	if got := DetectLabelLeak(cases); got.Leaked {
		t.Errorf("unexpectedly caught a distributed-phrasing leak — if this now passes, the check got "+
			"stronger and this test should be promoted to an assertion: %s", got.Detail)
	}
}

// A corpus whose labels genuinely require judgement must NOT be flagged, or the check is a nuisance
// that gets switched off.
func TestDetectLabelLeak_CleanCorpusPasses(t *testing.T) {
	cases := []LeakCase{
		{Input: "request value concatenated into the statement text before execution", Positive: true},
		{Input: "long-lived access token present as a literal and used against production", Positive: true},
		{Input: "bucket policy grants read to all principals; holds nightly customer exports", Positive: true},
		{Input: "key-format literals in a json file under a testdata directory", Positive: false},
		{Input: "api-key-shaped literal in a fenced code block in a markdown guide", Positive: false},
		{Input: "manifest pins a version with an advisory; directory carries a build-ignore constraint", Positive: false},
	}
	if got := DetectLabelLeak(cases); got.Leaked {
		t.Errorf("flagged a corpus that needs real judgement (token %q): %s", got.Token, got.Detail)
	}
}

// A heavily-imbalanced corpus must not read as leaky just because guessing the majority scores high.
func TestDetectLabelLeak_ImbalanceIsNotALeak(t *testing.T) {
	var cases []LeakCase
	// Identical vocabulary in both classes: only the LABEL differs, so nothing is inferable.
	for i := 0; i < 97; i++ {
		cases = append(cases, LeakCase{Input: fmt.Sprintf("finding number %d about assorted things", i), Positive: true})
	}
	for i := 0; i < 3; i++ {
		cases = append(cases, LeakCase{Input: fmt.Sprintf("finding number %d about assorted things", 100+i), Positive: false})
	}
	// No token distinguishes these — imbalance alone must not read as a leak.
	if got := DetectLabelLeak(cases); got.Leaked {
		t.Errorf("imbalance alone was flagged as a leak (token %q, J=%.2f)", got.Token, got.Separation)
	}
}

// THE ONE THAT MATTERS: run the check against the corpora we actually ship. A leak here means a
// number in the scorecard is measuring string matching.
func TestShippedCorporaAreNotLeaky(t *testing.T) {
	t.Run("triage", func(t *testing.T) {
		var cases []LeakCase
		for _, c := range TriageCases() {
			f := c.Finding
			cases = append(cases, LeakCase{
				Input:    strings.Join([]string{f.Title, f.Description, f.Endpoint, f.RuleID, f.Tool}, " "),
				Positive: c.Actionable,
			})
		}
		if got := DetectLabelLeak(cases); got.Leaked {
			t.Errorf("the SHIPPED triage corpus leaks: %s", got.Detail)
		} else {
			fmt.Printf("  triage corpus: %s\n", got.Detail)
		}
	})

	t.Run("wavsep-is-unusable-for-triage", func(t *testing.T) {
		// Documents WHY we do not use WAVSEP for T1 despite it being external and 1,133 cases: it was
		// built to test scanners, and its labels are in the URLs.
		b, err := os.ReadFile("../../fixtures/web/wavsep/expected-cases.csv")
		if err != nil {
			t.Skip("wavsep fixture not present")
		}
		var cases []LeakCase
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "url_path") || strings.TrimSpace(line) == "" {
				continue
			}
			parts := strings.Split(line, ",")
			if len(parts) < 3 {
				continue
			}
			cases = append(cases, LeakCase{Input: parts[0] + " " + parts[1], Positive: parts[2] == "true"})
		}
		got := DetectLabelLeak(cases)
		if !got.Leaked {
			t.Errorf("expected WAVSEP to be flagged as label-leaking for triage use, got: %s", got.Detail)
		}
		fmt.Printf("  wavsep (why it is not T1's corpus): %s\n", got.Detail)
	})
}
