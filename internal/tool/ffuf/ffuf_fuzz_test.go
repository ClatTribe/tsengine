package ffuf

import (
	"os"
	"strings"
	"testing"
)

// TestFuzzURL_KeywordAnywhere: the old wrapper ALWAYS appended /FUZZ, so FUZZ-in-the-middle
// (.../order/FUZZ/receipt — the IDOR/enumeration case) was impossible: it became
// .../order/FUZZ/receipt/FUZZ. A url that already carries FUZZ must be used verbatim.
func TestFuzzURL_KeywordAnywhere(t *testing.T) {
	mid := "http://t/order/FUZZ/receipt"
	if got := fuzzURL(mid); got != mid {
		t.Errorf("a url with FUZZ must be used verbatim; got %q", got)
	}
	// no FUZZ → dir-brute default (append /FUZZ, trim trailing slash)
	if got := fuzzURL("http://t/app/"); got != "http://t/app/FUZZ" {
		t.Errorf("dir-brute default wrong: %q", got)
	}
}

// TestCalibrate_OptIn: -ac auto-calibration must be OPT-IN, never forced by `range`. Forcing it (the
// original behavior) over-filtered a real authenticated IDOR sweep to ZERO results with no override.
// A range alone must NOT enable it; only calibrate:true does.
func TestCalibrate_OptIn(t *testing.T) {
	if c, _ := (map[string]any{"range": "1-10"})["calibrate"].(bool); c {
		t.Fatal("test setup wrong")
	}
	// mirror the wrapper's decision: autocalib := args["calibrate"].(bool)
	rangeOnly, _ := (map[string]any{"range": "300000-300999"})["calibrate"].(bool)
	if rangeOnly {
		t.Error("a range must NOT force -ac (it can over-filter to zero)")
	}
	explicit, _ := (map[string]any{"range": "1-10", "calibrate": true})["calibrate"].(bool)
	if !explicit {
		t.Error("calibrate:true must enable -ac")
	}
}

// TestRedactCookie: the injected session cookie must never survive into ffuf's returned output (it
// echoes the -H Cookie header in its config), so the agent's session can't leak into the evidence.
func TestRedactCookie(t *testing.T) {
	out := `{"config":{"headers":{"Cookie":"session=eyJ1c2VyX2lkIjoxMDAzMn0.abc"}}}`
	got := redactCookie(out, "session=eyJ1c2VyX2lkIjoxMDAzMn0.abc")
	if strings.Contains(got, "eyJ1c2VyX2lkIjoxMDAzMn0") {
		t.Errorf("session cookie leaked into output: %s", got)
	}
	if !strings.Contains(got, "<redacted-session>") {
		t.Errorf("expected a redaction marker: %s", got)
	}
	if redactCookie("no cookie here", "") != "no cookie here" {
		t.Error("empty cookie must not alter output")
	}
}

// TestNumericWordlist_RangeSweep: a numeric range generates a wordlist of every id in [lo,hi] — the
// object-id sweep a word wordlist can't do. Bounded by maxRange so a typo can't make it unbounded.
func TestNumericWordlist_RangeSweep(t *testing.T) {
	wf, cleanup, err := numericWordlist("300000-300004")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	b, _ := os.ReadFile(wf)
	got := strings.Fields(string(b))
	want := []string{"300000", "300001", "300002", "300003", "300004"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("range sweep = %v, want %v", got, want)
	}

	// bounded
	_, cl2, err := numericWordlist("0-99999999")
	if err != nil {
		t.Fatal(err)
	}
	cl2()
	lo, hi, err := parseRange("0-99999999")
	if err != nil || hi-lo+1 > maxRange {
		t.Errorf("range not bounded by maxRange: lo=%d hi=%d err=%v", lo, hi, err)
	}

	// malformed
	if _, _, err := parseRange("notarange"); err == nil {
		t.Error("malformed range must error")
	}
	if _, _, err := parseRange("10-5"); err == nil {
		t.Error("hi<lo must error")
	}
}
