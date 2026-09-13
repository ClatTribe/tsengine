package platformapi

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/tool/patchverify"
)

// The verifier's verdict decides whether the diff ships and is STATED in the note either way:
// verified → attached and said to have executed; rejected by the tests → withheld with the reason;
// unverifiable → attached and said not to have run; no verifier → attached and said so.
func TestPatchForAction_VerdictDecidesWhetherTheDiffShipsAndIsStated(t *testing.T) {
	llm := &patchLLM{}
	d, a, c := patchDeps(t, llm)
	var seen struct {
		full, regression string
		files            map[string]string
	}
	d.PatchVerifier = func(_ context.Context, _ string, full string, files map[string]string, regression string) (patchverify.Verdict, error) {
		seen.full, seen.files, seen.regression = full, files, regression
		return patchverify.Verdict{Status: patchverify.Verified, Runner: "go", Reason: "the regression test failed on the unpatched tree and passes with the patch; the existing suite passes"}, nil
	}
	files, note, err := d.PatchForAction(context.Background(), a, c, "gh-token")
	if err != nil {
		t.Fatal(err)
	}
	if seen.full != "acme/shop" || seen.regression != "app/db_test.go" || len(seen.files) != 2 {
		t.Errorf("the verifier must receive the repository, the patched files and the regression path: %+v", seen)
	}
	if len(files) != 2 || !strings.Contains(note, "EXECUTED against your repository") || !strings.Contains(note, "runner: go") {
		t.Errorf("a verified patch ships and the note says it ran: files=%d note=%q", len(files), note)
	}

	// Rejected by the tests: the diff is WITHHELD and the error names the verdict — the deliverer
	// quotes it in the PR body above the instructions.
	for _, status := range []string{patchverify.NotFixed, patchverify.BrokeSuite, patchverify.Vacuous} {
		d2, a2, c2 := patchDeps(t, &patchLLM{})
		d2.PatchVerifier = func(context.Context, string, string, map[string]string, string) (patchverify.Verdict, error) {
			return patchverify.Verdict{Status: status, Reason: "the tests said no"}, nil
		}
		files, _, err := d2.PatchForAction(context.Background(), a2, c2, "gh-token")
		if err == nil || files != nil || !strings.Contains(err.Error(), status) || !strings.Contains(err.Error(), "withheld") {
			t.Errorf("%s: a rejected patch must be withheld with the verdict named, got files=%v err=%v", status, files, err)
		}
	}

	// Unverifiable is said as itself, and the diff still ships — an unrun test is not a failed one.
	d3, a3, c3 := patchDeps(t, &patchLLM{})
	d3.PatchVerifier = func(context.Context, string, string, map[string]string, string) (patchverify.Verdict, error) {
		return patchverify.Verdict{Status: patchverify.Unverifiable, Reason: "a JavaScript/TypeScript project: the scan sandbox carries no node runtime"}, nil
	}
	files, note, err = d3.PatchForAction(context.Background(), a3, c3, "gh-token")
	if err != nil || len(files) != 2 || !strings.Contains(note, "could NOT be executed") || !strings.Contains(note, "no node runtime") {
		t.Errorf("unverifiable: files=%d note=%q err=%v", len(files), note, err)
	}

	// The verifier itself failing (no sandbox, no matching asset) is also said, and the diff ships.
	d4, a4, c4 := patchDeps(t, &patchLLM{})
	d4.PatchVerifier = func(context.Context, string, string, map[string]string, string) (patchverify.Verdict, error) {
		return patchverify.Verdict{}, errors.New("no monitored repository asset matches acme/shop")
	}
	files, note, err = d4.PatchForAction(context.Background(), a4, c4, "gh-token")
	if err != nil || len(files) != 2 || !strings.Contains(note, "NOT executed against your tests: no monitored repository") {
		t.Errorf("verifier error: files=%d note=%q err=%v", len(files), note, err)
	}

	// No verifier wired: attached, and the note says no sandbox verifier ran.
	d5, a5, c5 := patchDeps(t, &patchLLM{})
	_, note, err = d5.PatchForAction(context.Background(), a5, c5, "gh-token")
	if err != nil || !strings.Contains(note, "no sandbox verifier") {
		t.Errorf("no verifier: note=%q err=%v", note, err)
	}
}
