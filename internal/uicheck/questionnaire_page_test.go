package uicheck

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The /security-questionnaire marketing page transcribes the corpus: how many questions a scan
// answers, how many a person attests, and the per-domain split. Transcribed numbers drift the day
// someone adds a question, and a page that says "35 questions a scan answers" over a corpus of 40 is
// the product overclaiming precision about its own honesty layer. So the page is checked against
// internal/grc/questionnaire_corpus.go itself. FAILS, never skips, when either file moves (§14.2 rule 6).
func TestQuestionnairePageMatchesTheCorpus(t *testing.T) {
	page := frontendFile(t, "app", "(marketing)", "security-questionnaire", "page.tsx")
	corpusPath, _ := filepath.Abs(filepath.Join("..", "grc", "questionnaire_corpus.go"))
	raw, err := os.ReadFile(corpusPath)
	if err != nil {
		t.Fatalf("read corpus %s: %v — if it moved, move this guard with it", corpusPath, err)
	}
	corpus := string(raw)

	tally := func(fn string) (int, map[string]int) {
		re := regexp.MustCompile(fn + `\("[A-Z]+-\d+", "([^"]+)"`)
		out := map[string]int{}
		n := 0
		for _, m := range re.FindAllStringSubmatch(corpus, -1) {
			out[strings.ToLower(m[1])]++
			n++
		}
		return n, out
	}
	obsN, obsBy := tally("obs")
	attN, attBy := tally("att")
	if obsN == 0 || attN == 0 {
		t.Fatalf("corpus tally found obs=%d att=%d — the regex no longer matches the corpus format", obsN, attN)
	}

	// headline counts
	for _, want := range []string{
		strconv.Itoa(obsN) + " questions a scan answers",
		strconv.Itoa(attN) + " only a person can",
		strconv.Itoa(obsN) + " answered by the scan, " + strconv.Itoa(attN) + " by a named human", // nav entry text lives in nav.tsx
	} {
		if !strings.Contains(page, want) && !strings.Contains(frontendFile(t, "components", "marketing", "nav.tsx"), want) {
			t.Errorf("page/nav must state %q (corpus: observed=%d attested=%d)", want, obsN, attN)
		}
	}

	// per-domain split: every ["Name", n] pair on the page must match the corpus, and every corpus
	// domain must appear on the page
	pairs := regexp.MustCompile(`\["([^"]+)", (\d+)\]`)
	check := func(section string, by map[string]int) {
		start := strings.Index(page, section)
		if start < 0 {
			t.Fatalf("page no longer has %s", section)
		}
		end := strings.Index(page[start:], "] as const")
		block := page[start : start+end]
		seen := map[string]bool{}
		for _, m := range pairs.FindAllStringSubmatch(block, -1) {
			name := strings.ToLower(m[1])
			n, _ := strconv.Atoi(m[2])
			if by[name] != n {
				t.Errorf("%s: page says %q = %d, corpus has %d", section, m[1], n, by[name])
			}
			seen[name] = true
		}
		for name, n := range by {
			if !seen[name] {
				t.Errorf("%s: corpus domain %q (%d) is missing from the page", section, name, n)
			}
		}
	}
	check("OBSERVED_DOMAINS", obsBy)
	check("ATTESTED_DOMAINS", attBy)
}
