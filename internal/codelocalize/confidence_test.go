package codelocalize

import (
	"context"
	"testing"
)

func TestConfidenceTiers(t *testing.T) {
	cases := []struct {
		strong, weak, source, keyword bool
		want                          float64
	}{
		{true, false, true, true, 0.95},   // strong + source + keyword → capped
		{true, false, true, false, 0.85},  // strong + source
		{true, false, false, false, 0.6},  // strong only
		{false, true, false, false, 0.3},  // weak only
		{false, false, false, true, 0.1},  // keyword-only (unknown-CWE fallback)
		{false, false, false, false, 0.0}, // nothing
	}
	for _, c := range cases {
		if got := confidence(c.strong, c.weak, c.source, c.keyword); got != c.want {
			t.Errorf("confidence(%v,%v,%v,%v)=%.2f want %.2f", c.strong, c.weak, c.source, c.keyword, got, c.want)
		}
	}
}

func TestConfidence_StrongSinkWithSourceBeatsWeak(t *testing.T) {
	// the real SQLi sink (strong + source) must carry higher confidence than an incidental weak-only hit.
	tainted := File{Path: "a.go", Content: "n := r.URL.Query().Get(\"n\")\ndb.Query(\"SELECT * FROM t WHERE n='\"+n+\"'\")"}
	weakOnly := File{Path: "b.go", Content: "// audit query\nrows := doSELECT FROM cache\n"} // only the weak `select ` token
	res, _ := HeuristicLocalizer{}.Localize(context.Background(), Query{CWE: []string{"CWE-89"}}, Repo{tainted, weakOnly})
	byPath := map[string]Candidate{}
	for _, c := range res.Ranked {
		byPath[c.Path] = c
	}
	if byPath["a.go"].Confidence <= byPath["b.go"].Confidence {
		t.Fatalf("strong+source (%.2f) should exceed weak-only (%.2f)", byPath["a.go"].Confidence, byPath["b.go"].Confidence)
	}
	if byPath["a.go"].Confidence < 0.8 {
		t.Fatalf("a real strong+source SQLi site should be high-confidence, got %.2f", byPath["a.go"].Confidence)
	}
}
