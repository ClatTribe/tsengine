package bench

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadCSE_EvenLanguageSpread: the subset loader spreads samples across languages
// deterministically (so a small run isn't biased to one language) — validated on a tiny
// inline fixture (the real 1916-case dataset is operator-fetched, not committed).
func TestLoadCSE_EvenLanguageSpread(t *testing.T) {
	fixture := `[
	 {"prompt_id":1,"language":"c","cwe_identifier":"CWE-120","origin_code":"strcpy(a,b);","line_text":"strcpy(a,b);","file_path":"a.c","pattern_desc":"overflow"},
	 {"prompt_id":2,"language":"c","cwe_identifier":"CWE-121","origin_code":"x","line_text":"x","file_path":"b.c","pattern_desc":"y"},
	 {"prompt_id":3,"language":"python","cwe_identifier":"CWE-89","origin_code":"q","line_text":"q","file_path":"c.py","pattern_desc":"sqli"},
	 {"prompt_id":4,"language":"python","cwe_identifier":"CWE-78","origin_code":"o","line_text":"o","file_path":"d.py","pattern_desc":"cmd"}
	]`
	p := filepath.Join(t.TempDir(), "cse.json")
	if err := os.WriteFile(p, []byte(fixture), 0o644); err != nil {
		t.Fatal(err)
	}
	cases, err := LoadCSE(p, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 2 {
		t.Fatalf("want 2, got %d", len(cases))
	}
	// even spread: one c + one python (round-robin), not two of the same language.
	if cases[0].Language == cases[1].Language {
		t.Errorf("subset must spread across languages, got both %s", cases[0].Language)
	}
	all, _ := LoadCSE(p, 0)
	if len(all) != 4 {
		t.Errorf("n<=0 must load all, got %d", len(all))
	}
}
