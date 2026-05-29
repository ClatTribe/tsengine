package katana

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParse_DedupesAndExtracts(t *testing.T) {
	blob, err := os.ReadFile(filepath.Join("testdata", "sample.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	urls := parse(blob)
	// 4 unique: /, /login, /search?q=1, /api/users (the duplicate / and
	// the non-json line are dropped).
	if len(urls) != 4 {
		t.Fatalf("got %d urls; want 4: %v", len(urls), urls)
	}
	want := map[string]bool{
		"https://example.com/":           true,
		"https://example.com/login":      true,
		"https://example.com/search?q=1": true,
		"https://example.com/api/users":  true,
	}
	for _, u := range urls {
		if !want[u] {
			t.Errorf("unexpected url %q", u)
		}
	}
	// Sorted → deterministic.
	for i := 1; i < len(urls); i++ {
		if urls[i-1] > urls[i] {
			t.Errorf("urls not sorted: %v", urls)
		}
	}
}

func TestParse_Empty(t *testing.T) {
	if parse(nil) != nil {
		t.Error("nil expected for empty")
	}
	if parse([]byte("garbage\n")) != nil {
		t.Error("nil expected for non-json")
	}
}

func TestSurface(t *testing.T) {
	k := New()
	if k.Name() != "katana" || !k.SandboxExecution() {
		t.Error("surface wrong")
	}
}
