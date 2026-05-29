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

func TestParse_SynthesizesFormParamURLs(t *testing.T) {
	// A bare page URL (no query) carrying a POST form with one field — the
	// WAVSEP shape. parse must emit both the page AND an injectable GET URL.
	blob := []byte(`{"request":{"endpoint":"https://x/case.jsp","method":"GET"},` +
		`"forms":[{"method":"POST","action":"https://x/case.jsp","parameters":["userinput"]}]}` + "\n")
	urls := parse(blob)
	got := map[string]bool{}
	for _, u := range urls {
		got[u] = true
	}
	if !got["https://x/case.jsp"] {
		t.Errorf("page URL missing: %v", urls)
	}
	if !got["https://x/case.jsp?userinput=1"] {
		t.Errorf("synthesized injectable form URL missing: %v", urls)
	}
}

func TestFormParamURL(t *testing.T) {
	// multi-param, sorted/deterministic
	if got := formParamURL("https://x/p", "https://x/p", []string{"b", "a"}); got != "https://x/p?a=1&b=1" {
		t.Errorf("multi-param: got %q", got)
	}
	// relative action resolved against the page
	if got := formParamURL("https://x/dir/page.jsp", "submit.jsp", []string{"q"}); got != "https://x/dir/submit.jsp?q=1" {
		t.Errorf("relative action: got %q", got)
	}
	// no params → nothing injectable
	if got := formParamURL("https://x/p", "https://x/p", nil); got != "" {
		t.Errorf("no params should yield empty; got %q", got)
	}
}

func TestParse_SynthesizesFromResponseForms_v16(t *testing.T) {
	// katana >=1.6 nests forms under response.forms (the schema in the image).
	blob := []byte(`{"request":{"endpoint":"https://x/c.jsp","method":"GET"},` +
		`"response":{"forms":[{"method":"POST","action":"https://x/c.jsp","parameters":["msg"]}]}}` + "\n")
	got := map[string]bool{}
	for _, u := range parse(blob) {
		got[u] = true
	}
	if !got["https://x/c.jsp?msg=1"] {
		t.Errorf("response.forms (v1.6) not synthesized: %v", got)
	}
}
