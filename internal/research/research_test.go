package research

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func fakeFetcher(bodies map[string]Raw) Fetcher {
	return func(_ context.Context, u string, _ int) (Raw, error) {
		r, ok := bodies[u]
		if !ok {
			return Raw{}, errors.New("not reachable")
		}
		return r, nil
	}
}

const allowed = "advisory.example"

// THE SECURITY BOUNDARY: only allowlisted hosts are fetched, matched on a dotted boundary. A
// look-alike host and a host-as-prefix are both refused BEFORE any fetch.
func TestGather_AllowlistIsADottedBoundaryNotASubstring(t *testing.T) {
	ctx := context.Background()
	urls := []string{
		"https://advisory.example/cve-1",       // allowed: exact
		"https://docs.advisory.example/cve-2",  // allowed: subdomain
		"https://notadvisory.example/x",        // refused: substring, not a boundary
		"https://advisory.example.evil.test/x", // refused: suffix-injection
		"ftp://advisory.example/x",             // refused: scheme
		"https://advisory.example/dupe",        // fetched once
		"https://advisory.example/dupe",        // deduped
	}
	bodies := map[string]Raw{}
	for _, u := range urls {
		bodies[u] = Raw{Body: []byte("advisory text"), ContentType: "text/plain"}
	}
	res := Gather(ctx, fakeFetcher(bodies), urls, Options{AllowedHostSuffixes: []string{allowed}})

	got := map[string]bool{}
	for _, d := range res.Documents {
		got[d.URL] = true
	}
	for _, want := range []string{"https://advisory.example/cve-1", "https://docs.advisory.example/cve-2", "https://advisory.example/dupe"} {
		if !got[want] {
			t.Errorf("allowed URL not fetched: %s", want)
		}
	}
	for _, bad := range []string{"https://notadvisory.example/x", "https://advisory.example.evil.test/x", "ftp://advisory.example/x"} {
		if got[bad] {
			t.Errorf("a URL that must be refused was fetched: %s", bad)
		}
	}
	if len(res.Documents) != 3 {
		t.Fatalf("want 3 fetched (dedup), got %d: %+v", len(res.Documents), res.Documents)
	}
	if len(res.Rejected) < 3 {
		t.Errorf("refused hosts must be recorded, not silently dropped: %+v", res.Rejected)
	}
}

// An empty allowlist fetches nothing — fail closed, never fetch-anything.
func TestGather_EmptyAllowlistFetchesNothing(t *testing.T) {
	res := Gather(context.Background(), fakeFetcher(map[string]Raw{"https://x.example/a": {Body: []byte("x")}}),
		[]string{"https://x.example/a"}, Options{})
	if len(res.Documents) != 0 || len(res.Rejected) != 1 {
		t.Fatalf("empty allowlist must fetch nothing: %+v", res)
	}
}

// Every document is pinned (hash of the EXACT bytes + fetch time), text is extracted from HTML, and the
// byte cap truncates with Truncated set rather than silently cutting.
func TestPin_CitesAndBounds(t *testing.T) {
	html := []byte("<html><head><title>CVE-9999 advisory</title></head><body><script>bad()</script><p>Upgrade to 2.3.</p></body></html>")
	res := Gather(context.Background(), fakeFetcher(map[string]Raw{"https://advisory.example/a": {Body: html, ContentType: "text/html"}}),
		[]string{"https://advisory.example/a"}, Options{AllowedHostSuffixes: []string{allowed}, MaxBytes: 10})
	if len(res.Documents) != 1 {
		t.Fatal(res)
	}
	d := res.Documents[0]
	want := hex.EncodeToString(func() []byte { h := sha256.Sum256(html); return h[:] }())
	if d.SHA256 != want || d.FetchedAt.IsZero() {
		t.Errorf("the hash must pin the EXACT fetched bytes (not the extracted/truncated text): got %q want %q", d.SHA256, want)
	}
	if d.Title != "CVE-9999 advisory" {
		t.Errorf("title not extracted: %q", d.Title)
	}
	if strings.Contains(d.Text, "bad()") || strings.Contains(d.Text, "<") {
		t.Errorf("script/markup not stripped: %q", d.Text)
	}
	if !d.Truncated || len(d.Text) > 10 {
		t.Errorf("the byte cap must truncate and say so: trunc=%v len=%d", d.Truncated, len(d.Text))
	}
	if d.Bytes != len(html) {
		t.Errorf("Bytes must be the real size, not the truncated one: %d", d.Bytes)
	}
}

// The per-run document cap bounds outbound requests; the excess is recorded, not fetched.
func TestGather_DocCapBoundsFetches(t *testing.T) {
	bodies := map[string]Raw{}
	var urls []string
	for _, p := range []string{"a", "b", "c", "d"} {
		u := "https://advisory.example/" + p
		urls = append(urls, u)
		bodies[u] = Raw{Body: []byte("x")}
	}
	res := Gather(context.Background(), fakeFetcher(bodies), urls, Options{AllowedHostSuffixes: []string{allowed}, MaxDocs: 2})
	if len(res.Documents) != 2 || len(res.Unavailable) != 2 {
		t.Fatalf("doc cap not enforced: %d fetched, %d deferred", len(res.Documents), len(res.Unavailable))
	}
}

// PromptBlock renders the citation and the never-evidence framing, and is empty for no documents.
func TestPromptBlock_CarriesTheFramingOrNothing(t *testing.T) {
	if (Result{}).PromptBlock() != "" {
		t.Error("no documents must render no prompt block")
	}
	res := Gather(context.Background(), fakeFetcher(map[string]Raw{"https://advisory.example/a": {Body: []byte("Upgrade now."), ContentType: "text/plain"}}),
		[]string{"https://advisory.example/a"}, Options{AllowedHostSuffixes: []string{allowed}})
	blk := res.PromptBlock()
	if !strings.Contains(blk, PromptFraming) || !strings.Contains(blk, "NOT evidence") {
		t.Error("the block must carry the context-not-evidence framing")
	}
	if !strings.Contains(blk, "sha256") || !strings.Contains(blk, "advisory.example") {
		t.Error("the block must cite the source and its hash")
	}
}

// A nil fetcher rejects every URL rather than panicking or claiming an empty clean result.
func TestGather_NilFetcherRejectsAll(t *testing.T) {
	res := Gather(context.Background(), nil, []string{"https://advisory.example/a"}, Options{AllowedHostSuffixes: []string{allowed}})
	if len(res.Documents) != 0 || len(res.Rejected) != 1 {
		t.Fatalf("%+v", res)
	}
}

func TestAdvisoryURLs_KeepsOnlyRealHTTPLinks(t *testing.T) {
	got := AdvisoryURLs([]string{"https://a.example/x", "see the vendor note", "", "https://a.example/x", "http://b.example/y"})
	if len(got) != 2 {
		t.Fatalf("only real http(s) URLs, deduped: %+v", got)
	}
}
