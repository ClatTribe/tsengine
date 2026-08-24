package toolfresh

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParse_ClassifiesEveryPinShape(t *testing.T) {
	const df = `
FROM debian:bookworm
ARG NUCLEI_VERSION=3.3.7
ARG DALFOX_VERSION=latest
ENV KICS_VERSION=2.1.3
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@v1.6.0
RUN go install github.com/owasp-amass/amass/v4/...@master
RUN pip3 install semgrep==1.90.0
# a comment mentioning go install should-not-count@v1
`
	r := Parse(df)

	want := map[string]struct {
		version string
		pin     PinState
	}{
		"nuclei":  {"3.3.7", PinExact},
		"dalfox":  {"latest", PinFloating},
		"kics":    {"2.1.3", PinExact},
		"httpx":   {"v1.6.0", PinExact},
		"amass":   {"master", PinFloating},
		"semgrep": {"1.90.0", PinExact},
	}
	got := map[string]Tool{}
	for _, tl := range r.Tools {
		got[tl.Name] = tl
	}
	for name, w := range want {
		g, ok := got[name]
		if !ok {
			t.Errorf("%s was not seen at all — an install nobody counts is how a forty-tool image ends up with six recorded versions", name)
			continue
		}
		if g.Version != w.version || g.Pin != w.pin {
			t.Errorf("%s = %q/%s, want %q/%s", name, g.Version, g.Pin, w.version, w.pin)
		}
	}
	if _, counted := got["should-not-count"]; counted {
		t.Error("a commented-out install line was counted as a real tool")
	}
	if r.Pinned != 4 || r.Floating != 2 {
		t.Errorf("counts wrong: pinned=%d floating=%d, want 4/2", r.Pinned, r.Floating)
	}
}

func TestParse_MasterAndMainCountAsFloating(t *testing.T) {
	// "latest" is the obvious one; a branch ref is the same problem wearing a different word, and
	// missing it would let the report call an irreproducible build reproducible.
	for _, ref := range []string{"latest", "master", "main", "LATEST"} {
		if got := pinOf(ref); got != PinFloating {
			t.Errorf("pinOf(%q) = %s, want %s", ref, got, PinFloating)
		}
	}
	for _, ref := range []string{"v1.2.3", "3.3.7", "1.90.0"} {
		if got := pinOf(ref); got != PinExact {
			t.Errorf("pinOf(%q) = %s, want %s", ref, got, PinExact)
		}
	}
}

func TestRender_LeadsWithWhatIsNotReproducible(t *testing.T) {
	out := Parse("ARG DALFOX_VERSION=latest\nARG NUCLEI_VERSION=3.3.7\n").Render()
	fl := strings.Index(out, "FLOATING")
	pn := strings.Index(out, "PINNED:")
	if fl < 0 || pn < 0 {
		t.Fatalf("both sections must render:\n%s", out)
	}
	if fl > pn {
		t.Error("the pinned list renders before the floating one. The floating half is the actionable " +
			"half; a report that buries it reads as an inventory rather than a problem.")
	}
	if !strings.Contains(out, "SIGNATURE CORPORA") {
		t.Error("the signature corpora are missing. They are a different axis from the binaries and the " +
			"one that determines recall — a report on versions alone invites the wrong conclusion.")
	}
}

// TestRealDockerfile_IsInspectableAndReportsTheKnownDrift runs against the actual build definition.
// It asserts the parser SEES it (a parser that matched nothing would pass every test above while
// telling us nothing about the product) and pins the specific drift the audit found.
func TestRealDockerfile_IsInspectableAndReportsTheKnownDrift(t *testing.T) {
	path := filepath.Join("..", "..", "docker", "sandbox", "Dockerfile")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v — if the build definition moved, move this test with it rather than "+
			"letting the freshness check stop seeing its subject", path, err)
	}
	r := Parse(string(b))

	if len(r.Tools) < 6 {
		t.Fatalf("only saw %d tools in the real Dockerfile — the parser has stopped matching and this "+
			"whole package would report a clean bill of health for an image nobody inspected", len(r.Tools))
	}
	if r.Floating == 0 {
		t.Log("no floating pins found — if that is because they were fixed, lower nothing and delete " +
			"this log; if it is because the patterns stopped matching, the count above would also be low")
	}
	if len(r.Signatures) == 0 {
		t.Error("no signature corpora recorded")
	}
	// The one that motivated the package: at least one corpus must be honest about ageing with the image.
	var sawImageBuild bool
	for _, s := range r.Signatures {
		if s.Refresh == "image-build" {
			sawImageBuild = true
		}
	}
	if !sawImageBuild {
		t.Error("no corpus is recorded as refreshing at image-build time. nuclei's templates do, and " +
			"that fact is the reason this package exists — if it changed, the note must change with it.")
	}
	t.Logf("real image: %d pinned, %d floating, %d unmanaged", r.Pinned, r.Floating, r.Unmanaged)
}
