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

// TestRealDockerfile_IsInspectableAndFullyPinned runs against the actual build definition.
// It asserts the parser SEES it (a parser that matched nothing would pass every test above while
// telling us nothing about the product) and that nothing floats.
func TestRealDockerfile_IsInspectableAndFullyPinned(t *testing.T) {
	path := filepath.Join("..", "..", "docker", "sandbox", "Dockerfile")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v — if the build definition moved, move this test with it rather than "+
			"letting the freshness check stop seeing its subject", path, err)
	}
	r := Parse(string(b))

	// FLOOR RAISED FROM 6. Eight tools cleared the old floor while the parser was blind to 26 of the
	// image's scanners, so the guard passed at its most useless moment — the precise failure it was
	// written to catch, one level up.
	if len(r.Tools) < 25 {
		t.Fatalf("only saw %d tools in the real Dockerfile — the parser has stopped matching and this "+
			"whole package would report a clean bill of health for an image nobody inspected", len(r.Tools))
	}
	// EVERY tool is pinned, and this asserts it rather than logging about it. dalfox, subfinder,
	// gitleaks and naabu floated on `latest` when this package was written; they are pinned now, so
	// zero is the intended state and a regression must fail here as well as in CI. The tool count
	// checked above is what separates "nothing floats" from "the parser stopped matching".
	if r.Floating != 0 {
		var names []string
		for _, tl := range r.Tools {
			if tl.Pin == PinFloating {
				names = append(names, tl.Name)
			}
		}
		t.Errorf("%d scanner(s) float on an unpinned ref: %v. Two builds of this Dockerfile then ship "+
			"different scanners, and neither the evidence pack nor the VAPT report can say which one "+
			"tested the customer. Pin it to a real version.", r.Floating, names)
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

// TestParse_VariableVersionDefersToTheArg closes a hole that would let this package call an
// irreproducible build reproducible. `go install x@${FOO_VERSION}` carries no version of its own;
// treating the literal "${FOO_VERSION}" as a version string classifies it PinExact — a confident
// wrong answer, and the exact failure mode the package exists to report on.
func TestParse_VariableVersionDefersToTheArg(t *testing.T) {
	r := Parse("ARG NAABU_VERSION=latest\nRUN go install github.com/projectdiscovery/naabu/v2/cmd/naabu@${NAABU_VERSION}\n")
	for _, tl := range r.Tools {
		if tl.Installer == "go" && strings.Contains(tl.Version, "$") {
			t.Errorf("a build-arg reference was recorded as the version: %+v", tl)
		}
	}
	if r.Floating != 1 || r.Pinned != 0 {
		t.Errorf("counts = %d floating / %d pinned, want 1/0 — the ARG says `latest`, so the tool "+
			"floats; the go-install line must not out-vote it with a fake pin", r.Floating, r.Pinned)
	}
}

// TestParse_SeesTheInstallFormsThisImageActuallyUses is the regression test for the coverage gap
// that made this package report a clean bill of health for an image it barely inspected. It matched
// ARG/go-install/pip-pinned only, so eleven ts_install scanners on @latest and ten unpinned pip
// scanners were absent — the report said "0 floating · 0 unmanaged" and CI gated on that.
func TestParse_SeesTheInstallFormsThisImageActuallyUses(t *testing.T) {
	const df = `
RUN . /usr/local/bin/ts_want.sh && ts_install repository grype github.com/anchore/grype/cmd/grype@latest
RUN . /usr/local/bin/ts_want.sh && ts_install domain amass github.com/owasp-amass/amass/v4/...@v4.2.0
RUN PKGS="$PKGS sqlmap" \
    && { ts_want cloud && PKGS="$PKGS prowler==4.6.0 scoutsuite"; } || true
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh
`
	got := map[string]Tool{}
	for _, tl := range Parse(df).Tools {
		got[tl.Name] = tl
	}
	for name, want := range map[string]PinState{
		"grype":      PinFloating,  // ts_install @latest — was invisible
		"amass":      PinExact,     // ts_install pinned
		"sqlmap":     PinUnmanaged, // pip, no version — was invisible
		"scoutsuite": PinUnmanaged, // pip, no version
		"prowler":    PinExact,     // pip ==
		"syft":       PinUnmanaged, // curl installer off a branch
	} {
		g, ok := got[name]
		if !ok {
			t.Errorf("%s was not seen at all — an install nobody counts does not appear in any total, "+
				"so the report reads as a statement about the whole image while covering part of it", name)
			continue
		}
		if g.Pin != want {
			t.Errorf("%s = %s, want %s", name, g.Pin, want)
		}
	}
	if got["prowler"].Version != "4.6.0" {
		t.Errorf("prowler version = %q, want 4.6.0", got["prowler"].Version)
	}
}

// TestRender_StatesItsOwnCoverage: totals that cover part of an image must say so, or a tool absent
// from every list reads as confirmed-pinned rather than unverified (§5.2 rule 5).
func TestRender_StatesItsOwnCoverage(t *testing.T) {
	out := Parse("ARG NUCLEI_VERSION=3.3.7\nRUN PKGS=\"$PKGS sqlmap\"\n").Render()
	if !strings.Contains(out, "COVERAGE") {
		t.Error("no coverage disclosure: the totals read as a claim about the whole image")
	}
	if !strings.Contains(out, "UNMANAGED") {
		t.Error("an unmanaged tool was counted but never rendered — invisible in the report that " +
			"exists to make version control visible")
	}
	if !strings.Contains(out, "sqlmap") {
		t.Error("the unmanaged tool is not named; a count alone does not tell anyone what to pin")
	}
}
