// Package toolfresh answers a question the product could not previously answer about itself:
// WHICH VERSION OF EACH SCANNER, AND WHICH SIGNATURE CORPUS, DID WE ACTUALLY TEST YOU WITH?
//
// # Why this exists
//
// An audit went looking for the mechanism CLAUDE.md §5 describes — L0 corpora "cron-paged +
// delta-verified against L1 benches" — and found that it does not exist. What it found instead:
//
//   - No script anywhere updates a scanner or a signature corpus. `scripts/` has twelve scripts and
//     none of them is this; the `refresh` targets in the Makefile are demo data.
//   - No workflow rebuilds the sandbox image on a schedule. `release.yml` fires on `v*` tags only,
//     so every baked binary and every baked corpus ages with the manual release cadence.
//   - Pinning was a mix. Six tools carried a VERSION arg and three of those were `latest`; two `go
//     install` lines were `@latest`; the rest are apt/pip/curl with no version control at all. So two
//     builds of the same Dockerfile could ship different scanners, and nothing recorded which shipped.
//     THE FLOATING FOUR (dalfox, subfinder, gitleaks, naabu) ARE NOW PINNED and CI fails on a
//     reintroduced floating ref (`tool-freshness --fail-on-floating`). The apt/pip/curl tail is not
//     version-controlled and is still reported as unmanaged — an honest remainder, not a clean bill.
//   - nuclei's BINARY is pinned to 3.3.7 while upstream is well past it — a fact independent of the
//     template corpus, and one nobody could see.
//
// That last point is the one that matters for §2.1's promise ("per-tool recall equals the standalone
// OSS tool"). A user running the standalone tool today has today's binary and today's signatures. We
// could not say what we had.
//
// # What this package does, and deliberately does not
//
// It PARSES the Dockerfile and reports the pinning state of every tool it can see. That is offline,
// deterministic and testable, which is why it is the first half.
//
// It does NOT reach the network to compare against upstream releases, and it does not update
// anything. Fetching latest-version metadata for forty tools across five ecosystems is a different
// job with different failure modes, and a checker that silently half-worked because GitHub
// rate-limited it would be worse than no checker (§10). The report says what is knowable from the
// build definition; anything beyond that is stated as unknown rather than guessed.
package toolfresh

import (
	"bufio"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// PinState is how tightly a tool's version is controlled by the build definition.
type PinState string

const (
	// PinExact: a concrete version is pinned. Reproducible, and auditable in a report.
	PinExact PinState = "pinned"
	// PinFloating: the build asks for "latest" or "@latest". Two builds of the same Dockerfile can
	// ship different scanners, and neither the evidence pack nor the VAPT report can say which.
	PinFloating PinState = "floating"
	// PinUnmanaged: installed with no version expressed at all (apt, pip without ==, a curl
	// installer). Whatever the upstream had on build day.
	PinUnmanaged PinState = "unmanaged"
)

// Tool is one scanner as the build definition describes it.
type Tool struct {
	Name    string   `json:"name"`
	Version string   `json:"version,omitempty"` // empty for unmanaged
	Pin     PinState `json:"pin"`
	// Installer is how it arrives — go, apt, pip, curl, arg. Recorded because the fix differs per
	// mechanism and a reader deciding what to pin needs to know which lever exists.
	Installer string `json:"installer"`
	// Line is the Dockerfile line number, so a report points at something editable.
	Line int `json:"line"`
}

// Report is the inventory plus the counts a human reads first.
type Report struct {
	Tools     []Tool `json:"tools"`
	Pinned    int    `json:"pinned"`
	Floating  int    `json:"floating"`
	Unmanaged int    `json:"unmanaged"`
	// Signatures is the state of each SIGNATURE corpus — a different axis from the binaries, and the
	// one that actually determines recall.
	Signatures []Signature `json:"signatures"`
}

// Signature is one detection corpus and how it is refreshed.
type Signature struct {
	Name string `json:"name"`
	// Refresh is when the corpus is obtained: "image-build" | "scan-time" | "scheduled".
	Refresh string `json:"refresh"`
	// Note states the consequence in the terms a reader cares about.
	Note string `json:"note"`
}

var (
	argVersionRe = regexp.MustCompile(`^(?:ARG|ENV)\s+([A-Z0-9_]+)_VERSION=(\S+)`)
	goInstallRe  = regexp.MustCompile(`go install\s+(\S+?)@(\S+)`)
	pipPinnedRe  = regexp.MustCompile(`pip3? install[^\n]*?([a-zA-Z0-9_.-]+)==(\S+)`)
)

// Parse reads a Dockerfile and reports what it can see about every tool's version control.
//
// Unrecognised install lines are NOT silently dropped — anything that looks like a tool install but
// carries no version becomes PinUnmanaged, because an install nobody counted is exactly how a
// forty-tool image ends up with six recorded versions.
func Parse(dockerfile string) Report {
	rep := Report{Signatures: knownSignatures()}
	seen := map[string]bool{}
	add := func(t Tool) {
		key := t.Name + "|" + t.Installer
		if seen[key] {
			return
		}
		seen[key] = true
		rep.Tools = append(rep.Tools, t)
	}

	sc := bufio.NewScanner(strings.NewReader(dockerfile))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if m := argVersionRe.FindStringSubmatch(line); m != nil {
			add(Tool{Name: strings.ToLower(m[1]), Version: m[2], Pin: pinOf(m[2]), Installer: "arg", Line: n})
			continue
		}
		for _, m := range goInstallRe.FindAllStringSubmatch(line, -1) {
			// A version given as a variable reference (`@${NAABU_VERSION}`) says nothing about what
			// will actually be installed — the ARG line does, and it is recorded separately. Counting
			// the literal "${NAABU_VERSION}" as a version would classify it PinExact and report an
			// irreproducible build as reproducible, which is the one conclusion this package exists to
			// prevent. Skip it and let the ARG speak.
			if isVarRef(m[2]) {
				continue
			}
			add(Tool{Name: goModuleName(m[1]), Version: m[2], Pin: pinOf(m[2]), Installer: "go", Line: n})
		}
		for _, m := range pipPinnedRe.FindAllStringSubmatch(line, -1) {
			add(Tool{Name: strings.ToLower(m[1]), Version: m[2], Pin: PinExact, Installer: "pip", Line: n})
		}
	}

	sort.Slice(rep.Tools, func(i, j int) bool { return rep.Tools[i].Name < rep.Tools[j].Name })
	for _, t := range rep.Tools {
		switch t.Pin {
		case PinExact:
			rep.Pinned++
		case PinFloating:
			rep.Floating++
		default:
			rep.Unmanaged++
		}
	}
	return rep
}

// isVarRef reports a version that is a build-arg reference rather than a version.
func isVarRef(v string) bool {
	v = strings.TrimSpace(v)
	return strings.HasPrefix(v, "${") || strings.HasPrefix(v, "$")
}

func pinOf(v string) PinState {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "latest", "master", "main", "":
		return PinFloating
	default:
		return PinExact
	}
}

// goModuleName reduces a module path to the binary a reader recognises.
func goModuleName(mod string) string {
	mod = strings.TrimSuffix(mod, "/...")
	parts := strings.Split(mod, "/")
	name := parts[len(parts)-1]
	// Drop a version suffix directory (…/v2) and cmd/<tool> wrappers.
	if regexp.MustCompile(`^v\d+$`).MatchString(name) && len(parts) > 1 {
		name = parts[len(parts)-2]
	}
	return strings.ToLower(name)
}

// knownSignatures records how each DETECTION corpus is obtained. Hand-maintained on purpose: each
// entry is a claim about a mechanism, and a wrong one here is worse than an absent one.
//
// Kept beside the binary inventory because the two are constantly confused. A pinned scanner with a
// stale corpus and a floating scanner with a live corpus fail in opposite directions, and only the
// corpus determines what gets found.
func knownSignatures() []Signature {
	return []Signature{
		{Name: "nuclei templates", Refresh: "image-build",
			Note: "`nuclei -update-templates` runs in the Dockerfile. No runtime refresh exists, so the corpus ages with the image release."},
		{Name: "trivy vulnerability DB", Refresh: "scan-time",
			Note: "trivy fetches its DB itself on every scan. Fresh when egress works; a fetch failure is the silent-clean-scan path."},
		{Name: "grype vulnerability DB", Refresh: "scan-time",
			Note: "same shape as trivy."},
		{Name: "semgrep rule packs", Refresh: "scan-time",
			Note: "`--config p/...` pulls from semgrep.dev per scan. Network-dependent, undeclared in the report."},
		{Name: "threat intel (KEV/EPSS/ExploitDB/Metasploit/NVD/SSVC)", Refresh: "scheduled",
			Note: "scheduler.CorpusRefresher, default 24h — the ONLY corpus with a real refresh loop, and only when TSENGINE_THREAT_INTEL_CORPUS points at one."},
	}
}

// Render is the human report. It leads with what is NOT reproducible, because that is the half a
// reader can act on.
func (r Report) Render() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Scanner version control: %d pinned · %d floating · %d unmanaged (%d seen)\n\n",
		r.Pinned, r.Floating, r.Unmanaged, len(r.Tools))

	if r.Floating > 0 {
		b.WriteString("FLOATING — two builds of this Dockerfile can ship different scanners, and neither the\n")
		b.WriteString("evidence pack nor the VAPT report can say which one tested the customer:\n")
		for _, t := range r.Tools {
			if t.Pin == PinFloating {
				fmt.Fprintf(&b, "  %-18s %-8s via %-4s  Dockerfile:%d\n", t.Name, t.Version, t.Installer, t.Line)
			}
		}
		b.WriteString("\n")
	}
	b.WriteString("PINNED:\n")
	for _, t := range r.Tools {
		if t.Pin == PinExact {
			fmt.Fprintf(&b, "  %-18s %-8s via %-4s  Dockerfile:%d\n", t.Name, t.Version, t.Installer, t.Line)
		}
	}
	b.WriteString("\nSIGNATURE CORPORA — the axis that actually determines recall:\n")
	for _, s := range r.Signatures {
		fmt.Fprintf(&b, "  %-52s %s\n      %s\n", s.Name, s.Refresh, s.Note)
	}
	return b.String()
}
