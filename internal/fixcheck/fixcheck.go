// Package fixcheck is PRE-DELIVERY patch soundness: the checks a proposed code fix must survive
// before it is committed to a PR branch and handed to a human.
//
// WHY THIS EXISTS. The autofix pipeline (finding → ProposePatch → Patcher → connector commits the
// files → PR opens) had NOTHING between "the model produced a patch" and "the patch is on a branch a
// human is asked to merge". A code-fix action auto-applies at tier 1, so a bad patch reaches a real
// pull request with no gate. Three failures reach the human unexamined today:
//   - a NO-OP patch: the model echoed the file back unchanged, or changed only whitespace, and the PR
//     claims to fix a vulnerability while changing nothing;
//   - a MISDIRECTED patch: the model edited some other part of the file and left the exact line the
//     finding cites untouched, so the vulnerability is still there behind a plausible-looking diff;
//   - a BROKEN patch: the rewritten file no longer parses, so an auto-applied PR breaks the build.
//
// WHAT THIS IS, AND IS NOT. These checks run in OUR process, host-side, over content we already have
// (the original file and the proposed replacement). They prove the patch is SOUND — non-trivial,
// aimed at the cited location, and syntactically valid where we can check the language. They do NOT
// prove the vulnerability is CLOSED: that needs the customer's runtime and the recorded exploit, and
// it happens AFTER the fix is deployed (internal/retest + the re-attack path). Claiming closure here
// would be exactly the false assurance §10 forbids — so the report says, in its own words, that it is
// soundness and not proof.
//
// GROUNDED (§10) + DETERMINISTIC: every verdict is computed from the two file contents and the
// finding's own cited location. No model runs here — the model proposed the patch; this disposes on
// whether the proposal is sound, and a check it cannot perform (a language it cannot parse, a finding
// with no locatable line) is reported as NOT CHECKED, never as a pass.
package fixcheck

import (
	"go/parser"
	"go/token"
	"strconv"
	"strings"
)

// Status is one check's outcome. The distinction between Fail and NotChecked is the whole point:
// a Fail is evidence the patch is unsound; NotChecked is the honest absence of a check, and must
// never read as a pass.
type Status string

const (
	Pass       Status = "pass"
	Fail       Status = "fail"
	NotChecked Status = "not_checked" // we could not run this check (language we don't parse, no cited line)
)

// Check is one named pre-delivery check and its verdict.
type Check struct {
	Name    string `json:"name"`
	Status  Status `json:"status"`
	Message string `json:"message"`
}

// Report is the full pre-delivery verdict for one patch.
type Report struct {
	Checks []Check `json:"checks"`
	// Blocking is true when any check FAILED — the patch should not be auto-committed and a human must
	// look before merging. A NotChecked never blocks (absence of a check is not evidence of a fault).
	Blocking bool `json:"blocking"`
	// Note is the honest scope statement, always present: these checks prove soundness, not closure.
	Note string `json:"note"`
}

// Finding is the minimal cited evidence a check needs: the file:line the finding points at.
type Finding struct {
	// Endpoint is the finding's location. For a repository finding it is "relative/path.ext:LINE".
	Endpoint string
}

// File is one file's original and proposed contents (both keyed by the same repository path).
type File struct {
	Path     string
	Original string
	Patched  string
}

// Check runs every pre-delivery check over the patched files and returns the combined report.
// `files` pairs each patched file with the original it replaces; `f` is the finding being fixed.
func Checks(f Finding, files []File) Report {
	r := Report{Note: "These checks prove the patch is SOUND (non-trivial, aimed at the cited line, parses) — " +
		"NOT that the vulnerability is closed. Closure is verified after the fix is deployed, by re-running the scan and the exploit."}
	r.Checks = append(r.Checks, checkNonTrivial(files))
	r.Checks = append(r.Checks, checkTouchesCitedLine(f, files))
	r.Checks = append(r.Checks, checkSyntax(files))
	for _, c := range r.Checks {
		if c.Status == Fail {
			r.Blocking = true
		}
	}
	return r
}

// checkNonTrivial fails when the patch changes nothing of substance — every patched file is identical
// to its original once trailing whitespace on each line is ignored (a whitespace-only "fix" is a
// no-op dressed up as a change). The model echoing the file back is a real and common failure.
func checkNonTrivial(files []File) Check {
	const name = "non_trivial"
	for _, fl := range files {
		if normalize(fl.Original) != normalize(fl.Patched) {
			return Check{name, Pass, "the patch changes file content"}
		}
	}
	return Check{name, Fail, "the proposed patch is identical to the current file(s) — it changes nothing, so it cannot be a fix"}
}

// checkTouchesCitedLine fails when the finding cites a specific line and the patched file still
// contains that exact source line unchanged — i.e. the fix edited something else and left the
// vulnerable location in place. NotChecked when the finding has no locatable line, or the cited file
// is not among the patched files (then checkNonTrivial already covers "did anything change").
func checkTouchesCitedLine(f Finding, files []File) Check {
	const name = "changes_cited_line"
	path, line, ok := parseEndpoint(f.Endpoint)
	if !ok {
		return Check{name, NotChecked, "the finding cites no file:line, so the exact fix location cannot be checked"}
	}
	var fl *File
	for i := range files {
		if sameRepoPath(files[i].Path, path) {
			fl = &files[i]
			break
		}
	}
	if fl == nil {
		return Check{name, NotChecked, "the cited file " + path + " is not among the patched files"}
	}
	origLines := strings.Split(fl.Original, "\n")
	if line < 1 || line > len(origLines) {
		return Check{name, NotChecked, "the cited line is outside the file as we read it (the file may have moved); relying on the other checks"}
	}
	cited := strings.TrimSpace(origLines[line-1])
	if cited == "" {
		return Check{name, NotChecked, "the cited line is blank in the file we read; relying on the other checks"}
	}
	// If the exact cited source line still appears anywhere in the patched file, the vulnerable line
	// was not removed or rewritten. Comparing the trimmed line avoids a false fail from reindentation.
	for _, pl := range strings.Split(fl.Patched, "\n") {
		if strings.TrimSpace(pl) == cited {
			return Check{name, Fail, "the patch does not change the line the finding cites (`" + truncate(cited, 80) +
				"` is still present) — the fix may be aimed at the wrong place"}
		}
	}
	return Check{name, Pass, "the cited vulnerable line is no longer present as-is"}
}

// checkSyntax fails when a patched file in a language we can parse no longer parses. Only Go is
// parsed today (go/parser is in the stdlib — no new dependency and no sandbox); files in other
// languages are reported NotChecked by language, never assumed valid. An auto-applied patch that
// breaks the build is a severe, catchable failure, so a parse failure BLOCKS.
func checkSyntax(files []File) Check {
	const name = "syntax_valid"
	var unchecked []string
	for _, fl := range files {
		switch {
		case strings.HasSuffix(fl.Path, ".go"):
			fset := token.NewFileSet()
			if _, err := parser.ParseFile(fset, fl.Path, fl.Patched, parser.SkipObjectResolution); err != nil {
				return Check{name, Fail, "the patched file " + fl.Path + " no longer parses as Go: " + oneLine(err.Error())}
			}
		default:
			unchecked = append(unchecked, langOf(fl.Path))
		}
	}
	if len(unchecked) == len(files) && len(files) > 0 {
		return Check{name, NotChecked, "no patched file is in a language this check parses yet (" + strings.Join(dedupe(unchecked), ", ") +
			"); only Go syntax is verified today"}
	}
	msg := "every Go file in the patch parses"
	if len(unchecked) > 0 {
		msg += "; " + strconv.Itoa(len(unchecked)) + " non-Go file(s) not syntax-checked"
	}
	return Check{name, Pass, msg}
}

// --- helpers ---

func normalize(s string) string {
	lines := strings.Split(s, "\n")
	for i := range lines {
		lines[i] = strings.TrimRight(lines[i], " \t\r")
	}
	// Drop trailing blank lines so an added/removed final newline is not a "change".
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return strings.Join(lines, "\n")
}

// parseEndpoint splits "path/to/file.ext:LINE" into its path and line. ok=false when there is no
// trailing :LINE (so the caller reports NotChecked rather than guessing).
func parseEndpoint(ep string) (path string, line int, ok bool) {
	ep = strings.TrimSpace(ep)
	i := strings.LastIndex(ep, ":")
	if i <= 0 || i == len(ep)-1 {
		return "", 0, false
	}
	n, err := strconv.Atoi(ep[i+1:])
	if err != nil || n < 1 {
		return "", 0, false
	}
	return ep[:i], n, true
}

// sameRepoPath compares two repository paths tolerantly: an exact match, or one is a suffix of the
// other on a path boundary (the finding may cite "src/x.go" while the patch is keyed "x.go" or the
// reverse, depending on the build-context root).
func sameRepoPath(a, b string) bool {
	a, b = strings.TrimPrefix(a, "./"), strings.TrimPrefix(b, "./")
	if a == b {
		return true
	}
	return strings.HasSuffix(a, "/"+b) || strings.HasSuffix(b, "/"+a)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func oneLine(s string) string {
	return strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
}

func langOf(path string) string {
	i := strings.LastIndex(path, ".")
	if i < 0 || i == len(path)-1 {
		return "unknown"
	}
	return path[i+1:]
}

func dedupe(ss []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
