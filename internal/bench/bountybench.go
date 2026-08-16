package bench

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// BountyBench (github.com/bountybench/bountybench, Stanford) — real bounties on 25+ production
// codebases, split into three DISTINCT task types: Detect, Exploit, Patch.
//
// # Why this benchmark and not another of ours
//
// Our agent numbers are blended and self-defined. `tsbench xbow` scores flag capture, `cvepatch`
// scores patching, `defense` scores remediation — three harnesses we wrote, on corpora we chose, with
// no external comparison. BountyBench splits exactly the way a security team divides labour, on code we did
// not pick, with an oracle we do not control:
//
//   - Detect  — find a vulnerability nobody pointed you at
//   - Exploit — given the vulnerability, prove it
//   - Patch   — given the vulnerability, close it without breaking the app
//
// That maps onto our two products directly: Detect+Exploit is the AI pentester, Patch is the AI
// security engineer. A per-task number is the thing we could not produce.
//
// # What this file does, and deliberately does not
//
// It loads and inventories their task corpus. It does NOT score: scoring happens in their Python +
// Docker harness (`workflows.runner --workflow-type patch_workflow`), and their verify.sh is the
// oracle. That separation is the entire point of using someone else's benchmark — the same rule the
// PatchEval adapter follows.
//
// The inventory answers the question that has to come first: of their tasks, which fall in classes we
// claim to handle at all? That is the honest denominator. Claiming a score against tasks whose
// vulnerability class we have no detector for would repeat the mistake this campaign kept finding.

// BountyTask is one bounty: a real vulnerability in a real project, with their ground truth.
type BountyTask struct {
	Project   string  `json:"project"`    // e.g. "lunary", "django"
	Bounty    string  `json:"bounty"`     // e.g. "bounty_0"
	CWE       string  `json:"cwe"`        // "CWE-639: Authorization Bypass Through User-Controlled Key"
	CVE       string  `json:"cve"`        // may be empty — not every bounty has one
	Severity  float64 `json:"severity"`   // CVSS, 0 when absent
	PatchUSD  int     `json:"patch_usd"`  // what the patch bounty actually paid
	DetectUSD int     `json:"detect_usd"` // what disclosure paid
	// HasPatch / HasExploit / HasVerify record which task types this bounty can actually be scored
	// on. A bounty with no verify.sh has no oracle, so it is not a Detect/Exploit task for us — a
	// missing oracle is a task we cannot grade, never a task we passed.
	HasPatch   bool `json:"has_patch"`
	HasExploit bool `json:"has_exploit"`
	HasVerify  bool `json:"has_verify"`
}

// CWEID extracts the bare identifier ("CWE-639") from the descriptive CWE string.
//
// Their corpus writes it several ways — "CWE-29: Path Traversal: '\\..\\filename'" has two colons,
// and some entries carry the bare number. Splitting on the first colon and re-prefixing a bare
// numeric handles both without guessing at anything else.
func (t BountyTask) CWEID() string {
	s := strings.TrimSpace(t.CWE)
	if i := strings.Index(s, ":"); i > 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	if s != "" && !strings.HasPrefix(strings.ToUpper(s), "CWE-") {
		if _, err := strconv.Atoi(s); err == nil {
			return "CWE-" + s
		}
	}
	return s
}

// cweFamily maps a specific CWE onto the broader class a detector actually covers.
//
// A rule that finds path traversal finds it whether the corpus labels the instance CWE-22
// ("Path Traversal"), CWE-23 ("Relative Path Traversal") or CWE-29 ("'\\..\\filename'") — those are
// siblings describing the same bug with different specificity, and 5 of their 46 bounties use the
// variants. Treating them as separate classes UNDERSTATED our coverage.
//
// This is the same trap the SAST scorer hit, where semgrep emitted CWE-326 for crypto cases the
// ground truth labelled CWE-327 and every real detection was silently discarded. Sibling collapse has
// to be explicit, and only where one detector genuinely covers both.
var cweFamily = map[string]string{
	"CWE-23":  "CWE-22",  // relative path traversal
	"CWE-29":  "CWE-22",  // '\..\filename' path traversal
	"CWE-35":  "CWE-22",  // path traversal ../
	"CWE-36":  "CWE-22",  // absolute path traversal
	"CWE-776": "CWE-611", // XML entity expansion — the billion-laughs sibling of XXE
	"CWE-80":  "CWE-79",  // basic XSS
	"CWE-83":  "CWE-79",  // XSS in attributes
	"CWE-91":  "CWE-89",  // XML/XPath injection family
	"CWE-943": "CWE-89",  // improper neutralisation in a query
}

// canonicalCWE collapses a specific CWE onto the family a detector covers, when one applies.
func canonicalCWE(id string) string {
	if fam, ok := cweFamily[id]; ok {
		return fam
	}
	return id
}

type bountyMetadata struct {
	CWE              string            `json:"CWE"`
	CVE              string            `json:"CVE"`
	Severity         string            `json:"severity"`
	DisclosureBounty string            `json:"disclosure_bounty"`
	PatchBounty      string            `json:"patch_bounty"`
	Patch            map[string]string `json:"patch"`
}

// LoadBountyBench walks a checkout of their bountytasks corpus.
//
// dir is the corpus root (the directory holding one folder per project). Their layout is
// <project>/bounties/<bounty_N>/bounty_metadata.json, so anything not matching that shape is skipped
// rather than guessed at.
func LoadBountyBench(dir string) ([]BountyTask, error) {
	projects, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("bountybench: read corpus %s: %w", dir, err)
	}
	var out []BountyTask
	for _, p := range projects {
		if !p.IsDir() || strings.HasPrefix(p.Name(), ".") {
			continue
		}
		bountiesDir := filepath.Join(dir, p.Name(), "bounties")
		entries, derr := os.ReadDir(bountiesDir)
		if derr != nil {
			continue // a project folder with no bounties/ is not a task source
		}
		for _, b := range entries {
			if !b.IsDir() {
				continue
			}
			base := filepath.Join(bountiesDir, b.Name())
			raw, rerr := os.ReadFile(filepath.Join(base, "bounty_metadata.json")) //nolint:gosec // corpus path
			if rerr != nil {
				continue
			}
			var md bountyMetadata
			if json.Unmarshal(raw, &md) != nil {
				continue
			}
			t := BountyTask{
				Project: p.Name(), Bounty: b.Name(),
				CWE: md.CWE, CVE: md.CVE,
				Severity:   parseFloat(md.Severity),
				PatchUSD:   parseInt(md.PatchBounty),
				DetectUSD:  parseInt(md.DisclosureBounty),
				HasPatch:   len(md.Patch) > 0,
				HasExploit: fileExists(filepath.Join(base, "exploit_files", "exploit.sh")),
				HasVerify:  fileExists(filepath.Join(base, "verify_files", "verify.sh")),
			}
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Project != out[j].Project {
			return out[i].Project < out[j].Project
		}
		return out[i].Bounty < out[j].Bounty
	})
	return out, nil
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func parseFloat(s string) float64 {
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0
	}
	return v
}

func parseInt(s string) int {
	v, err := strconv.Atoi(strings.TrimSpace(strings.ReplaceAll(s, ",", "")))
	if err != nil {
		return 0
	}
	return v
}

// coveredCWEs are the vulnerability classes this engine has a real detector or agent capability for.
//
// Grounded deliberately: each entry corresponds to something that exists — a wrapped OSS tool, an
// agent tool, or a deterministic core — not to a class we would like to cover. bola_probe and
// apiauthz make CWE-639/CWE-284/CWE-863 real for us; semgrep's packs cover the injection and
// path-traversal families; there is no in-house detector for, say, a business-logic race, so it is
// absent rather than optimistically listed.
var coveredCWEs = map[string]string{
	"CWE-22":  "path traversal — semgrep + nuclei",
	"CWE-77":  "command injection — semgrep",
	"CWE-78":  "OS command injection — semgrep",
	"CWE-79":  "XSS — semgrep + dalfox",
	"CWE-89":  "SQL injection — semgrep + sqlmap",
	"CWE-94":  "code injection — semgrep",
	"CWE-284": "improper access control — apiauthz",
	"CWE-287": "improper authentication — apiauthz",
	"CWE-352": "CSRF — nuclei",
	"CWE-434": "unrestricted upload — semgrep",
	"CWE-502": "unsafe deserialization — semgrep",
	"CWE-611": "XXE — semgrep",
	"CWE-639": "authorization bypass / BOLA — bola_probe + apiauthz",
	"CWE-862": "missing authorization — apiauthz",
	"CWE-863": "incorrect authorization — apiauthz + privesc_probe",
	"CWE-918": "SSRF — nuclei DAST/OAST",
}

// BountyInventory summarises a corpus: how many tasks of each type, and how many fall in a class we
// have any capability for.
type BountyInventory struct {
	Projects int `json:"projects"`
	Tasks    int `json:"tasks"`
	// Per task type, how many bounties can be graded at all.
	PatchTasks   int `json:"patch_tasks"`
	ExploitTasks int `json:"exploit_tasks"`
	VerifyTasks  int `json:"verify_tasks"`
	// Covered is how many tasks sit in a CWE class this engine has a real capability for. The rest
	// are the honest denominator gap: scoring them would measure classes we never claimed.
	Covered   int            `json:"covered"`
	Uncovered int            `json:"uncovered"`
	ByCWE     map[string]int `json:"by_cwe"`
	// UncoveredCWEs are the classes present in the corpus that we have nothing for, worst-count
	// first — the ranked list of what to build next, chosen by someone else's corpus rather than ours.
	UncoveredCWEs []string `json:"uncovered_cwes,omitempty"`
	TotalPatchUSD int      `json:"total_patch_usd"`
}

// InventoryBountyBench summarises what a corpus contains and how much of it we can speak to.
func InventoryBountyBench(tasks []BountyTask) BountyInventory {
	inv := BountyInventory{Tasks: len(tasks), ByCWE: map[string]int{}}
	projects := map[string]bool{}
	uncovered := map[string]int{}
	for _, t := range tasks {
		projects[t.Project] = true
		if t.HasPatch {
			inv.PatchTasks++
		}
		if t.HasExploit {
			inv.ExploitTasks++
		}
		if t.HasVerify {
			inv.VerifyTasks++
		}
		inv.TotalPatchUSD += t.PatchUSD
		id := t.CWEID()
		if id != "" {
			inv.ByCWE[id]++
		}
		if _, ok := coveredCWEs[canonicalCWE(id)]; ok {
			inv.Covered++
		} else {
			inv.Uncovered++
			if id != "" {
				uncovered[id]++
			}
		}
	}
	inv.Projects = len(projects)
	for cwe := range uncovered {
		inv.UncoveredCWEs = append(inv.UncoveredCWEs, cwe)
	}
	sort.Slice(inv.UncoveredCWEs, func(i, j int) bool {
		a, b := inv.UncoveredCWEs[i], inv.UncoveredCWEs[j]
		if uncovered[a] != uncovered[b] {
			return uncovered[a] > uncovered[b]
		}
		return a < b
	})
	return inv
}

// RenderBountyInventory formats the corpus summary.
func RenderBountyInventory(inv BountyInventory, tasks []BountyTask) string {
	var b strings.Builder
	fmt.Fprintf(&b, "=== BountyBench corpus (real bounties, %d projects) ===\n", inv.Projects)
	fmt.Fprintf(&b, "tasks:            %d bounties\n", inv.Tasks)
	fmt.Fprintf(&b, "  patch tasks:    %d  (ground-truth patch supplied → AI security engineer)\n", inv.PatchTasks)
	fmt.Fprintf(&b, "  exploit tasks:  %d  (reference exploit supplied → AI pentester)\n", inv.ExploitTasks)
	fmt.Fprintf(&b, "  gradable:       %d  (verify.sh present — their oracle, not ours)\n", inv.VerifyTasks)
	fmt.Fprintf(&b, "patch bounties paid on this corpus: $%d\n", inv.TotalPatchUSD)

	fmt.Fprintf(&b, "\ncapability coverage (grounded — a class counts only if a real detector exists):\n")
	fmt.Fprintf(&b, "  in a class we cover:     %d\n", inv.Covered)
	fmt.Fprintf(&b, "  in a class we do NOT:    %d\n", inv.Uncovered)
	if len(inv.UncoveredCWEs) > 0 {
		fmt.Fprintf(&b, "  uncovered classes, most-frequent first: %s\n",
			strings.Join(truncate(inv.UncoveredCWEs, 12), ", "))
		fmt.Fprintf(&b, "  ^ this is the build backlog, ranked by someone else's corpus rather than ours.\n")
	}
	b.WriteString("\nNOT A SCORE. Their harness (workflows.runner) and verify.sh decide pass/fail;\n" +
		"this only reports what the corpus holds and how much of it we can honestly speak to.\n")
	return b.String()
}

func truncate(xs []string, n int) []string {
	if len(xs) <= n {
		return xs
	}
	return append(append([]string{}, xs[:n]...), "…")
}
