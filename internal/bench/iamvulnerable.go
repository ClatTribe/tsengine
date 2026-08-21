// Package bench — iamvulnerable.go scores the IAM privilege-escalation evaluator against
// an EXTERNAL answer key.
//
// WHY THIS FILE EXISTS. Every other capability number in this repo is measured on ground
// truth we wrote. cloudengine/holdout.go says so about its own in-distribution bench —
// "circular by construction" — and the honest held-out variant still uses fixtures we
// authored. A vendor scoring itself against its own fixtures learns whether the fixtures
// and the code agree, which is not the question anyone is asking.
//
// IAM-Vulnerable (github.com/BishopFox/iam-vulnerable) is the neutral corpus CLAUDE.md
// §2.2.1 already names for the cloud specialist. It is a Terraform deployment of ~31
// NAMED privilege-escalation paths, each with the exact IAM policy that enables it, and
// the naming is Bishop Fox's rather than ours. The file name IS the answer key.
//
// The policies are documents, so this needs NO AWS account: extract the policy from the
// Terraform, hand it to cloudiam.DetectPrivesc, and ask whether we find an escalation
// Bishop Fox says is there.
//
// # What a miss means, and why per-path reporting is mandatory
//
// Some of these paths are NOT decidable from permissions alone — privesc-AssumeRole turns
// on a trust policy, ssmSendCommand needs an EC2 instance to exist. A miss there is a
// correct refusal, not a defect. An aggregate number would hide that distinction entirely,
// so every path is reported individually and the summary states how many misses are
// permission-decidable. A benchmark that cannot tell a real gap from a principled refusal
// is worse than none.
package bench

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/internal/cloudiam"
)

// IAMVulnPath is one path from the suite, with the verdict our evaluator reached.
type IAMVulnPath struct {
	// Name is the Terraform file's basename — Bishop Fox's name for the path.
	Name string
	// Actions are the IAM actions the path's policy grants, as written in the corpus.
	Actions []string
	// Detected are the technique names cloudiam matched. Empty means we found nothing.
	Detected []string
	// Found reports whether we detected any escalation for this path.
	Found bool
}

// IAMVulnResult is the scorecard.
type IAMVulnResult struct {
	Paths []IAMVulnPath
	Total int
	Hits  int
}

// Recall is the share of corpus paths where we detected an escalation.
func (r IAMVulnResult) Recall() float64 {
	if r.Total == 0 {
		return 0
	}
	return float64(r.Hits) / float64(r.Total)
}

// Missed returns the paths where we found nothing, in corpus order.
func (r IAMVulnResult) Missed() []IAMVulnPath {
	var out []IAMVulnPath
	for _, p := range r.Paths {
		if !p.Found {
			out = append(out, p)
		}
	}
	return out
}

// policyBlock matches an aws_iam_policy resource's jsonencode body. Deliberately narrow:
// this reads ONE known corpus in ONE known shape, and a general HCL parser would be a new
// dependency and a new thing to be wrong about. If the corpus changes shape this stops
// matching and the count drops visibly, which is the failure mode we want.
//
// The `[^{}]*?` before `policy =` is load-bearing and was `.*?`. Non-greedy still matches
// across anything, so on a file whose aws_iam_policy references a data source instead of
// inlining one, the match ran PAST the closing brace and captured the next resource's
// assume_role_policy — the role TRUST policy, scored as if it were the identity policy
// under test. Both condition cases in the control set were graded against a document that
// was not the fixture, and one of them passed that way. Excluding braces confines the
// match to the block it started in, so a file with no inline policy now yields nothing,
// which is the honest answer.
var policyBlock = regexp.MustCompile(`(?s)resource\s+"aws_iam_policy"\s+"[^"]+"\s*\{[^{}]*?policy\s*=\s*jsonencode\((.*?)\n\s*\}\s*\)`)

// actionLine matches `Action = "x"` / `Action = ["x", "y"]` / `"Action": "x"`.
var actionLine = regexp.MustCompile(`(?s)"?Action"?\s*[:=]\s*(\[[^\]]*\]|"[^"]*")`)
var quoted = regexp.MustCompile(`"([^"]+)"`)

// ExtractActions pulls the IAM actions out of one Terraform file's aws_iam_policy blocks.
// Returns nil when the file declares no policy — a role-only or user-only file is not a
// parse failure.
func ExtractActions(tf string) []string {
	seen := map[string]bool{}
	var out []string
	for _, block := range policyBlock.FindAllStringSubmatch(tf, -1) {
		for _, am := range actionLine.FindAllStringSubmatch(block[1], -1) {
			for _, q := range quoted.FindAllStringSubmatch(am[1], -1) {
				a := strings.TrimSpace(q[1])
				// "*" is a wildcard grant, real but uninteresting as a named path.
				if a == "" || seen[a] {
					continue
				}
				seen[a] = true
				out = append(out, a)
			}
		}
	}
	sort.Strings(out)
	return out
}

// ScoreIAMVulnerable walks the corpus's privesc-paths directory and scores each path.
//
// Grounded: a path counts as found only when cloudiam really matched a technique from the
// actions the corpus really grants. Nothing is inferred from the file name — the name is
// the ANSWER, never an input.
func ScoreIAMVulnerable(dir string) (IAMVulnResult, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return IAMVulnResult{}, fmt.Errorf("bench: read iam-vulnerable suite: %w", err)
	}
	var res IAMVulnResult
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".tf") {
			continue
		}
		// variables.tf and shared helpers declare no privesc path.
		if !strings.HasPrefix(e.Name(), "privesc") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)

	for _, n := range names {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			return IAMVulnResult{}, fmt.Errorf("bench: read %s: %w", n, err)
		}
		actions := ExtractActions(string(b))
		if len(actions) == 0 {
			continue // no policy in this file: nothing to score, and no credit claimed
		}
		granted := map[string]bool{}
		for _, a := range actions {
			granted[strings.ToLower(a)] = true
		}
		can := func(a string) bool {
			if granted["*"] {
				return true
			}
			return granted[strings.ToLower(a)]
		}
		var detected []string
		for _, t := range cloudiam.DetectPrivesc(can) {
			detected = append(detected, t.Name)
		}
		p := IAMVulnPath{
			Name:     strings.TrimSuffix(n, ".tf"),
			Actions:  actions,
			Detected: detected,
			Found:    len(detected) > 0,
		}
		res.Paths = append(res.Paths, p)
		res.Total++
		if p.Found {
			res.Hits++
		}
	}
	return res, nil
}

// RenderIAMVulnerable writes the per-path scorecard.
//
// Per-path is not a nicety. Some corpus paths are undecidable from permissions alone, so
// an aggregate cannot distinguish a real gap from a correct refusal — and a benchmark
// that cannot make that distinction is worse than none.
func RenderIAMVulnerable(r IAMVulnResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "=== IAM privesc detection vs IAM-Vulnerable (BishopFox) — EXTERNAL answer key ===\n")
	fmt.Fprintf(&b, "paths scored: %d   detected: %d   recall: %.2f%%\n\n", r.Total, r.Hits, r.Recall()*100)
	fmt.Fprintf(&b, "| Path (corpus name = answer key) | Detected as | Actions granted |\n")
	fmt.Fprintf(&b, "|---|---|---|\n")
	for _, p := range r.Paths {
		det := strings.Join(p.Detected, ", ")
		if det == "" {
			det = "— NOT DETECTED"
		}
		fmt.Fprintf(&b, "| %s | %s | %s |\n", p.Name, det, strings.Join(p.Actions, " "))
	}
	if m := r.Missed(); len(m) > 0 {
		fmt.Fprintf(&b, "\nMISSED (%d) — each needs a judgement, because some of this corpus is NOT\n", len(m))
		fmt.Fprintf(&b, "decidable from permissions alone (a trust policy, or a resource that must exist):\n")
		for _, p := range m {
			fmt.Fprintf(&b, "  - %s  [granted: %s]\n", p.Name, strings.Join(p.Actions, " "))
		}
	}
	fmt.Fprintf(&b, "\nThe corpus and its path names are Bishop Fox's, not ours: this is the one\n")
	fmt.Fprintf(&b, "capability number here whose ground truth we did not author.\n")
	return b.String()
}
