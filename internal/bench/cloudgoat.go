// Package bench — cloudgoat.go scores the IAM privilege-escalation evaluator against a SECOND
// external answer key: Rhino Security Labs' CloudGoat.
//
// WHY A SECOND KEY. IAM-Vulnerable (Bishop Fox) scored 64.5% where every in-house bench scored
// 100%, and Rhino's GCP catalogue scored 65.2% — two independent keys, each saying "about two
// thirds". `tsbench cloud-engine --cloudgoat` replays TWO CloudGoat scenarios we TRANSCRIBED by
// hand, which is our reading of their lab, not their lab. This reads the scenarios' own
// Terraform — the corpus as Rhino published it, every scenario — and asks the same question
// IAM-Vulnerable asks: does a policy document Rhino wrote to be escalatable produce an escalation
// when our evaluator reads it?
//
// # What is and is not decidable here, stated per scenario
//
// CloudGoat is broader than IAM: cloud_breach_s3 is an SSRF through a reverse proxy, ec2_ssrf and
// rce_web_app are application bugs, vulnerable_cognito is an identity-pool misconfiguration. A
// policy-only evaluator CANNOT find those and a miss there is a correct refusal. So every scenario
// is reported with whether Rhino's OWN README describes it as a privilege escalation — the
// name or the summary says "privesc"/"privilege escalation" — and the recall figure is computed
// over THAT subset only. The non-decidable ones are listed with the route Rhino documents so a
// reader sees what the number leaves out rather than an aggregate that hides it.
//
// # Two refusals the scorer makes
//
// A document granting `*` is ADMIN, not an escalation path: the rollback scenario ships five
// policy versions and one is `"Action": "*"`. Counting a technique detected from that document
// would credit us with finding an escalation in a document that simply IS the destination. Such
// documents are counted (WildcardDocs) and never contribute to Found. And a document carrying a
// Deny statement is SKIPPED and counted, because the coarse action extraction cannot tell which
// statement an action sits in; the corpus has none today, and the count is the guard that says so.
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

// CloudGoatScenario is one scenario directory with the verdict our evaluator reached.
type CloudGoatScenario struct {
	Name string
	// Docs is how many policy documents were read (Terraform inline + policies/*.json).
	Docs int
	// WildcardDocs are documents granting "*" — admin, excluded from Found.
	WildcardDocs int
	// DenyDocsSkipped are documents with a Deny statement, skipped rather than mis-scored.
	DenyDocsSkipped int
	// Detected are the technique names cloudiam matched from a non-wildcard document.
	Detected []string
	// Found reports whether a non-wildcard document produced an escalation.
	Found bool
	// IAMDecidable is whether Rhino's own naming/summary calls the scenario a privilege escalation.
	IAMDecidable bool
	// Route is the first sentence of the README summary — Rhino's description of the attack.
	Route string
}

// CloudGoatResult is the scorecard.
type CloudGoatResult struct {
	Scenarios []CloudGoatScenario
	Total     int // scenarios with a terraform directory
	Decidable int // IAMDecidable scenarios
	Hits      int // Decidable AND Found
	// FoundOutsideDecidable counts non-decidable scenarios where a document still produced an
	// escalation — reported, not credited, because Rhino's route for them is something else.
	FoundOutsideDecidable int
}

// Recall is Hits over the IAM-decidable scenarios. 0 when nothing is decidable.
func (r CloudGoatResult) Recall() float64 {
	if r.Decidable == 0 {
		return 0
	}
	return float64(r.Hits) / float64(r.Decidable)
}

// identityPolicyTypes are the Terraform resources that carry an IDENTITY policy — what a principal
// MAY DO. aws_iam_role is deliberately absent: its inline document is the TRUST policy, which says
// who may ASSUME the role and grants the principal nothing, so mining it for actions would
// manufacture an escalation out of a document that confers no permissions.
var identityPolicyTypes = map[string]bool{
	"aws_iam_policy":       true,
	"aws_iam_role_policy":  true,
	"aws_iam_user_policy":  true,
	"aws_iam_group_policy": true,
}

// blockHeader matches a top-level Terraform block header, capturing its type.
var blockHeader = regexp.MustCompile(`(?m)^(?:resource|data|module)\s+"([^"]+)"`)

// ExtractPolicyDocs returns the body of every identity-policy resource, SPLITTING on top-level block
// headers rather than matching each block with a trailing delimiter.
//
// The delimiter approach silently dropped every OTHER adjacent policy: the pattern ended with
// `(?:\nresource\s+"|…)`, and because Go's RE2 has no lookahead that delimiter was CONSUMED, so the
// following block's header was eaten and could not start a match. Measured on three adjacent
// aws_iam_policy resources it returned two. That bias runs one way — a dropped document is an
// unseen escalation, so the recall it produces is too LOW — which is why it had to be fixed before
// the number was recorded rather than after.

var effectDeny = regexp.MustCompile(`(?i)"?Effect"?\s*[:=]\s*"Deny"`)

func ExtractPolicyDocs(tf string) []string {
	locs := blockHeader.FindAllStringSubmatchIndex(tf, -1)
	var out []string
	for i, loc := range locs {
		typ := tf[loc[2]:loc[3]]
		if !identityPolicyTypes[typ] {
			continue
		}
		end := len(tf)
		if i+1 < len(locs) {
			end = locs[i+1][0] // up to the next top-level block, not through it
		}
		out = append(out, tf[loc[1]:end])
	}
	return out
}

// actionsIn pulls the actions from one policy document's text (JSON or HCL jsonencode shape).
func actionsIn(doc string) []string {
	seen := map[string]bool{}
	var out []string
	for _, am := range actionLine.FindAllStringSubmatch(doc, -1) {
		for _, q := range quoted.FindAllStringSubmatch(am[1], -1) {
			a := strings.TrimSpace(q[1])
			if a == "" || seen[a] {
				continue
			}
			seen[a] = true
			out = append(out, a)
		}
	}
	sort.Strings(out)
	return out
}

func wildcardOnly(actions []string) bool {
	if len(actions) == 0 {
		return false
	}
	for _, a := range actions {
		if a != "*" && a != "*:*" {
			return false
		}
	}
	return true
}

// ScoreCloudGoat walks a CloudGoat `scenarios/aws` directory and scores each scenario.
//
// Grounded: a scenario counts as found only when cloudiam matched a technique from actions a
// document really grants, and the document is not itself admin. The scenario name decides only
// whether the scenario is IAM-decidable (which subset the recall is over) — never whether it was
// found.
func ScoreCloudGoat(dir string) (CloudGoatResult, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return CloudGoatResult{}, fmt.Errorf("bench: read cloudgoat scenarios: %w", err)
	}
	var res CloudGoatResult
	for _, e := range entries {
		if !e.IsDir() || e.Name() == "static" || e.Name() == "scenario_template" {
			continue
		}
		tfDir := filepath.Join(dir, e.Name(), "terraform")
		if st, err := os.Stat(tfDir); err != nil || !st.IsDir() {
			continue
		}
		sc := CloudGoatScenario{Name: e.Name()}
		readme, _ := os.ReadFile(filepath.Join(dir, e.Name(), "README.md"))
		sc.Route = readmeSummary(string(readme))
		low := strings.ToLower(e.Name() + " " + sc.Route)
		sc.IAMDecidable = strings.Contains(low, "privesc") || strings.Contains(low, "privilege escalat") || strings.Contains(low, "escalate")

		var docs []string
		_ = filepath.WalkDir(tfDir, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			b, rerr := os.ReadFile(path)
			if rerr != nil {
				return nil
			}
			switch {
			case strings.HasSuffix(path, ".tf"):
				docs = append(docs, ExtractPolicyDocs(string(b))...)
			case strings.HasSuffix(path, ".json") && strings.Contains(string(b), "Action"):
				docs = append(docs, string(b))
			}
			return nil
		})
		detected := map[string]bool{}
		for _, doc := range docs {
			actions := actionsIn(doc)
			if len(actions) == 0 {
				continue
			}
			sc.Docs++
			if effectDeny.MatchString(doc) {
				sc.DenyDocsSkipped++
				continue
			}
			if wildcardOnly(actions) {
				sc.WildcardDocs++
				continue
			}
			granted := map[string]bool{}
			for _, a := range actions {
				granted[strings.ToLower(a)] = true
			}
			can := func(a string) bool { return granted[strings.ToLower(a)] || granted["*"] || wildcardMatch(granted, a) }
			for _, t := range cloudiam.DetectPrivesc(can) {
				detected[t.Name] = true
			}
		}
		for n := range detected {
			sc.Detected = append(sc.Detected, n)
		}
		sort.Strings(sc.Detected)
		sc.Found = len(sc.Detected) > 0
		res.Scenarios = append(res.Scenarios, sc)
		res.Total++
		if sc.IAMDecidable {
			res.Decidable++
			if sc.Found {
				res.Hits++
			}
		} else if sc.Found {
			res.FoundOutsideDecidable++
		}
	}
	sort.Slice(res.Scenarios, func(i, j int) bool { return res.Scenarios[i].Name < res.Scenarios[j].Name })
	return res, nil
}

// wildcardMatch honours service-level and prefix wildcards the corpus writes ("iam:*", "iam:List*"):
// a granted "iam:*" covers "iam:PassRole"; "iam:Get*" does not.
func wildcardMatch(granted map[string]bool, action string) bool {
	a := strings.ToLower(action)
	for g := range granted {
		if !strings.HasSuffix(g, "*") {
			continue
		}
		if strings.HasPrefix(a, strings.TrimSuffix(g, "*")) {
			return true
		}
	}
	return false
}

// readmeSummary returns the first sentence under "## Summary", or "".
func readmeSummary(md string) string {
	i := strings.Index(md, "## Summary")
	if i < 0 {
		return ""
	}
	rest := strings.TrimSpace(md[i+len("## Summary"):])
	if j := strings.Index(rest, "\n\n"); j > 0 {
		rest = rest[:j]
	}
	rest = strings.TrimSpace(strings.ReplaceAll(rest, "\n", " "))
	if k := strings.Index(rest, ". "); k > 0 && k < 200 {
		rest = rest[:k+1]
	}
	if len(rest) > 220 {
		rest = rest[:220] + "…"
	}
	return rest
}

// RenderCloudGoat writes the per-scenario scorecard. The non-decidable scenarios are listed
// with Rhino's route, because a recall over a subset is only honest when the reader can see the
// subset's complement.
func RenderCloudGoat(r CloudGoatResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "=== IAM privesc detection vs CloudGoat (Rhino Security Labs) — EXTERNAL answer key ===\n")
	fmt.Fprintf(&b, "scenarios: %d   IAM-decidable (Rhino's own naming): %d   detected: %d   recall over decidable: %.1f%%\n",
		r.Total, r.Decidable, r.Hits, r.Recall()*100)
	fmt.Fprintf(&b, "This is a POLICY-ONLY read of the published Terraform (no AWS account). It cannot see the application, network and\n")
	fmt.Fprintf(&b, "service-misconfiguration routes; those scenarios are listed below so the number's scope is visible.\n\n")
	fmt.Fprintf(&b, "IAM-decidable scenarios:\n")
	for _, s := range r.Scenarios {
		if !s.IAMDecidable {
			continue
		}
		mark := "MISS"
		if s.Found {
			mark = "hit "
		}
		fmt.Fprintf(&b, "  %s  %-32s docs=%d wildcard=%d", mark, s.Name, s.Docs, s.WildcardDocs)
		if s.DenyDocsSkipped > 0 {
			fmt.Fprintf(&b, " deny-skipped=%d", s.DenyDocsSkipped)
		}
		if len(s.Detected) > 0 {
			fmt.Fprintf(&b, "  %s", strings.Join(s.Detected, ", "))
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "\nNot IAM-decidable (Rhino's documented route is not a policy escalation) — not scored:\n")
	for _, s := range r.Scenarios {
		if s.IAMDecidable {
			continue
		}
		extra := ""
		if s.Found {
			extra = "  [a document still yields " + strings.Join(s.Detected, ", ") + " — reported, not credited]"
		}
		route := s.Route
		if route == "" {
			route = "(no summary in README)"
		}
		fmt.Fprintf(&b, "  %-32s %s%s\n", s.Name, route, extra)
	}
	return b.String()
}
