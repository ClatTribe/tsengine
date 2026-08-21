package bench

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/internal/cloudiam"
)

// iamvulnerable_fpfn.go scores the OTHER half of the corpus — the half that says whether
// we are wrong in the expensive direction.
//
// The recall benchmark (iamvulnerable.go) asks "do we find the escalations BishopFox
// planted". A number that only goes up when you add detections is the least trustworthy
// shape a metric has: nine new techniques can only INCREASE false positives, and a
// recall-only harness cannot see one.
//
// BishopFox ships the control set for exactly this, in modules/free-resources/tool-testing:
//
//	fp1  allow and deny in the SAME policy      → deny wins; must NOT flag
//	fp2  allow and deny across MULTIPLE policies → deny wins; must NOT flag
//	fp3  deny only                               → must NOT flag
//	fp4  non-exploitable RESOURCE constraint     → the grant cannot reach a privileged target
//	fp5  non-exploitable CONDITION constraint    → the grant is gated
//	fn1  the same privesc split across policies  → must flag
//	fn2  EXPLOITABLE resource constraint         → must flag
//	fn3  EXPLOITABLE condition constraint        → must flag
//	fn4  NotAction                               → must flag
//
// Their own file header asks the question directly: "Does the tool evaluate deny's first
// before allows like AWS does? Many tools ignore or incorrectly handle DENY actions."
//
// # Why this needs the real document
//
// The recall harness extracts a bare ACTION LIST and asks whether the actions match a
// technique. Effect, Deny, Resource and Condition are thrown away — which is precisely
// what fp1–fp5 test. Run against them, that harness would report a false positive on
// every single one, and the failure would be the harness's rather than the engine's. So
// this reconstructs a cloudiam.Document and evaluates it through the real evaluator.

// PolicyCase is one control-set file and how we scored it.
type PolicyCase struct {
	Name string
	// Expect is whether an escalation SHOULD be reported (fn) or not (fp).
	Expect bool
	// Detected is what we actually reported.
	Detected bool
	// Techniques names what fired, for the report.
	Techniques []string
	// Scored is false when the file's policy could not be reconstructed — some cases use
	// a Terraform data source rather than jsonencode. Reported, never counted as a pass.
	Scored bool
	Why    string
}

// PolicyCaseResult is the FP/FN scorecard.
type PolicyCaseResult struct {
	Cases []PolicyCase
	// FalsePositives are fp cases we flagged; FalseNegatives are fn cases we missed.
	FalsePositives, FalseNegatives, Unscored int
	FPTotal, FNTotal                         int
}

// tfStatement is the slice of an IAM statement this needs.
type tfStatement struct {
	Effect      string         `json:"Effect,omitempty"`
	Action      []string       `json:"Action,omitempty"`
	NotAction   []string       `json:"NotAction,omitempty"`
	Resource    []string       `json:"Resource,omitempty"`
	NotResource []string       `json:"NotResource,omitempty"`
	Condition   map[string]any `json:"Condition,omitempty"`
}

var (
	stmtBlock = regexp.MustCompile(`(?s)\{(.*?)\}`)
	effectRe  = regexp.MustCompile(`"?Effect"?\s*[:=]\s*"([^"]+)"`)
	notActRe  = regexp.MustCompile(`(?s)"?NotAction"?\s*[:=]\s*(\[[^\]]*\]|"[^"]*")`)
	resRe     = regexp.MustCompile(`(?s)"?Resource"?\s*[:=]\s*(\[[^\]]*\]|"[^"]*")`)
	condRe    = regexp.MustCompile(`"?Condition"?\s*[:=]`)
)

// ExtractDocument reconstructs an IAM policy document from a Terraform file's
// aws_iam_policy blocks, keeping the fields the recall harness discards.
//
// Returns ok=false when no jsonencode policy is present — several corpus cases use a
// data.aws_iam_policy_document source instead, and guessing at one would be worse than
// declaring it unscored.
func ExtractDocument(tf string) (*cloudiam.Document, bool) {
	blocks := policyBlock.FindAllStringSubmatch(tf, -1)
	if len(blocks) == 0 {
		return nil, false
	}
	var doc cloudiam.Document
	for _, b := range blocks {
		body := b[1]
		// Statements live inside `Statement = [ ... ]`; each is a brace block.
		i := strings.Index(body, "Statement")
		if i < 0 {
			continue
		}
		for _, sb := range stmtBlock.FindAllStringSubmatch(body[i:], -1) {
			st := parseStatement(sb[1])
			if len(st.Action) == 0 && len(st.NotAction) == 0 {
				continue // a Principal block or similar — not a permission statement
			}
			raw, err := json.Marshal(st)
			if err != nil {
				continue
			}
			var cs cloudiam.Statement
			if json.Unmarshal(raw, &cs) != nil {
				continue
			}
			doc.Statement = append(doc.Statement, cs)
		}
	}
	if len(doc.Statement) == 0 {
		return nil, false
	}
	return &doc, true
}

func parseStatement(body string) tfStatement {
	st := tfStatement{Effect: "Allow"}
	if m := effectRe.FindStringSubmatch(body); m != nil {
		st.Effect = m[1]
	}
	// Action, but NOT the NotAction that also contains the substring "Action".
	stripped := notActRe.ReplaceAllString(body, "")
	for _, am := range actionLine.FindAllStringSubmatch(stripped, -1) {
		st.Action = append(st.Action, quotedAll(am[1])...)
	}
	if m := notActRe.FindStringSubmatch(body); m != nil {
		st.NotAction = quotedAll(m[1])
	}
	if m := resRe.FindStringSubmatch(body); m != nil {
		st.Resource = quotedAll(m[1])
	}
	if condRe.MatchString(body) {
		// The exact condition is not modelled: its PRESENCE is what matters, because
		// cloudiam treats an unevaluated condition as making the grant conditional rather
		// than firm — which is the behaviour fp5/fn3 are probing.
		st.Condition = map[string]any{"Unmodelled": map[string]any{"x": "y"}}
	}
	return st
}

func quotedAll(s string) []string {
	var out []string
	for _, q := range quoted.FindAllStringSubmatch(s, -1) {
		if v := strings.TrimSpace(q[1]); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// ScorePolicyCases walks the control-set directory and scores each fp/fn case.
//
// A case counts as detected only on a FIRM allow — permitted and not condition-gated.
// That is the same rule the ingest uses to create an edge, so this measures what the
// product would actually report rather than a laxer benchmark-only predicate.
func ScorePolicyCases(dir string) (PolicyCaseResult, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return PolicyCaseResult{}, fmt.Errorf("bench: read tool-testing suite: %w", err)
	}
	var names []string
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".tf") {
			continue
		}
		if !strings.HasPrefix(n, "fp") && !strings.HasPrefix(n, "fn") {
			continue
		}
		names = append(names, n)
	}
	sort.Strings(names)

	var res PolicyCaseResult
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			return PolicyCaseResult{}, err
		}
		// fn = should be found; fp = should not.
		c := PolicyCase{Name: strings.TrimSuffix(n, ".tf"), Expect: strings.HasPrefix(n, "fn")}
		if c.Expect {
			res.FNTotal++
		} else {
			res.FPTotal++
		}

		doc, ok := ExtractDocument(string(b))
		if !ok {
			c.Why = "policy is not a jsonencode literal (data source) — NOT SCORED, never counted as a pass"
			res.Unscored++
			res.Cases = append(res.Cases, c)
			continue
		}
		c.Scored = true
		firm := func(a string) bool {
			allowed, conditional := cloudiam.Allows(a, "*", doc)
			return allowed && !conditional
		}
		for _, t := range cloudiam.DetectPrivesc(firm) {
			c.Techniques = append(c.Techniques, t.Name)
		}
		c.Detected = len(c.Techniques) > 0

		switch {
		case c.Expect && !c.Detected:
			res.FalseNegatives++
			c.Why = "expected an escalation and found none"
		case !c.Expect && c.Detected:
			res.FalsePositives++
			c.Why = "flagged an escalation the corpus says is not exploitable"
		}
		res.Cases = append(res.Cases, c)
	}
	return res, nil
}

// RenderPolicyCases writes the FP/FN scorecard.
func RenderPolicyCases(r PolicyCaseResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "=== IAM privesc FP/FN control set (BishopFox tool-testing) ===\n")
	fmt.Fprintf(&b, "false positives: %d/%d   false negatives: %d/%d   unscored: %d\n\n",
		r.FalsePositives, r.FPTotal, r.FalseNegatives, r.FNTotal, r.Unscored)
	fmt.Fprintf(&b, "| Case | Expect | Got | Verdict |\n|---|---|---|---|\n")
	for _, c := range r.Cases {
		exp, got, verdict := "no finding", "no finding", "✅"
		if c.Expect {
			exp = "finding"
		}
		if c.Detected {
			got = strings.Join(c.Techniques, ", ")
		}
		switch {
		case !c.Scored:
			verdict = "— unscored"
		case c.Expect != c.Detected:
			verdict = "❌ " + c.Why
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", c.Name, exp, got, verdict)
	}
	fmt.Fprintf(&b, "\nfp cases probe DENY precedence and resource/condition constraints — the corpus's\n")
	fmt.Fprintf(&b, "own header asks whether a tool evaluates denies first, as AWS does. A recall-only\n")
	fmt.Fprintf(&b, "harness cannot answer that, which is why this set exists alongside it.\n")
	return b.String()
}
