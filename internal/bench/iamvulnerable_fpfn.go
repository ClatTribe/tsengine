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
	// The corpus writes a policy two ways. Both are the fixture; only one is JSON.
	if doc, ok := extractPolicyDocumentData(tf); ok {
		return doc, true
	}
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
	if c := parseCondition(body); c != nil {
		st.Condition = c
	} else if condRe.MatchString(body) {
		// A condition we could not parse keeps its PRESENCE, which cloudiam reads as
		// making the grant conditional rather than firm. That is the right default for
		// an unknown gate, and it is why an unparsed condition can only cost recall,
		// never manufacture a false positive.
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
		// The same target derivation the ingest uses (cloudiam.CandidateResources), so
		// this measures the product's answer rather than a benchmark-only predicate.
		targets := cloudiam.CandidateResources([]*cloudiam.Document{doc}, "123456789012")
		firm := func(a string) bool {
			for _, res := range targets {
				allowed, conditional := cloudiam.Allows(a, res, doc)
				if allowed && !conditional {
					return true
				}
			}
			return false
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

// condBlock captures a Terraform `condition { ... }` block, which is how the corpus
// writes a condition in a policy-DOCUMENT data source.
var (
	condBlock  = regexp.MustCompile(`(?s)condition\s*\{(.*?)\}`)
	condTestRe = regexp.MustCompile(`test\s*=\s*"([^"]+)"`)
	condVarRe  = regexp.MustCompile(`variable\s*=\s*"([^"]+)"`)
	condValsRe = regexp.MustCompile(`(?s)values\s*=\s*\[(.*?)\]`)
	// The jsonencode form: "Condition" = { "Op" = { "key" = [...] } }.
	condJSONRe = regexp.MustCompile(`(?s)"?Condition"?\s*[:=]\s*\{(.*)`)
)

// parseCondition reads a real condition out of a corpus file, in either of the two
// forms it appears in. Returns nil when nothing parseable is present.
//
// This exists because stubbing the condition made fn3 and fp5 INDISTINGUISHABLE — both
// came back conditional, so fp5 passed for the wrong reason and fn3 failed. A control
// set is only worth the fidelity of what feeds it: a harness that discards the exact
// field the case is probing measures the harness.
func parseCondition(body string) map[string]any {
	if m := condBlock.FindStringSubmatch(body); m != nil {
		inner := m[1]
		t := condTestRe.FindStringSubmatch(inner)
		v := condVarRe.FindStringSubmatch(inner)
		vals := condValsRe.FindStringSubmatch(inner)
		if t == nil || v == nil || vals == nil {
			return nil
		}
		got := quotedAll(vals[1])
		if len(got) == 0 {
			return nil
		}
		return map[string]any{t[1]: map[string]any{v[1]: got}}
	}
	if m := condJSONRe.FindStringSubmatch(body); m != nil {
		op := regexp.MustCompile(`"([A-Za-z]+)"?\s*[:=]\s*\{`).FindStringSubmatch(m[1])
		key := regexp.MustCompile(`"([a-zA-Z0-9:_-]+)"?\s*[:=]\s*(\[[^\]]*\]|"[^"]*")`).FindStringSubmatch(m[1])
		if op == nil || key == nil {
			return nil
		}
		got := quotedAll(key[2])
		if len(got) == 0 {
			return nil
		}
		return map[string]any{op[1]: map[string]any{key[1]: got}}
	}
	return nil
}

// extractPolicyDocumentData reads a `data "aws_iam_policy_document"` block — HCL, not
// JSON, with `statement { actions = [...] effect resources condition {...} }`.
//
// Both of the control set's CONDITION cases are written this way, and nothing read them.
// They were not reported as unparsed either: the jsonencode regex wandered into the next
// resource and returned the role's trust policy, so fn3 and fp5 were both scored against
// sts:AssumeRole. fp5 "passed". A control set is worth exactly the fidelity of what feeds
// it, and a case graded on the wrong document is not evidence in either direction.
func extractPolicyDocumentData(tf string) (*cloudiam.Document, bool) {
	i := strings.Index(tf, `data "aws_iam_policy_document"`)
	if i < 0 {
		return nil, false
	}
	body, ok := braceBody(tf[i:])
	if !ok {
		return nil, false
	}
	var doc cloudiam.Document
	for rest := body; ; {
		j := strings.Index(rest, "statement")
		if j < 0 {
			break
		}
		sb, ok := braceBody(rest[j:])
		if !ok {
			break
		}
		rest = rest[j+len("statement")+len(sb):]

		st := tfStatement{Effect: "Allow"}
		if m := regexp.MustCompile(`effect\s*=\s*"([^"]+)"`).FindStringSubmatch(sb); m != nil {
			st.Effect = m[1]
		}
		if m := regexp.MustCompile(`(?s)actions\s*=\s*\[(.*?)\]`).FindStringSubmatch(sb); m != nil {
			st.Action = quotedAll(m[1])
		}
		if m := regexp.MustCompile(`(?s)not_actions\s*=\s*\[(.*?)\]`).FindStringSubmatch(sb); m != nil {
			st.NotAction = quotedAll(m[1])
		}
		if m := regexp.MustCompile(`(?s)resources\s*=\s*\[(.*?)\]`).FindStringSubmatch(sb); m != nil {
			st.Resource = quotedAll(m[1])
		}
		if c := parseCondition(sb); c != nil {
			st.Condition = c
		} else if strings.Contains(sb, "condition") {
			st.Condition = map[string]any{"Unmodelled": map[string]any{"x": "y"}}
		}
		if len(st.Action) == 0 && len(st.NotAction) == 0 {
			continue
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
	if len(doc.Statement) == 0 {
		return nil, false
	}
	return &doc, true
}

// braceBody returns the contents of the first balanced {...} in s. Brace counting rather
// than a regex because condition blocks nest inside statement blocks, and a non-greedy
// regex stops at the wrong brace — the same mistake that made policyBlock read the next
// resource entirely.
func braceBody(s string) (string, bool) {
	start := strings.Index(s, "{")
	if start < 0 {
		return "", false
	}
	depth := 0
	for i := start; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return s[start+1 : i], true
			}
		}
	}
	return "", false
}
