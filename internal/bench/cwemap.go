// Package bench — CWE-attribution benchmark (the ANALYSIS lane).
//
// WHY THIS EXISTS. The localization benchmark measures the CODE lane: trace taint across files, find
// the sink. A general model wins that, which is unsurprising — it is code navigation, and the
// defensive-security model vendors say plainly that their models are not for coding.
//
// This benchmark measures the other lane, on the security model's OWN home turf. The task is
// root-cause attribution: given raw scanner output with NO CWE, name the weakness class. That is
// security KNOWLEDGE, not code reasoning — and it is close to CTI-RCM, one of the two benchmarks
// Foundation-Sec publishes wins on. If the "a specialized security model beats a general model of the
// same size" hypothesis is true anywhere in this product, it should be true here.
//
// IT IS ALSO A REAL PRODUCT GAP, not a synthetic exercise. §8's compliance.map hook keys on CWE
// (hooks.Compliance.Lookup(cwes)). A finding that arrives without one gets no specific control
// mapping — it falls through to generic vulnerability-management controls at best, and to nothing at
// worst. Plenty of real scanner output is exactly that shape: a title, a description, a rule id, no
// CWE. Correct attribution turns those into mapped, auditable findings.
//
// SCORING IS GROUNDED (§10). Truth is the CWE the finding actually is, and every truth value is a key
// in the shipped crosswalk (internal/tracer/hooks/data/compliance.json), so a correct answer provably
// produces a real control mapping rather than a plausible-sounding one.
//
// OVER-CONFIDENCE IS SCORED, NOT IGNORED. Some cases are deliberately outside the crosswalk (business
// logic, a plain availability bug). The right answer there is to decline. A model that always emits a
// confident CWE would map those to controls that do not apply, which in a compliance product is worse
// than saying nothing — so declining correctly earns credit and guessing on them is penalised.
package bench

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// CWECase is one scanner finding stripped of its CWE.
type CWECase struct {
	Name string
	// Tool/RuleID/Title/Description mirror what a wrapper actually emits.
	Tool        string
	RuleID      string
	Title       string
	Description string
	// TruthCWE is the correct class, or "" when the finding legitimately maps to NO crosswalk CWE and
	// the correct behaviour is to decline.
	TruthCWE string
}

// CWEAttributor is the thing under test: propose a CWE for a finding, or "" to decline.
type CWEAttributor interface {
	Attribute(ctx context.Context, c CWECase) (cwe string, err error)
	Engine() string
}

// CWEScore is the outcome over a case set.
type CWEScore struct {
	Engine string
	Total  int
	// Correct counts exact matches on an in-crosswalk case.
	Correct int
	// CorrectDeclines counts out-of-crosswalk cases the engine correctly declined.
	CorrectDeclines int
	// Overconfident counts out-of-crosswalk cases the engine answered anyway — the compliance-damaging
	// error, since it produces control mappings that do not apply.
	Overconfident int
	// WrongClass counts in-crosswalk cases answered with the wrong CWE.
	WrongClass int
	// Abstained counts in-crosswalk cases the engine declined — a miss, but an honest one.
	Abstained int
	// Unparseable counts responses that yielded no CWE and no explicit decline (harness-visible, so a
	// format failure is never silently scored as a reasoning failure — the confound that made the
	// localization result ambiguous).
	Unparseable int
}

// Accuracy is exact-match over the in-crosswalk cases only.
func (s CWEScore) Accuracy() float64 {
	n := s.Correct + s.WrongClass + s.Abstained
	if n == 0 {
		return 0
	}
	return float64(s.Correct) / float64(n)
}

// Restraint is the share of out-of-crosswalk cases correctly declined.
func (s CWEScore) Restraint() float64 {
	n := s.CorrectDeclines + s.Overconfident
	if n == 0 {
		return 1
	}
	return float64(s.CorrectDeclines) / float64(n)
}

var cweRe = regexp.MustCompile(`(?i)CWE[-\s]?(\d{1,4})`)

// ParseCWE pulls a CWE id out of free-form model output, or reports an explicit decline.
// Returns (cwe, declined, ok): ok=false means nothing usable was found.
func ParseCWE(out string) (string, bool, bool) {
	t := strings.ToLower(out)
	// Check the decline BEFORE the id: a model that says "none — this is not CWE-89" must not be read
	// as answering CWE-89.
	for _, d := range []string{"none", "no cwe", "not applicable", "n/a", "decline", "unknown"} {
		if strings.Contains(t, d) {
			return "", true, true
		}
	}
	if m := cweRe.FindStringSubmatch(out); m != nil {
		return "CWE-" + m[1], false, true
	}
	return "", false, false
}

// ScoreCWE runs an attributor over the cases.
func ScoreCWE(ctx context.Context, a CWEAttributor, cases []CWECase) (CWEScore, error) {
	s := CWEScore{Engine: a.Engine(), Total: len(cases)}
	for _, c := range cases {
		got, err := a.Attribute(ctx, c)
		if err != nil {
			return s, fmt.Errorf("%s: %w", c.Name, err)
		}
		inCrosswalk := c.TruthCWE != ""
		switch {
		case got == "unparseable":
			s.Unparseable++
		case inCrosswalk && got == c.TruthCWE:
			s.Correct++
		case inCrosswalk && got == "":
			s.Abstained++
		case inCrosswalk:
			s.WrongClass++
		case got == "": // out-of-crosswalk, declined
			s.CorrectDeclines++
		default: // out-of-crosswalk, answered anyway
			s.Overconfident++
		}
	}
	return s, nil
}

// RenderCWEScores renders the comparison table.
func RenderCWEScores(scores []CWEScore) string {
	var b strings.Builder
	b.WriteString("# CWE-Attribution Benchmark (analysis lane)\n")
	b.WriteString("Task: name the weakness class from raw scanner output carrying NO CWE.\n")
	b.WriteString("Truth is a key in the shipped compliance crosswalk, so a correct answer provably yields a real control mapping.\n\n")
	b.WriteString("| Engine | accuracy | restraint | correct | wrong | abstained | overconfident | unparseable |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|\n")
	for _, s := range scores {
		b.WriteString(fmt.Sprintf("| %s | **%.2f** | %.2f | %d | %d | %d | %d | %d |\n",
			s.Engine, s.Accuracy(), s.Restraint(), s.Correct, s.WrongClass, s.Abstained, s.Overconfident, s.Unparseable))
	}
	b.WriteString("\n*accuracy* = exact CWE match over in-crosswalk cases. ")
	b.WriteString("*restraint* = share of out-of-crosswalk cases correctly declined ")
	b.WriteString("(guessing there maps a finding to controls that do not apply — in a compliance product that is worse than silence).\n")
	return b.String()
}

// CWECases is the corpus.
//
// Each entry is written the way a scanner actually reports: a rule id, a terse title, and a
// description of the observed behaviour. Crucially they describe the SYMPTOM, never the class — no
// entry contains the words "injection", "traversal", "deserialization" etc. as a giveaway, because a
// corpus that names the answer measures string matching rather than security knowledge.
func CWECases() []CWECase {
	cs := []CWECase{
		{
			Name: "sqli", Tool: "semgrep", RuleID: "go.lang.security.audit.database.string-formatted-query",
			Title:       "Query built with formatted string",
			Description: "A database query is assembled by concatenating a value taken from the HTTP request into the statement text before execution. The value is not bound as a parameter.",
			TruthCWE:    "CWE-89",
		},
		{
			Name: "xss", Tool: "nuclei", RuleID: "reflected-parameter-echo",
			Title:       "Request parameter echoed into response body",
			Description: "A value supplied in the query string is returned verbatim inside the HTML document without contextual encoding, and is interpreted by the browser as markup rather than text.",
			TruthCWE:    "CWE-79",
		},
		{
			Name: "traversal", Tool: "semgrep", RuleID: "path-join-user-input",
			Title:       "User-controlled segment joined to a filesystem path",
			Description: "A request parameter is joined onto a base directory and opened. Sequences that walk to a parent directory are not rejected, so files outside the intended root can be read.",
			TruthCWE:    "CWE-22",
		},
		{
			Name: "hardcoded-creds", Tool: "gitleaks", RuleID: "generic-api-key",
			Title:       "Credential literal committed to source",
			Description: "A long-lived access token is present as a string literal in a tracked source file and is used to authenticate to a production service.",
			TruthCWE:    "CWE-798",
		},
		{
			Name: "cleartext-transport", Tool: "nuclei", RuleID: "http-endpoint-no-tls",
			Title:       "Credentials submitted over an unencrypted channel",
			Description: "The login form posts to an http:// endpoint. The submitted username and password traverse the network without transport encryption.",
			TruthCWE:    "CWE-319",
		},
		{
			Name: "weak-hash", Tool: "semgrep", RuleID: "use-of-md5",
			Title:       "Obsolete digest used for password storage",
			Description: "Stored account secrets are digested with MD5 and no per-record salt or work factor. Collisions and precomputed tables are practical against this construction.",
			TruthCWE:    "CWE-327",
		},
		{
			Name: "ssrf", Tool: "semgrep", RuleID: "outbound-request-user-host",
			Title:       "Server issues request to a caller-supplied destination",
			Description: "The service performs an outbound HTTP request to a URL taken from the request body. The destination is not restricted, so internal-only addresses are reachable through the server.",
			TruthCWE:    "CWE-918",
		},
		{
			Name: "xxe", Tool: "semgrep", RuleID: "xml-external-entity-enabled",
			Title:       "XML parser resolves external declarations",
			Description: "The document parser is constructed with external entity resolution left enabled while parsing uploaded documents, so a document can cause the server to fetch and inline other resources.",
			TruthCWE:    "CWE-611",
		},
		{
			Name: "missing-authn", Tool: "nuclei", RuleID: "admin-endpoint-unauthenticated",
			Title:       "Administrative endpoint served without a credential check",
			Description: "A management route returns 200 with full data to a request that carries no session and no token. No credential is demanded before the action is performed.",
			TruthCWE:    "CWE-306",
		},
		{
			Name: "verbose-error", Tool: "nuclei", RuleID: "stacktrace-in-response",
			Title:       "Internal diagnostic detail returned to the client",
			Description: "An unhandled failure returns a response containing the framework version, absolute file paths and a full call stack from the server process.",
			TruthCWE:    "CWE-209",
		},
		{
			Name: "cookie-not-httponly", Tool: "nuclei", RuleID: "session-cookie-flags",
			Title:       "Session cookie readable from scripts",
			Description: "The cookie carrying the authenticated session is set without the flag that withholds it from client-side script access.",
			TruthCWE:    "CWE-1004",
		},
		{
			Name: "csrf", Tool: "nuclei", RuleID: "state-change-no-token",
			Title:       "State-changing POST accepted without an anti-forgery token",
			Description: "An endpoint that changes the account's email address accepts a POST carrying only the session cookie. No unpredictable per-request value is required, so a third-party page can cause the action.",
			TruthCWE:    "CWE-352",
		},
		{
			Name: "cert-not-verified", Tool: "semgrep", RuleID: "tls-verify-disabled",
			Title:       "Peer certificate validation disabled",
			Description: "The HTTP client is constructed with the option that skips verification of the presented server certificate chain and hostname.",
			TruthCWE:    "CWE-295",
		},
		{
			Name: "secret-in-log", Tool: "semgrep", RuleID: "log-sensitive-field",
			Title:       "Authentication material written to the application log",
			Description: "The request handler writes the full authorization header to the standard application log at info level on every call.",
			TruthCWE:    "CWE-532",
		},
		// ---- deliberately OUTSIDE the crosswalk: the correct answer is to decline ----
		{
			Name: "business-logic-refund", Tool: "manual", RuleID: "biz.refund-window",
			Title:       "Refund permitted after the eligibility window",
			Description: "The refund workflow allows a refund to be issued 45 days after purchase although policy states 30. This is a policy discrepancy in the workflow, not a technical weakness in the implementation.",
			TruthCWE:    "",
		},
		{
			Name: "flaky-healthcheck", Tool: "manual", RuleID: "ops.healthcheck-flap",
			Title:       "Health probe intermittently reports unhealthy under load",
			Description: "Under sustained traffic the readiness probe times out and the instance is recycled, causing dropped connections. Caused by an undersized probe timeout, with no attacker involvement.",
			TruthCWE:    "",
		},
		{
			Name: "license-conflict", Tool: "syft", RuleID: "license.copyleft-in-proprietary",
			Title:       "Copyleft-licensed dependency in a proprietary distribution",
			Description: "A bundled library is distributed under a reciprocal licence whose terms conflict with the product's proprietary distribution model. This is a licensing-obligation conflict; the library itself functions correctly and has no known defect.",
			TruthCWE:    "",
		},
		{
			Name: "complexity", Tool: "manual", RuleID: "quality.cyclomatic-threshold",
			Title:       "Function exceeds the configured complexity threshold",
			Description: "A request handler has a cyclomatic complexity of 47 against a configured ceiling of 15, making it hard to review and maintain. No incorrect behaviour is demonstrated.",
			TruthCWE:    "",
		},
		{
			Name: "idle-resource-cost", Tool: "prowler", RuleID: "cost.instance-underutilised",
			Title:       "Compute instance consistently under-utilised",
			Description: "An instance has averaged under 3% CPU for 30 days while billed at full rate. Flagged for right-sizing to reduce spend; the instance is correctly configured and patched.",
			TruthCWE:    "",
		},
		{
			Name: "coverage-gap", Tool: "manual", RuleID: "quality.coverage-below-gate",
			Title:       "Module falls below the unit-test coverage gate",
			Description: "Statement coverage for the billing package is 41% against a required 70%. The gate fails the build. No defect is asserted in the uncovered paths.",
			TruthCWE:    "",
		},
	}
	sort.Slice(cs, func(i, j int) bool { return cs[i].Name < cs[j].Name })
	return cs
}
