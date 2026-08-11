// Package bench — T1 TRIAGE benchmark.
//
// WHY THIS IS THE MISSING ONE. Deconstructing the security engineer's job into eight tasks, triage is
// the one they spend most of the week on: a pile of scanner output arrives and somebody decides what
// is real and what is noise. We measured localization (T2) and CWE attribution, but never the funnel
// itself — so the task with the largest share of the job had no number at all, and the 40% efficacy
// bar was unmeasurable.
//
// WHAT IT MEASURES. Given a mixed pile, two things that pull against each other:
//
//	recall     did it KEEP the findings that genuinely need work?
//	restraint  did it DROP the noise?
//
// Either alone is trivially gameable — keep everything scores perfect recall, drop everything scores
// perfect restraint — so the headline is Youden's J (recall + restraint − 1), which is only high when
// both are. J=0 is the score of a coin flip and of both degenerate strategies.
//
// WHY THE DECOYS ARE THE HARD PART. They are not random noise: each is a finding a real scanner really
// emits and a real engineer really dismisses — a credential in a test fixture, a documented sample key
// from a vendor README, a vulnerable dependency that is vendored but never built, an injection sink in
// a disabled code path. Distinguishing those from the real thing requires reading context, not
// matching a rule, which is exactly the judgement the persona claims to provide.
//
// This matters given what we measured elsewhere: both an 8B general and an 8B security model
// over-attributed non-vulnerabilities (2/6 and 6/6). A model that cannot say "this one is noise" will
// score high recall and near-zero restraint here, and J will expose it.
package bench

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// TriageCase is one finding with a ground-truth verdict.
type TriageCase struct {
	Name    string
	Finding types.Finding
	// Actionable is the truth: would a competent engineer put work into this?
	Actionable bool
	// Why records the reasoning a human would give, so a failure is readable rather than a bare miss.
	Why string
}

// Triager decides whether a finding deserves work.
type Triager interface {
	Triage(ctx context.Context, f types.Finding) (actionable bool, err error)
	Engine() string
}

// TriageScore is the outcome over a case set.
type TriageScore struct {
	Engine string
	// Kept/Dropped are correct decisions; Missed/FalseAlarm are the two error modes.
	Kept       int // actionable, correctly kept   (true positive)
	Missed     int // actionable, wrongly dropped  (false negative — the dangerous one)
	Dropped    int // noise, correctly dropped     (true negative)
	FalseAlarm int // noise, wrongly kept          (false positive — the trust-destroying one)
	Errors     int
}

// Recall is the share of genuinely actionable findings kept. Missing a real vulnerability is the
// failure that gets someone breached.
func (s TriageScore) Recall() float64 {
	n := s.Kept + s.Missed
	if n == 0 {
		return 0
	}
	return float64(s.Kept) / float64(n)
}

// Restraint is the share of noise correctly dropped. Failing here is what makes a security product
// unusable: an engineer who cannot trust the queue stops reading it, and then recall stops mattering.
func (s TriageScore) Restraint() float64 {
	n := s.Dropped + s.FalseAlarm
	if n == 0 {
		return 1
	}
	return float64(s.Dropped) / float64(n)
}

// Youden is the headline: recall + restraint − 1. Both degenerate strategies (keep everything, drop
// everything) score 0, so it cannot be gamed by picking a side.
func (s TriageScore) Youden() float64 { return s.Recall() + s.Restraint() - 1 }

// ScoreTriage runs a triager over the corpus.
func ScoreTriage(ctx context.Context, t Triager, cases []TriageCase) (TriageScore, []string, error) {
	s := TriageScore{Engine: t.Engine()}
	var misses []string
	for _, c := range cases {
		got, err := t.Triage(ctx, c.Finding)
		if err != nil {
			s.Errors++
			continue
		}
		switch {
		case c.Actionable && got:
			s.Kept++
		case c.Actionable && !got:
			s.Missed++
			misses = append(misses, fmt.Sprintf("MISSED  %-26s %s", c.Name, c.Why))
		case !c.Actionable && !got:
			s.Dropped++
		default:
			s.FalseAlarm++
			misses = append(misses, fmt.Sprintf("NOISE   %-26s %s", c.Name, c.Why))
		}
	}
	sort.Strings(misses)
	return s, misses, nil
}

// RenderTriageScores renders the comparison table.
func RenderTriageScores(scores []TriageScore) string {
	var b strings.Builder
	b.WriteString("# T1 — Triage Benchmark (the task the engineer spends most of the week on)\n")
	b.WriteString("Decide, per finding: does this deserve work? Decoys are findings real scanners emit and real engineers dismiss.\n\n")
	b.WriteString("| Engine | Youden J | recall | restraint | kept | missed | dropped | false alarms |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|\n")
	for _, s := range scores {
		b.WriteString(fmt.Sprintf("| %s | **%.2f** | %.2f | %.2f | %d | %d | %d | %d |\n",
			s.Engine, s.Youden(), s.Recall(), s.Restraint(), s.Kept, s.Missed, s.Dropped, s.FalseAlarm))
	}
	b.WriteString("\n*Youden J* = recall + restraint − 1. Keeping everything and dropping everything both score 0, ")
	b.WriteString("so the number is only high when the engine genuinely separates signal from noise.\n")
	return b.String()
}

// TriageCases is the corpus: findings that need work, and findings that look identical to a matcher
// but that any competent engineer dismisses.
//
// Deliberately first-party and synthetic (§14 anti-overfit): no SUT-specific identifiers and no
// snippets copied from a public benchmark a model may have memorised.
func TriageCases() []TriageCase {
	mk := func(tool, rule, title, endpoint, desc string, sev types.Severity) types.Finding {
		return types.Finding{
			ID: rule + "|" + endpoint, Tool: tool, RuleID: rule, Title: title,
			Endpoint: endpoint, Description: desc, Severity: sev,
			VerificationStatus: types.VerificationPatternMatch,
		}
	}
	return []TriageCase{
		// ---------- genuinely actionable ----------
		{
			Name: "sqli-in-handler", Actionable: true,
			Why:     "request data concatenated into a live query on a reachable endpoint",
			Finding: mk("semgrep", "string-formatted-query", "Query built from request data", "internal/api/search.go:42", "A value from the HTTP request is concatenated into the SQL statement executed against the production database.", types.SeverityCritical),
		},
		{
			Name: "live-aws-key", Actionable: true,
			Why:     "a real long-lived credential in a tracked file used against production",
			Finding: mk("gitleaks", "aws-access-key", "AWS access key committed", "config/deploy.go:12", "A long-lived AWS access key id and secret appear as string literals and are used to authenticate the deployment job.", types.SeverityCritical),
		},
		{
			Name: "public-bucket-with-pii", Actionable: true,
			Why:     "world-readable storage holding customer records",
			Finding: mk("prowler", "s3-public-read", "Bucket readable by anyone", "s3://acme-customer-exports", "The bucket policy grants read to all principals. It holds nightly customer exports.", types.SeverityHigh),
		},
		{
			Name: "unauth-admin-route", Actionable: true,
			Why:     "an admin route answering without any credential",
			Finding: mk("nuclei", "admin-no-auth", "Admin endpoint without authentication", "https://app.example.com/admin/users", "The route returns 200 with the full user list to a request carrying no session and no token.", types.SeverityCritical),
		},
		{
			Name: "outdated-dep-reachable", Actionable: true,
			Why:     "a known-vulnerable version of a library the app actually calls",
			Finding: mk("osv-scanner", "GHSA-xxxx-serialize", "Vulnerable serialization library", "go.mod", "The pinned version has a published deserialization advisory. The affected function is called from internal/auth/session.go.", types.SeverityHigh),
		},
		{
			Name: "weak-password-hash", Actionable: true,
			Why:     "production account secrets stored with an obsolete digest",
			Finding: mk("semgrep", "weak-hash-md5", "Account secrets hashed with MD5", "internal/auth/store.go:88", "Stored account secrets are digested with MD5 and no salt or work factor.", types.SeverityHigh),
		},
		// ---------- noise a competent engineer drops ----------
		{
			Name: "key-in-test-fixture", Actionable: false,
			Why:     "a fake credential in a test fixture — it authenticates to nothing",
			Finding: mk("gitleaks", "aws-access-key", "AWS access key committed", "internal/auth/testdata/fixture_creds.json:3", "An AWS-format key id and secret appear as literals in a JSON file under a testdata directory.", types.SeverityCritical),
		},
		{
			Name: "vendor-sample-key", Actionable: false,
			Why:     "the vendor's own documented placeholder, published in their README",
			Finding: mk("gitleaks", "generic-api-key", "API key in documentation", "docs/integrations/README.md:57", "An API-key-shaped literal appears in a fenced code block in a markdown integration guide.", types.SeverityHigh),
		},
		{
			Name: "vendored-dep-never-built", Actionable: false,
			Why:     "vulnerable code that is present but excluded from every build",
			Finding: mk("osv-scanner", "GHSA-yyyy-legacy", "Vulnerable legacy library", "third_party/legacy-sdk/go.mod", "The manifest under third_party/legacy-sdk pins a version with a published advisory. The directory carries a //go:build ignore constraint.", types.SeverityHigh),
		},
		{
			Name: "injection-in-dead-path", Actionable: false,
			Why:     "the sink sits behind a feature flag removed two releases ago",
			Finding: mk("semgrep", "command-exec-user-input", "Command built from a variable", "internal/legacy/import.go:210", "A variable is interpolated into a command string. The enclosing function is guarded by a feature flag not present in any config file, and has no callers in the tree.", types.SeverityHigh),
		},
		{
			Name: "self-signed-cert-on-localhost", Actionable: false,
			Why:     "a development-only listener that is not exposed",
			Finding: mk("nuclei", "self-signed-cert", "Self-signed certificate", "https://127.0.0.1:8443", "The TLS listener on 127.0.0.1:8443 presents a certificate signed by its own key.", types.SeverityMedium),
		},
		{
			Name: "version-banner-disclosure", Actionable: false,
			Why:     "an informational banner with no exploitable consequence on its own",
			Finding: mk("nuclei", "server-version-banner", "Server version in response header", "https://app.example.com/", "The response includes a Server header naming the web server and its minor version.", types.SeverityLow),
		},
	}
}
