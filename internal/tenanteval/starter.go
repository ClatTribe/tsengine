package tenanteval

import "github.com/ClatTribe/tsengine/pkg/types"

// THE COLD START.
//
// A tenant's suite is built from decisions their people have made, so on day one it is empty — and
// a customer choosing which model to trust has nothing to go on until they have already trusted one
// for a while. That is the wrong way round.
//
// The starter check fills that gap WITHOUT pretending to be their evals. It is a small, fixed set of
// findings whose correct handling does not depend on this customer's estate, their risk appetite, or
// anything they have told us — cases where disagreeing is indefensible for anybody. It is a
// calibration check on the grader, not a measurement of their security posture, and everything here
// is built so it can never be mistaken for one:
//
//   - it is scored and recorded SEPARATELY (ArmStarter), never folded into "agreement with your
//     experts", because these are OUR cases and that number's whole worth is that they are not;
//   - it is BALANCED — two keep, two suppress — so a model that answers the same word every time
//     scores 50%, not 100%. An unbalanced check is one a constant answerer passes, which measures
//     nothing (the FP-control discipline the benchmarks already apply);
//   - every case cites the PUBLIC authority that settles it, so a customer can check the answer key
//     rather than take our word for it. A case we cannot cite has no business being in here.
//
// It says nothing about the tenant's estate, and the API and UI both say so.

// SourceStarter marks a case as ours rather than the customer's.
const SourceStarter Source = "starter"

// ArmStarter is the starter check's own recorded history, kept apart from both the filter's and the
// model's scores on the tenant's real cases.
const ArmStarter = "starter"

// StarterCases returns the fixed calibration set.
//
// The two SUPPRESS cases are the load-bearing ones. Both are strings their own vendors publish as
// public examples, and a scanner that reports them is producing exactly the alert that erodes trust
// in scanners — this repository has itself paged an on-call over the AWS documentation key. A model
// that cannot tell a published example from a live credential will bury a security team.
func StarterCases() []Case {
	mk := func(id, rule, endpoint, title, desc string, sev types.Severity, expect Verdict, why string) Case {
		return Case{
			FindingID: id, RuleID: rule, Source: SourceStarter, Expect: expect, Reason: why,
			finding: types.Finding{
				ID: id, RuleID: rule, Tool: "starter-check", Severity: sev,
				Endpoint: endpoint, Title: title, Description: desc,
			},
		}
	}
	return []Case{
		mk("starter-kev-rce", "nuclei::CVE-2021-44228", "https://app.example.com/api/login",
			"Log4Shell remote code execution (CVE-2021-44228)",
			"A crafted JNDI lookup in a logged header executes attacker-controlled code on the server. "+
				"The service echoes the payload and resolves the attacker's LDAP reference.",
			types.SeverityCritical, Keep,
			"CISA lists CVE-2021-44228 in the Known Exploited Vulnerabilities catalogue — it is exploited "+
				"in the wild, so suppressing it is indefensible for any organisation."),

		mk("starter-live-secret", "gitleaks::stripe-secret-key", "src/config/payments.go:14",
			"Live Stripe secret key committed to the repository",
			"A key with the sk_live_ prefix appears in committed source. Stripe secret keys authorise "+
				"charges and refunds against the live account.",
			types.SeverityCritical, Keep,
			"Stripe's own documentation states secret keys must never be shared or committed; a live one "+
				"in source is a working credential regardless of who owns the repository."),

		mk("starter-aws-doc-example", "gitleaks::aws-access-key", "docs/getting-started.md:31",
			"AWS access key in documentation",
			"The string AKIAIOSFODNN7EXAMPLE appears in a setup guide, in a fenced example block "+
				"showing users where to paste their own key.",
			types.SeverityHigh, Suppress,
			"AKIAIOSFODNN7EXAMPLE is the example key AWS itself publishes throughout its public "+
				"documentation. It authenticates nothing, and reporting it is the false positive that "+
				"teaches a team to ignore secret alerts."),

		mk("starter-publishable-key", "gitleaks::stripe-key", "web/src/checkout.js:8",
			"Stripe key in front-end JavaScript",
			"A key with the pk_test_ prefix is embedded in browser-delivered JavaScript that "+
				"initialises the payment form.",
			types.SeverityMedium, Suppress,
			"Stripe publishable keys are designed to be shipped in client-side code and carry no ability "+
				"to move money; the test-mode prefix cannot touch live data at all."),
	}
}

// StarterBalance reports the check's shape, so a caller can state plainly that answering the same
// word every time does not pass it.
func StarterBalance() (keep, suppress int) {
	for _, c := range StarterCases() {
		if c.Expect == Keep {
			keep++
			continue
		}
		suppress++
	}
	return keep, suppress
}
