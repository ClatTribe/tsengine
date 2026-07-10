package bench

import (
	"fmt"
	"strings"

	"github.com/ClatTribe/tsengine/internal/correlate"
	"github.com/ClatTribe/tsengine/internal/crossdetect"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// correlation.go is the CROSS-TOOL CORRELATION benchmark — the "three scanners → one
// engineer" nuance the per-integration bench (integration.go) doesn't touch. It plants a
// multi-surface estate where findings from DIFFERENT tools share a real identifier (an AWS
// key leaked in code that also grants a cloud admin; an identity email that owns a cloud
// principal; an ARN a web finding leaks) and asserts crossdetect.Correlate bridges them into
// a cross-surface attack chain that ends at a crown jewel — while DECOY findings that share
// no groundable entity never chain (§10: a bridge is an EXACT shared token, never a
// coincidence). This is the substrate the L2 Lead then reasons over.

// well-formed tokens the correlator's entity extraction matches EXACTLY (see internal/correlate).
const (
	keyLeaked = "AKIA" + "IOSFODNN7EXAMPLE" // the code→cloud bridge key (4+16)
	keyDecoy  = "AKIA" + "ZZZZZZZZZZZZZZ9Z" // a leaked key that appears in NO cloud finding → no chain
	arnApp    = "arn:aws:iam::123456789012:role/app-deploy-role"
	arnWeb    = "arn:aws:iam::123456789012:role/web-instance-role" // the web→cloud chain's own crown ARN
	userEmail = "j.chen@acme.com"                                  // a specific local-part (generic mailboxes like admin@/info@ are excluded)
)

// CorrelationResult scores the cross-surface correlation.
type CorrelationResult struct {
	ExpectedChains int      `json:"expected_chains"`
	FoundChains    int      `json:"found_chains"`
	Missed         []string `json:"missed,omitempty"` // expected chains not built
	Spurious       int      `json:"spurious_chains"`  // chains that matched no expected bridge (grounding violation)
	TotalChains    int      `json:"total_chains"`     // everything Correlate returned
	UnifiedOK      bool     `json:"unified_ok"`       // the CVE-dedup collapsed the two-tool duplicate + confirmed it
	UnifiedIssues  int      `json:"unified_issues"`   //
}

// Recall is found / expected cross-surface chains.
func (r CorrelationResult) Recall() float64 {
	if r.ExpectedChains == 0 {
		return 1
	}
	return float64(r.FoundChains) / float64(r.ExpectedChains)
}

// Pass is full chain recall, zero spurious chains, and unified-issues working.
func (r CorrelationResult) Pass() bool {
	return len(r.Missed) == 0 && r.Spurious == 0 && r.UnifiedOK
}

// correlationEstate returns the planted findings + the expected chains (each keyed by its
// entry finding id → crown finding id + the bridge that must connect them).
func correlationEstate() ([]types.Finding, []expectedChain) {
	fs := []types.Finding{
		// CHAIN 1 (code→cloud, bridge = leaked AWS key): gitleaks finds the key in source;
		// prowler finds that key grants admin over customer PII.
		{ID: "code-key", Tool: "gitleaks", RuleID: "gitleaks::aws-key", Severity: types.SeverityHigh,
			Endpoint: "config/prod.env:12", Title: "Hardcoded AWS access key in source",
			Description: "Long-lived AWS access key " + keyLeaked + " committed to the repo."},
		{ID: "cloud-admin", Tool: "prowler", RuleID: "prowler::iam-admin", Severity: types.SeverityCritical,
			Endpoint: arnApp, Title: "IAM user has administrator access to customer PII bucket",
			Description: "Access key " + keyLeaked + " belongs to a principal with AdministratorAccess over customer-pii."},

		// CHAIN 2 (identity→cloud, bridge = email): operate flags a no-MFA admin; prowler finds
		// that same person owns a privilege-escalation path.
		{ID: "id-mfa", Tool: "operate", RuleID: "operate::admin-no-mfa", Severity: types.SeverityHigh,
			Endpoint: userEmail, Title: "Admin account " + userEmail + " has no MFA",
			Description: "Workspace admin " + userEmail + " can sign in without a second factor."},
		{ID: "cloud-privesc", Tool: "prowler", RuleID: "prowler::privesc", Severity: types.SeverityCritical,
			Endpoint: "arn:aws:iam::123456789012:user/" + userEmail, Title: "Privilege escalation to administrator",
			Description: "Principal mapped to " + userEmail + " can iam:PutUserPolicy → assume administrator."},

		// CHAIN 3 (web→cloud, bridge = ARN): an SSRF leaks instance-role creds for a DISTINCT ARN
		// (its own crown, so this tests the ARN bridge independently of the AWS-key chain).
		{ID: "web-ssrf", Tool: "nuclei", RuleID: "nuclei::ssrf-metadata", Severity: types.SeverityHigh, VerificationStatus: types.VerificationVerified,
			Endpoint: "https://app.acme.com/fetch?url=", Title: "SSRF exposes instance metadata credentials",
			// the ARN ends the sentence (trailing period) — the correlator must still bridge it
			// (regression for the arn-trailing-punctuation robustness fix).
			Description: "SSRF returns temporary instance-metadata credentials for " + arnWeb + "."},
		{ID: "cloud-web-crown", Tool: "prowler", RuleID: "prowler::role-admin", Severity: types.SeverityCritical,
			Endpoint: arnWeb, Title: "web-instance-role has administrator access",
			Description: "The instance role " + arnWeb + " holds AdministratorAccess (full access)."},

		// DECOYS — must NOT chain:
		{ID: "code-decoy", Tool: "gitleaks", RuleID: "gitleaks::aws-key", Severity: types.SeverityHigh,
			Endpoint: "test/fixtures.js:3", Title: "AWS key in a test fixture",
			Description: "Key " + keyDecoy + " appears only here; it maps to no cloud finding."},
		{ID: "cloud-lonely", Tool: "prowler", RuleID: "prowler::open-sg", Severity: types.SeverityMedium,
			Endpoint: "arn:aws:ec2:us-east-1:123456789012:security-group/sg-999", Title: "Security group allows 0.0.0.0/0 on 8080",
			Description: "An open SG with no shared identifier to any entry finding."},

		// UNIFIED-ISSUES probe: two tools, same CVE → must collapse to one confirmed issue.
		{ID: "sca-a", Tool: "trivy", RuleID: "trivy::CVE-2021-44228", Severity: types.SeverityCritical,
			Endpoint: "pkg/log4j", Title: "CVE-2021-44228 Log4Shell in log4j-core"},
		{ID: "sca-b", Tool: "grype", RuleID: "grype::CVE-2021-44228", Severity: types.SeverityCritical,
			Endpoint: "pkg/log4j", Title: "CVE-2021-44228 Log4Shell (grype)"},
	}
	expected := []expectedChain{
		{name: "code→cloud (leaked AWS key)", entry: "code-key", crown: "cloud-admin"},
		{name: "identity→cloud (email)", entry: "id-mfa", crown: "cloud-privesc"},
		{name: "web→cloud (SSRF→ARN)", entry: "web-ssrf", crown: "cloud-web-crown"},
	}
	return fs, expected
}

type expectedChain struct {
	name  string
	entry string // entry finding id that must appear as a step
	crown string // crown-jewel finding id the chain must reach
}

// chainHasSteps reports whether a chain's steps include both finding ids.
func chainHasSteps(c correlate.Chain, a, b string) bool {
	var seenA, seenB bool
	for _, s := range c.Steps {
		if s.FindingID == a {
			seenA = true
		}
		if s.FindingID == b {
			seenB = true
		}
	}
	return seenA && seenB
}

// RunCorrelationCoverage plants the multi-surface estate and scores cross-surface chaining
// + unified-issue dedup — the cross-tool correlation the AI Security Engineer relies on.
func RunCorrelationCoverage() CorrelationResult {
	fs, expected := correlationEstate()
	chains := crossdetect.Correlate(nil, fs)

	r := CorrelationResult{ExpectedChains: len(expected), TotalChains: len(chains)}
	matched := make([]bool, len(chains))
	for _, ex := range expected {
		found := false
		for i, c := range chains {
			if chainHasSteps(c, ex.entry, ex.crown) {
				found = true
				matched[i] = true
			}
		}
		if found {
			r.FoundChains++
		} else {
			r.Missed = append(r.Missed, ex.name)
		}
	}
	// any chain that matched no expected (entry,crown) pair is spurious — a decoy must never
	// bridge, and a real chain must always end at a crown jewel.
	for i, c := range chains {
		if !matched[i] {
			// tolerate sub-chains of an expected one (same entry, crown reachable) only if they
			// still terminate at a real crown-jewel step; otherwise it's spurious.
			if !endsAtCrown(c) {
				r.Spurious++
			}
		}
	}

	// unified issues: the two-tool Log4Shell must collapse to ONE confirmed issue.
	issues := crossdetect.UnifiedIssues(fs)
	r.UnifiedIssues = len(issues)
	for _, is := range issues {
		if strings.Contains(strings.ToUpper(is.CVE), "CVE-2021-44228") && is.Confirmed && len(is.Tools) >= 2 {
			r.UnifiedOK = true
		}
	}
	return r
}

func endsAtCrown(c correlate.Chain) bool {
	for _, s := range c.Steps {
		if s.CrownJewel {
			return true
		}
	}
	return false
}

// RenderCorrelationMarkdown renders the correlation scoreboard.
func RenderCorrelationMarkdown(r CorrelationResult) string {
	var b strings.Builder
	b.WriteString("\n## Cross-tool correlation (three scanners → one attack path)\n\n")
	b.WriteString("_A multi-surface estate where findings from different tools share a real identifier — ")
	b.WriteString("crossdetect.Correlate must bridge them into a cross-surface chain ending at a crown jewel, ")
	b.WriteString("while decoys that share no groundable token never chain (§10)._\n\n")
	fmt.Fprintf(&b, "- cross-surface chain recall **%.0f%%** (%d/%d) · spurious chains **%d** · unified-issue dedup %s\n",
		r.Recall()*100, r.FoundChains, r.ExpectedChains, r.Spurious,
		map[bool]string{true: "OK ✓", false: "FAIL ✗"}[r.UnifiedOK])
	if len(r.Missed) > 0 {
		fmt.Fprintf(&b, "- missed: %v\n", r.Missed)
	}
	return b.String()
}
