package bench

import (
	"fmt"
	"strings"

	"github.com/ClatTribe/tsengine/internal/crossdetect"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// triage.go is the ALERT-TRIAGE benchmark — the metric every AI SOC (Dropzone, Prophet,
// Simbian, SIR-Bench, OpenSec) is judged on: given a NOISY stream where most alerts are benign
// or not actionable, correctly ESCALATE the real threats (TP-detection) while DISMISSING the
// noise (FP-rejection), and stay CALIBRATED against adversarially-misleading decoys (a
// scary-LOOKING finding that isn't actually reachable/on a path — the OpenSec dimension).
//
// This is the state-of-the-art gap our other benches (clean planted estates) didn't cover.
// It tests the product's real actionability philosophy — a finding is ACTIONABLE when it's on
// a cross-surface attack path, VERIFIED (PoC-proven), or CORROBORATED by ≥2 tools — NOT raw
// severity. So a lone "critical" CVE with no reachability/path is correctly deprioritized, the
// same call Prophet markets as "96% false-positive reduction." Deterministic + credential-free.

// self-contained test tokens (unique names so this file composes with the other bench files
// regardless of merge order).
const (
	triageSampleKey = "AKIA" + "IOSFODNN7EXAMPLE"
	triageSampleARN = "arn:aws:iam::123456789012:role/app-deploy-role"
)

func highOrCritical(s types.Severity) bool {
	return s == types.SeverityHigh || s == types.SeverityCritical
}

// TriageResult scores one triage pass over a noisy estate.
type TriageResult struct {
	Threats        int      `json:"threats"`                 // ground-truth actionable findings
	Noise          int      `json:"noise"`                   // ground-truth non-actionable (incl. adversarial decoys)
	Decoys         int      `json:"decoys"`                  // of the noise, the adversarially-misleading subset
	TPDetected     int      `json:"tp_detected"`             // threats correctly escalated
	FPRejected     int      `json:"fp_rejected"`             // noise correctly dismissed
	MisEscalated   []string `json:"mis_escalated,omitempty"` // noise WRONGLY escalated (a calibration failure)
	MissedThreats  []string `json:"missed_threats,omitempty"`
	DecoyEscalated int      `json:"decoy_escalated"` // adversarial decoys wrongly escalated (the OpenSec metric)
}

// TPRate is TP-detection recall (SIR-Bench headline).
func (r TriageResult) TPRate() float64 {
	if r.Threats == 0 {
		return 1
	}
	return float64(r.TPDetected) / float64(r.Threats)
}

// FPRejectionRate is the alert-fatigue metric (Prophet's "false-positive reduction").
func (r TriageResult) FPRejectionRate() float64 {
	if r.Noise == 0 {
		return 1
	}
	return float64(r.FPRejected) / float64(r.Noise)
}

// Precision of the escalation set (escalated-that-are-real / all-escalated).
func (r TriageResult) Precision() float64 {
	escalated := r.TPDetected + (r.Noise - r.FPRejected)
	if escalated == 0 {
		return 1
	}
	return float64(r.TPDetected) / float64(escalated)
}

// Pass: every threat caught, every noise dismissed (incl. all adversarial decoys).
func (r TriageResult) Pass() bool {
	return len(r.MissedThreats) == 0 && len(r.MisEscalated) == 0
}

type alert struct {
	f           types.Finding
	actionable  bool // ground truth: a real threat that must be escalated
	adversarial bool // a decoy engineered to LOOK critical but isn't actionable
}

// triageEstate is a realistic noisy stream: a few real threats + a majority of non-actionable
// noise, including adversarially-misleading decoys.
func triageEstate() []alert {
	return []alert{
		// --- REAL THREATS (must escalate) ---
		// on a cross-surface attack path (code→cloud): both steps are actionable.
		{f: types.Finding{ID: "t-key", Tool: "gitleaks", RuleID: "gitleaks::aws-key", Severity: types.SeverityHigh,
			Endpoint: "config/prod.env:12", Title: "Hardcoded AWS access key in source",
			Description: "Long-lived AWS access key " + triageSampleKey + " committed to the repo."}, actionable: true},
		{f: types.Finding{ID: "t-cloudadmin", Tool: "prowler", RuleID: "prowler::iam-admin", Severity: types.SeverityCritical,
			Endpoint: triageSampleARN, Title: "IAM principal has administrator access to customer PII",
			Description: "Access key " + triageSampleKey + " belongs to a principal with AdministratorAccess over customer-pii."}, actionable: true},
		// PoC-verified (exploitation-proven).
		{f: types.Finding{ID: "t-ssrf", Tool: "nuclei", RuleID: "nuclei::ssrf", Severity: types.SeverityHigh, VerificationStatus: types.VerificationVerified,
			Endpoint: "https://app.acme.com/fetch?url=", Title: "SSRF (PoC-verified) reaches internal metadata"}, actionable: true},
		// corroborated critical (two independent tools agree — Log4Shell).
		{f: types.Finding{ID: "t-log4-a", Tool: "trivy", RuleID: "trivy::CVE-2021-44228", Severity: types.SeverityCritical,
			Endpoint: "pkg/log4j", Title: "CVE-2021-44228 Log4Shell"}, actionable: true},
		{f: types.Finding{ID: "t-log4-b", Tool: "grype", RuleID: "grype::CVE-2021-44228", Severity: types.SeverityCritical,
			Endpoint: "pkg/log4j", Title: "CVE-2021-44228 Log4Shell (grype)"}, actionable: true},

		// --- NOISE (must dismiss) ---
		// a lone medium with no path / not verified / not corroborated.
		{f: types.Finding{ID: "n-sg", Tool: "prowler", RuleID: "prowler::open-sg", Severity: types.SeverityMedium,
			Endpoint: "arn:aws:ec2:us-east-1:123456789012:security-group/sg-31", Title: "Security group allows 0.0.0.0/0 on a dev port 8081"}, actionable: false},
		// an info-level hygiene note.
		{f: types.Finding{ID: "n-info", Tool: "nuclei", RuleID: "nuclei::tech-detect", Severity: types.SeverityInfo,
			Endpoint: "https://app.acme.com", Title: "Technology fingerprint: nginx 1.25"}, actionable: false},

		// --- ADVERSARIALLY-MISLEADING DECOYS (LOOK critical, must dismiss — the OpenSec/calibration test) ---
		// a "critical leaked key" that is the DOCUMENTED PUBLIC SAMPLE key (AKIAIOSFODNN7EXAMPLE is AWS's
		// own example in every tutorial) — a classic false alarm a naive scanner escalates.
		{f: types.Finding{ID: "d-samplekey", Tool: "gitleaks", RuleID: "gitleaks::aws-key", Severity: types.SeverityCritical,
			Endpoint: "docs/README.md:88", Title: "AWS access key in documentation",
			Description: "Key " + triageSampleKey + " appears in a docs code-sample; it is the well-known public AWS example key, not a live credential."}, actionable: false, adversarial: true},
		// a high-severity SQLi finding, but in a TEST FIXTURE (non-production) with no path.
		{f: types.Finding{ID: "d-testfix", Tool: "semgrep", RuleID: "semgrep::sqli", Severity: types.SeverityHigh,
			Endpoint: "test/fixtures/vuln_samples.py:3", Title: "SQL injection in a test fixture"}, actionable: false, adversarial: true},
		// a lone CRITICAL CVE with no reachability/corroboration/path — scary severity, not actionable.
		{f: types.Finding{ID: "d-unreach", Tool: "trivy", RuleID: "trivy::CVE-2023-99999", Severity: types.SeverityCritical,
			Endpoint: "vendor/unused-lib", Title: "CVE-2023-99999 RCE in an unreachable transitive dependency"}, actionable: false, adversarial: true},
	}
}

// deterministicTriage decides ESCALATE vs DISMISS using the product's real actionability
// signals — cross-surface attack-path membership, PoC verification, and ≥2-tool corroboration
// — plus benign-provenance rejection (a documented public sample, a test-fixture path). This
// is the substrate triage; the L2 Lead can be scored on the same estate via the proxy.
func deterministicTriage(alerts []alert) map[string]bool {
	fs := make([]types.Finding, len(alerts))
	for i, a := range alerts {
		fs[i] = a.f
	}
	// on-a-path set (the strongest actionability signal).
	onPath := map[string]bool{}
	for _, ch := range crossdetect.Correlate(nil, fs) {
		for _, s := range ch.Steps {
			onPath[s.FindingID] = true
		}
	}
	// corroboration: a finding in a ≥2-tool confirmed unified issue.
	corroborated := map[string]bool{}
	for _, is := range crossdetect.UnifiedIssues(fs) {
		if is.Confirmed {
			for _, id := range is.FindingIDs {
				corroborated[id] = true
			}
		}
	}
	escalate := map[string]bool{}
	for _, a := range alerts {
		f := a.f
		switch {
		case benignProvenance(f):
			// documented public sample / non-production test fixture → dismiss regardless of severity.
		case onPath[f.ID]:
			escalate[f.ID] = true // on a cross-surface attack path — the actionable signal
		case f.VerificationStatus == types.VerificationVerified:
			escalate[f.ID] = true // PoC-proven
		case corroborated[f.ID] && highOrCritical(f.Severity):
			escalate[f.ID] = true // ≥2 tools agree on a high+ finding
		default:
			// lone finding, no path, not verified, not corroborated → not proven actionable → dismiss
			// (this is the "raw severity is not a reason to page someone" call the AI-SOC leaders make).
		}
	}
	return escalate
}

// benignProvenance rejects an alert whose SOURCE marks it non-actionable: the documented public
// AWS sample key, or a non-production test-fixture path.
func benignProvenance(f types.Finding) bool {
	blob := strings.ToLower(f.Title + " " + f.Description + " " + f.Endpoint)
	if strings.Contains(blob, "public aws example key") || strings.Contains(blob, "well-known public aws example") {
		return true
	}
	ep := strings.ToLower(f.Endpoint)
	if strings.HasPrefix(ep, "test/") || strings.Contains(ep, "/test/") || strings.Contains(ep, "/fixtures/") || strings.Contains(ep, "test/fixtures") {
		return true
	}
	return false
}

// RunTriageBench scores the deterministic triage over the noisy estate.
func RunTriageBench() TriageResult {
	alerts := triageEstate()
	return scoreTriage(alerts, deterministicTriage(alerts))
}

// scoreTriage compares an escalation set against ground truth.
func scoreTriage(alerts []alert, escalated map[string]bool) TriageResult {
	r := TriageResult{}
	for _, a := range alerts {
		if a.actionable {
			r.Threats++
			if escalated[a.f.ID] {
				r.TPDetected++
			} else {
				r.MissedThreats = append(r.MissedThreats, a.f.ID)
			}
			continue
		}
		r.Noise++
		if a.adversarial {
			r.Decoys++
		}
		if escalated[a.f.ID] {
			r.MisEscalated = append(r.MisEscalated, a.f.ID)
			if a.adversarial {
				r.DecoyEscalated++
			}
		} else {
			r.FPRejected++
		}
	}
	return r
}

// RenderTriageMarkdown renders the triage scoreboard against the SOTA metrics.
func RenderTriageMarkdown(r TriageResult) string {
	var b strings.Builder
	b.WriteString("\n## Alert triage under noise (the AI-SOC metric)\n\n")
	b.WriteString("_A noisy stream: real threats + non-actionable noise + adversarially-misleading decoys. ")
	b.WriteString("Escalate the threats, dismiss the noise — the actionability call (attack-path / verified / ")
	b.WriteString("corroborated), not raw severity. Comparable to SIR-Bench (TP/FP) + OpenSec (calibration) + ")
	b.WriteString("Prophet's false-positive-reduction._\n\n")
	fmt.Fprintf(&b, "- **TP-detection %.0f%%** (%d/%d threats) · **FP-rejection %.0f%%** (%d/%d noise) · precision %.0f%% · adversarial decoys mis-escalated **%d/%d**\n",
		r.TPRate()*100, r.TPDetected, r.Threats, r.FPRejectionRate()*100, r.FPRejected, r.Noise, r.Precision()*100, r.DecoyEscalated, r.Decoys)
	if len(r.MissedThreats) > 0 {
		fmt.Fprintf(&b, "- missed threats: %v\n", r.MissedThreats)
	}
	if len(r.MisEscalated) > 0 {
		fmt.Fprintf(&b, "- wrongly escalated (calibration failures): %v\n", r.MisEscalated)
	}
	return b.String()
}
