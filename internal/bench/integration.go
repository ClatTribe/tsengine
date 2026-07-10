package bench

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/clouddrift"
	"github.com/ClatTribe/tsengine/internal/cloudengine"
	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/internal/deviceposture"
	"github.com/ClatTribe/tsengine/internal/identitythreat"
	"github.com/ClatTribe/tsengine/internal/osint"
	"github.com/ClatTribe/tsengine/internal/sspm"
	"github.com/ClatTribe/tsengine/internal/tprm"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// integration.go is the credential-free INTEGRATION-COVERAGE benchmark for the AI Security
// Engineer: a synthetic estate spanning every snapshot-driven integration (identity/ITDR,
// SaaS posture/SSPM, OSINT external exposure, vendor risk/TPRM, device posture) with, per
// integration, PLANTED must-detect issues + hardened DECOYS. It runs the SAME detectors the
// product runs (no mocks, no LLM, no external credential) and scores, per integration:
//   - detection recall  (planted issues surfaced / planted)
//   - FP-control        (decoys that stayed clean; a flagged decoy is a false positive)
// Grounding (§10): the estate is built so every at/above-floor finding maps to a planted
// issue; a hardened decoy yields nothing, so any decoy finding is a real FP. Deterministic
// (fixed clock) — the number is an artifact, not a slogan. The LLM AGENT layer (cloud/code
// investigate) is scored separately (it needs a model; driven via the dev proxy).

// IntegrationResult is one integration's coverage score.
type IntegrationResult struct {
	Integration string   `json:"integration"`
	Planted     int      `json:"planted"`
	Detected    int      `json:"detected"`
	Missed      []string `json:"missed,omitempty"`
	Decoys      int      `json:"decoys"`
	FalsePos    []string `json:"false_positives,omitempty"`
	Findings    int      `json:"findings"` // total findings the detector emitted
}

// Recall is planted-issues-surfaced / planted (1.0 when none missed).
func (r IntegrationResult) Recall() float64 {
	if r.Planted == 0 {
		return 1
	}
	return float64(r.Detected) / float64(r.Planted)
}

// Pass is a clean sweep: every planted issue caught AND no decoy flagged.
func (r IntegrationResult) Pass() bool { return len(r.Missed) == 0 && len(r.FalsePos) == 0 }

// signal is a detector output normalized to (searchable text, severity).
type signal struct {
	text string
	sev  types.Severity
}

var sevRank = map[types.Severity]int{
	types.SeverityInfo: 0, types.SeverityLow: 1, types.SeverityMedium: 2, types.SeverityHigh: 3, types.SeverityCritical: 4,
}

func sevAtLeast(s, floor types.Severity) bool { return sevRank[s] >= sevRank[floor] }

// scoreEntities scores by ENTITY containment: a planted entity must appear in some
// at/above-floor finding; a clean (decoy) entity must appear in none.
func scoreEntities(integration string, sigs []signal, planted, clean []string, floor types.Severity) IntegrationResult {
	flagged := func(entity string) bool {
		e := strings.ToLower(entity)
		for _, s := range sigs {
			if sevAtLeast(s.sev, floor) && strings.Contains(strings.ToLower(s.text), e) {
				return true
			}
		}
		return false
	}
	r := IntegrationResult{Integration: integration, Planted: len(planted), Decoys: len(clean), Findings: len(sigs)}
	for _, e := range planted {
		if flagged(e) {
			r.Detected++
		} else {
			r.Missed = append(r.Missed, e)
		}
	}
	for _, e := range clean {
		if flagged(e) {
			r.FalsePos = append(r.FalsePos, e)
		}
	}
	return r
}

func findingSignals(fs []types.Finding) []signal {
	out := make([]signal, 0, len(fs))
	for _, f := range fs {
		out = append(out, signal{text: f.Endpoint + " | " + f.Title + " | " + f.Description, sev: f.Severity})
	}
	return out
}

// benchClock is a fixed reference time so identity/vendor/device staleness is deterministic.
var benchClock = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

// --- per-integration builders (real detectors, planted issues + hardened decoys) ---

func benchIdentity() IntegrationResult {
	events := []identitythreat.Event{
		// PLANTED: impossible travel — alice logs in from two countries within the window.
		{ID: "e1", User: "alice@acme.com", Type: identitythreat.EventLogin, Country: "US", IP: "1.2.3.4", Time: benchClock},
		{ID: "e2", User: "alice@acme.com", Type: identitythreat.EventLogin, Country: "RU", IP: "5.6.7.8", Time: benchClock.Add(20 * time.Minute)},
		// PLANTED: MFA removed then access from a new IP — the account-takeover sequence.
		{ID: "e3", User: "carol@acme.com", Type: identitythreat.EventMFARemoved, IP: "1.1.1.1", Time: benchClock},
		{ID: "e4", User: "carol@acme.com", Type: identitythreat.EventLogin, Country: "US", IP: "9.9.9.9", Time: benchClock.Add(10 * time.Minute)},
		// DECOY: bob — two logins, same country/IP, no MFA change.
		{ID: "e5", User: "bob@acme.com", Type: identitythreat.EventLogin, Country: "US", IP: "1.2.3.4", Time: benchClock},
		{ID: "e6", User: "bob@acme.com", Type: identitythreat.EventLogin, Country: "US", IP: "1.2.3.4", Time: benchClock.Add(3 * time.Hour)},
	}
	threats := identitythreat.Detect(events, identitythreat.Config{})
	sigs := make([]signal, 0, len(threats))
	for _, t := range threats {
		sigs = append(sigs, signal{text: t.User + " | " + t.Title + " | " + strings.Join(t.Evidence, " "), sev: t.Severity})
	}
	return scoreEntities("identity (ITDR)", sigs, []string{"alice@acme.com", "carol@acme.com"}, []string{"bob@acme.com"}, types.SeverityMedium)
}

func benchTPRM() IntegrationResult {
	vendors := []tprm.Vendor{
		// PLANTED: a PII vendor with no SOC2/ISO.
		{Name: "DataGrindAnalytics", Category: "analytics", DataAccess: "sensitive", Certifications: nil, Criticality: "high", LastAssessed: "2026-01-01"},
		// PLANTED: a subprocessor with no DPA.
		{Name: "SubProcCo", Category: "infra", Subprocessor: true, HasDPA: false, DataAccess: "sensitive", Criticality: "high", LastAssessed: "2026-01-01"},
		// DECOY: a well-managed certified vendor with a DPA, recently reviewed.
		{Name: "TrustyVendor", Category: "infra", DataAccess: "sensitive", Certifications: []string{"SOC2", "ISO27001"}, HasDPA: true, Subprocessor: true, Criticality: "high", LastAssessed: "2026-05-01"},
	}
	fs := tprm.Assess(vendors, tprm.Options{Now: func() time.Time { return benchClock }})
	return scoreEntities("vendor risk (TPRM)", findingSignals(fs), []string{"DataGrindAnalytics", "SubProcCo"}, []string{"TrustyVendor"}, types.SeverityMedium)
}

func benchDevices() IntegrationResult {
	devices := []deviceposture.Device{
		// PLANTED: unencrypted + end-of-life + jailbroken laptop.
		{Name: "laptop-breach", Owner: "dave@acme.com", OS: "macos", DiskEncrypted: false, OSEndOfLife: true, Jailbroken: true, ScreenLock: false, LastCheckIn: "2026-05-30"},
		// DECOY: a fully hardened laptop.
		{Name: "laptop-clean", Owner: "erin@acme.com", OS: "macos", OSVersion: "15.5", DiskEncrypted: true, ScreenLock: true, FirewallOn: true, EDR: true, AutoUpdate: true, LastCheckIn: "2026-05-31"},
	}
	fs := deviceposture.Assess(devices, deviceposture.Options{})
	return scoreEntities("device posture (MDM)", findingSignals(fs), []string{"laptop-breach"}, []string{"laptop-clean"}, types.SeverityMedium)
}

func benchOSINT() IntegrationResult {
	snap := osint.Snapshot{
		Org: "acme",
		// a monitored domain with NO exposure on it — the clean decoy (a domain is never itself a finding).
		Domains: []string{"acme.com", "quiet-decoy-zone.net"},
		// PLANTED: infostealer credential (critical), an internet-exposed legacy host, a dangling DNS (takeover).
		StealerLogs:     []osint.StealerLog{{Email: "cfo@acme.com", Domain: "okta.acme.com", Password: true}},
		ExposedHosts:    []osint.ExposedHost{{Host: "legacy.acme.com", Services: []string{"rdp", "mysql"}}},
		DanglingRecords: []osint.DanglingDNS{{Subdomain: "assets.acme.com", Record: "acme.s3.amazonaws.com", Service: "s3", Claimable: true}},
	}
	fs := osint.Assess(snap, osint.Options{})
	return scoreEntities("OSINT external exposure",
		findingSignals(fs),
		[]string{"cfo@acme.com", "legacy.acme.com", "assets.acme.com"},
		[]string{"quiet-decoy-zone.net"}, // a monitored domain with no exposure must raise nothing
		types.SeverityMedium)
}

func benchSaaSGitHub() IntegrationResult {
	// PLANTED: an org with 2FA off + secret scanning off + members can create public repos.
	weak := sspm.GitHubOrg{Login: "acme-weak", TwoFactorRequired: false, DefaultRepoPermission: "write", MembersCanCreatePublicRepos: true, SecretScanningEnabled: false}
	// DECOY: a hardened org.
	strong := sspm.GitHubOrg{Login: "acme-strong", TwoFactorRequired: true, DefaultRepoPermission: "read", MembersCanCreatePublicRepos: false, SecretScanningEnabled: true}
	var sigs []signal
	sigs = append(sigs, findingSignals(sspm.AssessGitHubOrg(weak, sspm.Options{}))...)
	sigs = append(sigs, findingSignals(sspm.AssessGitHubOrg(strong, sspm.Options{}))...)
	return scoreEntities("SaaS posture (SSPM · GitHub)", sigs, []string{"acme-weak"}, []string{"acme-strong"}, types.SeverityMedium)
}

func benchCloudDrift() IntegrationResult {
	prev := cloudgraph.New("acct", "aws")
	prev.AddNode(&cloudgraph.Node{ID: cloudgraph.InternetID, Kind: cloudgraph.KindNetwork})
	prev.AddNode(&cloudgraph.Node{ID: "bucket-pii", Kind: cloudgraph.KindResource, Name: "customer-pii-bucket", Type: "AWS::S3::Bucket", Public: false, Sensitive: cloudgraph.SensHigh})
	prev.AddNode(&cloudgraph.Node{ID: "role-app", Kind: cloudgraph.KindPrincipal, Name: "app-role", Privileged: false})

	cur := cloudgraph.New("acct", "aws")
	cur.AddNode(&cloudgraph.Node{ID: cloudgraph.InternetID, Kind: cloudgraph.KindNetwork})
	// CHANGED: the PII bucket became public (the drift the SOC2 change-control signal must catch).
	cur.AddNode(&cloudgraph.Node{ID: "bucket-pii", Kind: cloudgraph.KindResource, Name: "customer-pii-bucket", Type: "AWS::S3::Bucket", Public: true, Sensitive: cloudgraph.SensHigh})
	// UNCHANGED decoy: app-role identical in both snapshots — must NOT be flagged as drift.
	cur.AddNode(&cloudgraph.Node{ID: "role-app", Kind: cloudgraph.KindPrincipal, Name: "app-role", Privileged: false})

	fs := clouddrift.Diff(prev, cur, clouddrift.Options{Now: func() time.Time { return benchClock }})
	return scoreEntities("cloud drift (change-control)", findingSignals(fs),
		[]string{"customer-pii-bucket"}, []string{"app-role"}, types.SeverityMedium)
}

func benchCloudAttackPath() IntegrationResult {
	// A deterministic synthetic account: 2 real internet→jewel paths + 2 config-bad-but-inert decoys.
	scn := cloudengine.Generate(42, 2, 2, true)
	a := cloudengine.Assess(scn.Snapshot, scn.Prowler, scn.Oracle(), cloudengine.Options{})

	// Recall: each planted RealTarget must appear as a reached resource in some proven path.
	pathText := func() []string {
		var out []string
		for _, p := range a.Paths {
			out = append(out, strings.ToLower(p.Narrative+" "+strings.Join(p.Affected, " ")))
		}
		return out
	}()
	r := IntegrationResult{Integration: "cloud attack-path (AI substrate)", Planted: len(scn.RealTargets), Decoys: len(scn.DecoyFindings), Findings: len(a.Paths)}
	for _, tgt := range scn.RealTargets {
		hit := false
		for _, t := range pathText {
			if strings.Contains(t, strings.ToLower(tgt)) {
				hit = true
				break
			}
		}
		if hit {
			r.Detected++
		} else {
			r.Missed = append(r.Missed, tgt)
		}
	}
	// FP-control: every config-bad-but-inert decoy must be DOWNGRADED (proven not reachable), not left
	// as a live path — the substrate's noise-reduction guarantee (§10).
	downgraded := map[string]bool{}
	for _, d := range a.Downgraded {
		downgraded[d] = true
	}
	for _, d := range scn.DecoyFindings {
		if !downgraded[d] {
			r.FalsePos = append(r.FalsePos, d)
		}
	}
	return r
}

// RunIntegrationCoverage runs every deterministic integration and returns per-integration
// results plus a rolled-up view. Credential-free + LLM-free + deterministic.
func RunIntegrationCoverage() []IntegrationResult {
	results := []IntegrationResult{
		benchIdentity(),
		benchTPRM(),
		benchDevices(),
		benchOSINT(),
		benchSaaSGitHub(),
		benchCloudDrift(),
		benchCloudAttackPath(),
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Integration < results[j].Integration })
	return results
}

// IntegrationCoverageSummary rolls the per-integration results into a portfolio view.
type IntegrationCoverageSummary struct {
	Integrations   int     `json:"integrations"`
	Passed         int     `json:"passed"` // clean-sweep integrations (all planted caught, no decoy flagged)
	TotalPlanted   int     `json:"total_planted"`
	TotalDetected  int     `json:"total_detected"`
	TotalDecoys    int     `json:"total_decoys"`
	FalsePositives int     `json:"false_positives"`
	OverallRecall  float64 `json:"overall_recall"`   // detected / planted across all integrations
	FPControlClean bool    `json:"fp_control_clean"` // zero decoys flagged anywhere
}

// SummarizeIntegrationCoverage aggregates the per-integration results.
func SummarizeIntegrationCoverage(rs []IntegrationResult) IntegrationCoverageSummary {
	s := IntegrationCoverageSummary{Integrations: len(rs)}
	for _, r := range rs {
		if r.Pass() {
			s.Passed++
		}
		s.TotalPlanted += r.Planted
		s.TotalDetected += r.Detected
		s.TotalDecoys += r.Decoys
		s.FalsePositives += len(r.FalsePos)
	}
	if s.TotalPlanted > 0 {
		s.OverallRecall = float64(s.TotalDetected) / float64(s.TotalPlanted)
	} else {
		s.OverallRecall = 1
	}
	s.FPControlClean = s.FalsePositives == 0
	return s
}

// RenderIntegrationCoverageMarkdown renders the credential-free coverage scoreboard.
func RenderIntegrationCoverageMarkdown(rs []IntegrationResult) string {
	sum := SummarizeIntegrationCoverage(rs)
	var b strings.Builder
	b.WriteString("# AI Security Engineer — integration coverage (credential-free)\n\n")
	b.WriteString("_Every integration exercised against a synthetic estate with PLANTED must-detect issues + ")
	b.WriteString("hardened DECOYS, through the SAME snapshot-driven detectors the product runs — no mocks, no LLM, ")
	b.WriteString("no external credential. Detection recall + FP-control per integration (§10: a hardened decoy yields ")
	b.WriteString("nothing, so a flagged decoy is a real false positive)._\n\n")
	fmt.Fprintf(&b, "- **%d/%d integrations clean-sweep** · overall recall **%.0f%%** (%d/%d planted) · FP-control %s (%d decoys flagged)\n\n",
		sum.Passed, sum.Integrations, sum.OverallRecall*100, sum.TotalDetected, sum.TotalPlanted,
		map[bool]string{true: "CLEAN", false: "BREACHED"}[sum.FPControlClean], sum.FalsePositives)
	b.WriteString("| Integration | Recall | Detected | Findings | Decoys flagged |\n|---|---|---|---|---|\n")
	for _, r := range rs {
		fp := "0 ✓"
		if len(r.FalsePos) > 0 {
			fp = fmt.Sprintf("%d ✗ %v", len(r.FalsePos), r.FalsePos)
		}
		fmt.Fprintf(&b, "| %s | %.0f%% | %d/%d | %d | %s |\n", r.Integration, r.Recall()*100, r.Detected, r.Planted, r.Findings, fp)
	}
	return b.String()
}
