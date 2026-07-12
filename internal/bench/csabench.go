package bench

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/clouddrift"
	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/internal/identitythreat"
)

// csabench.go runs our engine against the two scenarios of the ONLY independent, public AI-SOC
// benchmark with published competitor numbers: the Cloud Security Alliance "Beyond the Hype: A
// Benchmark Study of AI Agents in the SOC" (CSA, Oct 2025; 148 real SOC analysts, CSA-run). The
// study measured analysts investigating two escalated Tier-2 alerts and reported per-scenario
// triage accuracy:
//
//	Scenario                     with-AI (Dropzone)   manual (GuardDuty/Sentinel)
//	1. AWS S3 / GuardDuty              97%                    86%
//	2. Microsoft Entra failed-login   85%                    81%
//
// WHAT THIS HARNESS IS (and is NOT) — read before quoting the number:
//
//   - It runs the SAME TWO SCENARIO TYPES through our engine and scores triage accuracy on the
//     same axis (reach the correct conclusion: escalate a real threat, DON'T escalate a decoy).
//   - Both scenarios run on our DETERMINISTIC detectors — identitythreat.Detect (Entra spray) and
//     clouddrift.Diff (S3 exposure) — so the number is AUTONOMOUS, reproducible, and CI-runnable
//     with NO LLM key and NO proxy. That is the point: it closes the "every number is a manual
//     proxy run" credibility gap.
//   - HONESTY (§10), stated loudly in the render:
//     (a) REPRODUCTION, not their data. The CSA per-scenario telemetry is not public; these are
//     faithful reconstructions of the two scenario TYPES from the published description, labeled
//     by real-world correctness (NOT reverse-engineered to pass — see the restraint decoys).
//     (b) DIFFERENT OPERATING MODE. CSA measured HUMANS (with vs without AI-assist); ours is the
//     engine triaging AUTONOMOUSLY. Same task + ground-truth axis, different measurement.
//     (c) COVERAGE. We score accuracy + consistency (deterministic → 0% run-to-run variance); the
//     CSA speed/detail measures are human-workflow metrics that don't map to an autonomous engine.
//     (d) NO OVERFIT. Detectors run AS-IS; the set includes restraint decoys that a naive
//     always-escalate agent would get WRONG, so accuracy is not gameable by crying wolf.
//
// IMPORTANT — this is a CALIBRATION check, NOT a competitor scoreboard. The episodes are
// self-authored, so a 100% pass here is circular (we know what the detectors do). It proves the
// detectors are wired + correctly reject decoys; it proves NOTHING about out-performing Dropzone
// et al. A real comparison needs an EXTERNAL labeled dataset / the CSA telemetry / competitor
// trials — none of which we have. The render says this loudly and does NOT put our rate in the
// same column as the competitor number.

// CSAScenario is one of the two CSA scenarios, as a set of labeled triage episodes.
type CSAScenario struct {
	Key      string
	Name     string
	AIBench  int // CSA published with-AI (Dropzone) accuracy %
	Manual   int // CSA published manual accuracy %
	Episodes []csaEpisode
}

// csaEpisode is one alert to triage. escalate is the ground-truth correct verdict (true = a real
// threat that must be escalated; false = a benign/decoy that must NOT be escalated).
type csaEpisode struct {
	id       string
	desc     string
	escalate bool                  // ground-truth correct verdict
	verdict  func() (bool, string) // runs the REAL detector, returns (engine escalated?, evidence)
}

// CSAResult scores one scenario.
type CSAResult struct {
	Key     string      `json:"key"`
	Name    string      `json:"name"`
	Total   int         `json:"total"`
	Correct int         `json:"correct"`
	AIBench int         `json:"ai_bench_pct"`
	Manual  int         `json:"manual_pct"`
	Wrong   []string    `json:"wrong,omitempty"`
	Detail  []csaVerdit `json:"detail"`
}

type csaVerdit struct {
	ID       string `json:"id"`
	Desc     string `json:"desc"`
	Want     bool   `json:"want_escalate"`
	Got      bool   `json:"got_escalate"`
	Correct  bool   `json:"correct"`
	Evidence string `json:"evidence"`
}

// Accuracy is correct/total as a percentage.
func (r CSAResult) Accuracy() float64 {
	if r.Total == 0 {
		return 0
	}
	return 100 * float64(r.Correct) / float64(r.Total)
}

// t0 is a fixed base time (no wall-clock — deterministic, replayable; Date.now is unavailable).
var csaT0 = time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)

// ---- Scenario 1: AWS S3 / GuardDuty — a bucket-exposure triage ---------------------------------
// The CSA task: an escalated GuardDuty finding about S3 bucket access — real exposure or benign?
// Correct triage separates a bucket that BECAME internet-exposed (real change-control exposure)
// from an intentionally-public asset (a static-site bucket that was always public). We run the
// product's real drift detector (clouddrift.Diff) — resource-became-public fires ONLY on a
// private→public transition, so an always-public benign bucket correctly does NOT escalate.

func s3DriftEscalates(prevPublic, curPublic bool, name string, sens cloudgraph.Sensitivity) func() (bool, string) {
	return func() (bool, string) {
		mk := func(public bool) *cloudgraph.Snapshot {
			s := cloudgraph.New("111122223333", "aws")
			s.AddNode(&cloudgraph.Node{ID: "arn:aws:s3:::" + name, Kind: cloudgraph.KindData,
				Type: "AWS::S3::Bucket", Name: name, Public: public, Sensitive: sens})
			return s
		}
		// every episode is drift-vs-last-baseline (the realistic GuardDuty triage), so a prior
		// snapshot always exists; became-public fires only on a real private→public transition.
		prev := mk(prevPublic)
		fs := clouddrift.Diff(prev, mk(curPublic), clouddrift.Options{Now: func() time.Time { return csaT0 }})
		for _, f := range fs {
			if strings.Contains(f.RuleID, "became-public") || strings.Contains(f.RuleID, "new-public") {
				return true, f.RuleID + " on " + name
			}
		}
		return false, "no exposure drift on " + name
	}
}

func csaS3Scenario() CSAScenario {
	return CSAScenario{
		Key: "s3_guardduty", Name: "AWS S3 / GuardDuty bucket-exposure triage", AIBench: 97, Manual: 86,
		Episodes: []csaEpisode{
			{id: "s3-exfil", desc: "customer-data bucket went private→public (real exposure)", escalate: true,
				verdict: s3DriftEscalates(false, true, "acme-customer-exports", cloudgraph.SensHigh)},
			{id: "s3-logs-public", desc: "an app-logs bucket became public (real exposure)", escalate: true,
				verdict: s3DriftEscalates(false, true, "acme-app-logs", cloudgraph.SensLow)},
			{id: "s3-static-site", desc: "static-website bucket, intentionally public all along (decoy)", escalate: false,
				verdict: s3DriftEscalates(true, true, "acme-marketing-site", cloudgraph.SensNone)},
			{id: "s3-stayed-private", desc: "bucket re-tagged but stayed private (decoy)", escalate: false,
				verdict: s3DriftEscalates(false, false, "acme-internal-backups", cloudgraph.SensHigh)},
		},
	}
}

// ---- Scenario 2: Microsoft Entra failed-login — a spray-vs-fat-finger triage -------------------
// The CSA task: failed Entra logins in Sentinel — a password-spray attack or benign user error?
// We run the product's real identitythreat.Detect: a spray beyond threshold-in-window escalates;
// a couple of failures then a success does NOT.

func entraDetects(events []identitythreat.Event) func() (bool, string) {
	return func() (bool, string) {
		th := identitythreat.Detect(events, identitythreat.Config{})
		if len(th) == 0 {
			return false, "no identity threat detected"
		}
		names := make([]string, 0, len(th))
		for _, t := range th {
			names = append(names, t.Rule)
		}
		return true, strings.Join(names, ",")
	}
}

// spray builds N failed logins for one user inside a 10-minute window (trips password_spray).
func csaSpray(user string, n int) []identitythreat.Event {
	var evs []identitythreat.Event
	for i := 0; i < n; i++ {
		evs = append(evs, identitythreat.Event{ID: fmt.Sprintf("%s-f%d", user, i), User: user,
			Type: identitythreat.EventLoginFail, Time: csaT0.Add(time.Duration(i) * time.Minute), IP: "203.0.113.7"})
	}
	return evs
}

// distributedSpray builds one attacker IP failing across many distinct users in-window.
func csaDistributed(nUsers int) []identitythreat.Event {
	var evs []identitythreat.Event
	for i := 0; i < nUsers; i++ {
		u := fmt.Sprintf("user%d@acme.com", i)
		evs = append(evs, identitythreat.Event{ID: fmt.Sprintf("d-%d", i), User: u,
			Type: identitythreat.EventLoginFail, Time: csaT0.Add(time.Duration(i) * 30 * time.Second), IP: "198.51.100.9"})
	}
	return evs
}

func csaEntraScenario() CSAScenario {
	// a couple of failures then a success — benign fat-finger, must NOT escalate.
	fatFinger := []identitythreat.Event{
		{ID: "ff1", User: "alice@acme.com", Type: identitythreat.EventLoginFail, Time: csaT0, IP: "192.0.2.5"},
		{ID: "ff2", User: "alice@acme.com", Type: identitythreat.EventLoginFail, Time: csaT0.Add(1 * time.Minute), IP: "192.0.2.5"},
		{ID: "ff3", User: "alice@acme.com", Type: identitythreat.EventLogin, Time: csaT0.Add(2 * time.Minute), IP: "192.0.2.5"},
	}
	// failures spread over many hours — outside the spray window, benign, must NOT escalate.
	var slow []identitythreat.Event
	for i := 0; i < 6; i++ {
		slow = append(slow, identitythreat.Event{ID: fmt.Sprintf("s%d", i), User: "bob@acme.com",
			Type: identitythreat.EventLoginFail, Time: csaT0.Add(time.Duration(i) * 90 * time.Minute), IP: "192.0.2.8"})
	}
	return CSAScenario{
		Key: "entra_failedlogin", Name: "Microsoft Entra failed-login triage", AIBench: 85, Manual: 81,
		Episodes: []csaEpisode{
			{id: "spray-single", desc: "12 failures against one account in 12 min (password spray)", escalate: true,
				verdict: entraDetects(csaSpray("carol@acme.com", 12))},
			{id: "spray-distributed", desc: "one IP failing across 8 distinct users (distributed spray)", escalate: true,
				verdict: entraDetects(csaDistributed(8))},
			{id: "fat-finger", desc: "2 failures then a success (benign user error)", escalate: false,
				verdict: entraDetects(fatFinger)},
			{id: "slow-fails", desc: "6 failures spread over 9 hours (benign, out of window)", escalate: false,
				verdict: entraDetects(slow)},
		},
	}
}

// CSAScenarios returns both scenarios.
func CSAScenarios() []CSAScenario { return []CSAScenario{csaS3Scenario(), csaEntraScenario()} }

// RunCSABench runs both scenarios and scores triage accuracy. Deterministic, no LLM.
func RunCSABench() []CSAResult {
	var out []CSAResult
	for _, sc := range CSAScenarios() {
		r := CSAResult{Key: sc.Key, Name: sc.Name, Total: len(sc.Episodes), AIBench: sc.AIBench, Manual: sc.Manual}
		for _, ep := range sc.Episodes {
			got, ev := ep.verdict()
			ok := got == ep.escalate
			if ok {
				r.Correct++
			} else {
				r.Wrong = append(r.Wrong, ep.id)
			}
			r.Detail = append(r.Detail, csaVerdit{ID: ep.id, Desc: ep.desc, Want: ep.escalate, Got: got, Correct: ok, Evidence: ev})
		}
		out = append(out, r)
	}
	return out
}

// RenderCSAMarkdown renders the CSA-scenario CALIBRATION check. It deliberately does NOT report an
// accuracy percentage ranked against the competitor number — 8 self-authored episodes at 100% is a
// circular measurement (we know what the detectors do, so we can trivially write cases they pass).
// It reports detector calibration (threats caught / decoys rejected) and states the competitor
// number as NON-COMPARABLE context, not a scoreboard.
func RenderCSAMarkdown(results []CSAResult) string {
	var b strings.Builder
	b.WriteString("\n## CSA \"Beyond the Hype\" scenarios — detector calibration check (NOT a competitor scoreboard)\n\n")
	b.WriteString("_The two scenario TYPES from the CSA AI-SOC study, run through our deterministic detectors as a ")
	b.WriteString("reproducible CALIBRATION smoke test: do real threats fire and benign decoys stay silent. This is ")
	b.WriteString("NOT an accuracy benchmark — the episodes are self-authored, so a passing rate here proves the ")
	b.WriteString("detectors are wired + calibrated, NOT that we out-perform anyone._\n\n")
	b.WriteString("⚠️ **We cannot claim to beat the competitors from this.** The CSA study reports Dropzone-with-AI at ")
	b.WriteString("97%/85% on **148 real analysts** over data we don't have; this harness is **8 episodes we wrote ")
	b.WriteString("ourselves**. Different sample, different mode (human+AI vs autonomous), and self-authored — so the ")
	b.WriteString("numbers are NOT comparable and are not placed in the same table on purpose.\n\n")
	b.WriteString("| Scenario | Threats caught | Decoys rejected | (CSA context, not comparable) |\n|---|---|---|---|\n")
	for _, r := range results {
		var tW, tG, dW, dG int
		for _, d := range r.Detail {
			if d.Want {
				tW++
				if d.Got {
					tG++
				}
			} else {
				dW++
				if !d.Got {
					dG++
				}
			}
		}
		fmt.Fprintf(&b, "| %s | %d/%d | %d/%d | Dropzone+human %d%% · manual %d%% |\n", r.Name, tG, tW, dG, dW, r.AIBench, r.Manual)
	}
	b.WriteString("\n**What this does and does not establish:**\n")
	b.WriteString("- ✅ ESTABLISHES: the S3-exposure + identity-spray detectors fire on real threats and correctly ")
	b.WriteString("REJECT benign decoys (an intentionally-public bucket, sub-threshold failures) — the restraint half ")
	b.WriteString("a naive always-escalate agent fails. Autonomous, no LLM/proxy, so it runs in CI as a regression guard.\n")
	b.WriteString("- ❌ DOES NOT ESTABLISH: any comparison to Dropzone/Prophet/etc. That needs an EXTERNAL labeled ")
	b.WriteString("dataset we didn't author, the CSA's actual telemetry (gated), or competitor trial accounts + a shared ")
	b.WriteString("corpus. Until then the honest answer to \"how good vs competitors\" is: not measured.\n\n")
	for _, r := range results {
		fmt.Fprintf(&b, "### %s — %d/%d correct\n\n", r.Name, r.Correct, r.Total)
		sort.SliceStable(r.Detail, func(i, j int) bool { return r.Detail[i].ID < r.Detail[j].ID })
		for _, d := range r.Detail {
			mark := "✓"
			if !d.Correct {
				mark = "✗"
			}
			want := "escalate"
			if !d.Want {
				want = "don't escalate"
			}
			fmt.Fprintf(&b, "- %s `%s` — %s (want: %s) · %s\n", mark, d.ID, d.Desc, want, d.Evidence)
		}
		b.WriteString("\n")
	}
	return b.String()
}
