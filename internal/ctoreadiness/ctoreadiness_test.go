package ctoreadiness

import (
	"strings"
	"testing"
)

// The value of a checklist is entirely in the rows it will NOT tick. These tests hold the properties
// that stop it becoming a sales sheet: an unconnected estate never reads as clean, an item only a
// human can answer is never inferred, and the things we do not do say so by name.

func byID(rs []Result, id string) *Result {
	for i := range rs {
		if rs[i].ID == id {
			return &rs[i]
		}
	}
	return nil
}

// ── THE CENTRAL PROPERTY ─────────────────────────────────────────────────────────────────────────

// An empty workspace must not read as compliant. Every observed row is answered by a scanner, and a
// scanner that never ran has not established anything — "we looked and it was clean" and "we never
// looked" render identically to a reader, which is why they must not render identically here.
func TestEmptyWorkspace_NeverReadsAsPassing(t *testing.T) {
	got := Assess(Input{Stage: TierSeriesC})
	for _, r := range got {
		if r.Evidence == EvidenceObserved && r.Status == StatusPass {
			t.Errorf("%s passed with nothing connected — that claims a scan that never ran: %q", r.ID, r.Detail)
		}
	}
	s := Summarize(TierSeriesC, got)
	if s.Pass != 0 {
		t.Errorf("an empty workspace scored %d passes", s.Pass)
	}
	if s.NotChecked == 0 {
		t.Error("nothing was reported as unchecked, so the empty state is indistinguishable from a clean one")
	}
}

// And the not-checked row must say what to connect. "Not checked" with no next step is just a shrug.
func TestNotChecked_SaysWhatToConnect(t *testing.T) {
	for _, r := range Assess(Input{Stage: TierSeriesC}) {
		if r.Status != StatusNotChecked || r.Evidence != EvidenceObserved {
			continue
		}
		if !strings.Contains(r.Detail, "Connect") {
			t.Errorf("%s is unchecked but does not say what to connect: %q", r.ID, r.Detail)
		}
	}
}

// ── EVIDENCE KINDS ARE NOT INTERCHANGEABLE ───────────────────────────────────────────────────────

// An attested row can only be answered by a person. If findings could move it, we would be inferring
// a process fact from scan output — precisely the overclaim this package exists to prevent.
func TestAttested_IsNeverInferredFromFindings(t *testing.T) {
	loud := Input{
		Stage:        TierSeriesC,
		AssetTypes:   map[string]bool{"repository": true, "web_application": true, "cloud_account": true},
		ConnKinds:    map[string]bool{"github": true, "aws": true},
		FindingTools: map[string]int{"gitleaks": 40, "prowler": 90, "nuclei": 25},
		FindingRules: map[string]int{"osint::stealer-log": 5},
	}
	for _, r := range Assess(loud) {
		if r.Evidence != EvidenceAttested {
			continue
		}
		if r.Status != StatusNeedsYou {
			t.Errorf("%s resolved to %q from findings alone — no scan can see this practice", r.ID, r.Status)
		}
	}
}

// A human's answer is what moves it, and both answers are recorded — including "no". A checklist that
// only records the yes is a checklist nobody should trust.
func TestAttested_RecordsBothAnswers(t *testing.T) {
	in := Input{Stage: TierSeriesC, Attestations: map[string]Attestation{
		"access.jit_elevation":          {Answered: true, InPlace: true, By: "cto@acme.com", At: "2026-08-15"},
		"appsec.version_control_review": {Answered: true, InPlace: false, By: "cto@acme.com", At: "2026-08-15"},
	}}
	got := Assess(in)

	yes := byID(got, "access.jit_elevation")
	if yes == nil || yes.Status != StatusPass {
		t.Fatalf("a confirmed practice did not pass: %+v", yes)
	}
	if yes.AttestedBy != "cto@acme.com" {
		t.Error("the answer was accepted without recording who gave it")
	}

	no := byID(got, "appsec.version_control_review")
	if no == nil || no.Status != StatusGap {
		t.Fatalf("a practice recorded as NOT in place did not read as a gap: %+v", no)
	}
	if no.AttestedBy == "" {
		t.Error("a negative answer was recorded anonymously")
	}
}

// ── THE ROWS WE DO NOT DO ────────────────────────────────────────────────────────────────────────

// An unbuilt row must say so, and must point somewhere useful. Naming a competitor's tool costs less
// than the trust lost when a customer discovers the gap themselves.
func TestUnbuilt_SaysSoAndNamesAnAlternative(t *testing.T) {
	found := 0
	for _, r := range Assess(Input{Stage: TierSeriesC}) {
		if r.Evidence != EvidenceUnbuilt {
			continue
		}
		found++
		if r.Status != StatusNotCovered {
			t.Errorf("%s is unbuilt but resolved to %q", r.ID, r.Status)
		}
		if !strings.Contains(r.Detail, "don't cover") {
			t.Errorf("%s does not plainly say we do not cover it: %q", r.ID, r.Detail)
		}
		if strings.TrimSpace(r.Instead) == "" {
			t.Errorf("%s leaves the customer with no alternative", r.ID)
		}
	}
	if found == 0 {
		t.Error("no row is marked unbuilt — a checklist that scores itself 30/30 is a sales sheet")
	}
}

// Every observed row must name the OSS that answers it, so a tick is checkable rather than trusted.
func TestObservedRows_NameTheirTools(t *testing.T) {
	for _, it := range Items() {
		if it.Evidence != EvidenceObserved {
			continue
		}
		if len(it.Tools) == 0 {
			t.Errorf("%s claims to be observed but names no tool — an unverifiable tick", it.ID)
		}
		if len(it.GapRules) == 0 {
			t.Errorf("%s names tools but nothing that could make it fail, so it can only ever pass", it.ID)
		}
	}
}

// ── STAGING ──────────────────────────────────────────────────────────────────────────────────────

// A seed company is not measured against a Series C bar. Getting this wrong makes the whole list
// read as unattainable, which is how checklists get closed and never reopened.
func TestStage_IsCumulativeAndBounded(t *testing.T) {
	seed := Assess(Input{Stage: TierSeed})
	all := Assess(Input{Stage: TierSeriesC})
	if len(seed) >= len(all) {
		t.Fatalf("seed scope (%d) is not smaller than series C (%d)", len(seed), len(all))
	}
	for _, r := range seed {
		if r.Tier != TierSeed {
			t.Errorf("a seed company is being measured on a %s practice: %s", r.Tier, r.ID)
		}
	}
	// Cumulative: Series B includes everything seed and Series A expect.
	b := Assess(Input{Stage: TierSeriesB})
	for _, s := range seed {
		if byID(b, s.ID) == nil {
			t.Errorf("series B dropped the seed practice %s", s.ID)
		}
	}
}

// An unknown stage must not silently measure someone against everything.
func TestUnknownStage_FallsBackToSeed(t *testing.T) {
	got := Assess(Input{Stage: Tier("series_z")})
	for _, r := range got {
		if r.Tier != TierSeed {
			t.Errorf("an unrecognised stage was measured on a %s practice", r.Tier)
		}
	}
}

// ── OBSERVED ROWS, DRIVEN BY REAL STATE ──────────────────────────────────────────────────────────

// With an asset connected and a matching finding, the row fails and says how many.
func TestConnectedWithFindings_ReadsAsGap(t *testing.T) {
	in := Input{
		Stage:        TierSeed,
		AssetTypes:   map[string]bool{"repository": true},
		FindingTools: map[string]int{"gitleaks": 3},
	}
	r := byID(Assess(in), "data.secrets_out_of_vcs")
	if r == nil || r.Status != StatusGap {
		t.Fatalf("3 leaked secrets did not produce a gap: %+v", r)
	}
	if r.GapCount != 3 {
		t.Errorf("gap count = %d, want 3", r.GapCount)
	}
}

// With the asset connected, SCANNED, and nothing found, it passes — and says which tool established
// that. The scan is the load-bearing half: see the test below for why presence alone is not enough.
func TestConnectedScannedAndClean_PassesAndCitesTheTool(t *testing.T) {
	in := Input{Stage: TierSeed,
		AssetTypes: map[string]bool{"repository": true},
		Scanned:    map[string]bool{"repository": true}}
	r := byID(Assess(in), "data.secrets_out_of_vcs")
	if r == nil || r.Status != StatusPass {
		t.Fatalf("a connected, scanned, clean repo did not pass: %+v", r)
	}
	if !strings.Contains(r.Detail, "gitleaks") {
		t.Errorf("a passing row does not say what established it: %q", r.Detail)
	}
}

// CONNECTED IS NOT SCANNED — the false pass this guard exists for.
//
// Found by driving a live tenant: adding one domain asset and never scanning it flipped six rows to
// pass, including "Checked by nuclei, hydra, naabu — nothing open" for an asset the engine had never
// touched. The coverage endpoint said scanned:false about that same asset at that same moment, so the
// product was contradicting itself; a CTO reads that row as "we tested for default credentials and
// found none".
func TestConnectedButNeverScanned_DoesNotPass(t *testing.T) {
	in := Input{Stage: TierSeed, AssetTypes: map[string]bool{"repository": true}} // no Scanned
	r := byID(Assess(in), "data.secrets_out_of_vcs")
	if r == nil {
		t.Fatal("row missing")
	}
	if r.Status == StatusPass {
		t.Fatalf("an asset that was never scanned reported PASS (%q) — that names tools which never "+
			"ran and asserts nothing was found", r.Detail)
	}
	if r.Status != StatusNotChecked {
		t.Errorf("status = %q, want not_checked", r.Status)
	}
	// And it must say WHY, or the customer cannot tell this from "connect a repository".
	if !strings.Contains(r.Detail, "not scanned yet") {
		t.Errorf("detail does not explain the state: %q", r.Detail)
	}
}

// A real finding still proves the check ran, even with no scan evidence recorded — an ingested
// posture snapshot produces findings without an engagement, and that row must stay a GAP rather than
// regress to "not scanned yet".
func TestFindingsStillProveTheCheckRan_WithoutScanEvidence(t *testing.T) {
	in := Input{Stage: TierSeed,
		AssetTypes:   map[string]bool{"repository": true},
		FindingTools: map[string]int{"gitleaks": 2}} // no Scanned
	r := byID(Assess(in), "data.secrets_out_of_vcs")
	if r == nil || r.Status != StatusGap {
		t.Fatalf("real findings did not produce a gap: %+v", r)
	}
	if r.GapCount != 2 {
		t.Errorf("gap count = %d, want 2", r.GapCount)
	}
}

// A connection that is not active must not count. The runner skips its assets, so counting it would
// claim coverage that is not happening — the same false-clean, one layer up.
func TestInactiveConnection_DoesNotCountAsCoverage(t *testing.T) {
	// ConnKinds is documented as ACTIVE connections only; the caller filters. This pins the contract
	// by showing an empty set yields not_checked rather than pass.
	in := Input{Stage: TierSeed, ConnKinds: map[string]bool{}}
	r := byID(Assess(in), "data.secrets_out_of_vcs")
	if r == nil || r.Status != StatusNotChecked {
		t.Fatalf("with no active connection the row should be unchecked, got %+v", r)
	}
}

// ── THE SUMMARY MUST NOT FLATTER ─────────────────────────────────────────────────────────────────

// Summarize deliberately has no single percentage. Rolling "never looked" in with "looked and clean"
// produces a number that rises when a customer connects nothing — the exact false comfort at issue.
func TestSummary_KeepsUncheckedSeparateFromPassing(t *testing.T) {
	s := Summarize(TierSeriesC, Assess(Input{Stage: TierSeriesC}))
	if s.Total != s.Pass+s.Gap+s.NotChecked+s.NeedsYou+s.NotCovered {
		t.Error("the buckets do not account for every item")
	}
	if s.NotChecked == 0 || s.NotCovered == 0 || s.NeedsYou == 0 {
		t.Errorf("an empty workspace should be mostly unchecked, needs-you and not-covered: %+v", s)
	}
}

// Ids must be unique — a duplicate would silently overwrite an attestation.
func TestItemIDs_AreUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, it := range Items() {
		if seen[it.ID] {
			t.Errorf("duplicate item id %q — an attestation on one would answer the other", it.ID)
		}
		seen[it.ID] = true
	}
	if len(seen) != 30 {
		t.Errorf("expected 30 practices, found %d", len(seen))
	}
}

// Findings are proof the check ran, and must not be suppressed by the Needs gate.
//
// Found by driving the real API: a posted SaaS posture snapshot produces sspm findings without any
// connection of that kind existing. Gating on Needs first reported those rows as "not checked" while
// the gaps sat in the store — the checklist hiding findings the product had already made.
func TestFindingsAreProofTheCheckRan(t *testing.T) {
	in := Input{
		Stage:        TierSeed,
		FindingRules: map[string]int{"sspm::slack::2fa-not-enforced": 1, "sspm::slack::sso-not-enforced": 1},
	}
	r := byID(Assess(in), "access.sso_mfa")
	if r == nil {
		t.Fatal("row missing")
	}
	if r.Status != StatusGap {
		t.Fatalf("real MFA findings resolved to %q — the checklist is hiding findings the product "+
			"already produced: %+v", r.Status, r)
	}
	if r.GapCount != 2 {
		t.Errorf("gap count = %d, want 2", r.GapCount)
	}
}

// The gate still does its real job: with neither findings nor anything connected, it is unchecked.
func TestNoFindingsAndNothingConnected_IsStillUnchecked(t *testing.T) {
	r := byID(Assess(Input{Stage: TierSeed}), "access.sso_mfa")
	if r == nil || r.Status != StatusNotChecked {
		t.Fatalf("an empty workspace should be unchecked, got %+v", r)
	}
}

// A row claiming both at-rest and in-transit encryption must not pass because a hostname exists.
func TestEncryption_NeedsCloudNotJustADomain(t *testing.T) {
	r := byID(Assess(Input{Stage: TierSeed, AssetTypes: map[string]bool{"domain": true}}), "cloud.encryption")
	if r == nil || r.Status != StatusNotChecked {
		t.Fatalf("a connected domain alone passed an encryption-at-rest row: %+v", r)
	}
}

// ── THE AGENTS ───────────────────────────────────────────────────────────────────────────────────

// A row is only actionable if we can say which findings it is made of. Matches is what lets a gap
// row hand its findings to the proposer instead of asking an agent to guess what to fix.
func TestMatches_SelectsTheFindingsBehindARow(t *testing.T) {
	var secrets Item
	for _, it := range Items() {
		if it.ID == "data.secrets_out_of_vcs" {
			secrets = it
		}
	}
	if !Matches(secrets, "gitleaks", "gitleaks::aws-key") {
		t.Error("a gitleaks finding does not match the secrets practice")
	}
	if Matches(secrets, "prowler", "prowler::s3-public") {
		t.Error("a cloud misconfiguration matched the source-secrets practice — a row that claims " +
			"unrelated findings would queue fixes for work the customer did not ask for")
	}
}

// Only measured rows belong to an agent. Asking an agent to "fix" whether your company reviews code
// is how a checklist starts inventing work, so process rows are owned by nobody.
func TestAgentOwnership_OnlyOnMeasuredRows(t *testing.T) {
	for _, it := range Items() {
		if it.Agent == "" {
			continue
		}
		if it.Evidence != EvidenceObserved {
			t.Errorf("%s is owned by the %s but is not measured by a scanner — there is nothing for "+
				"an agent to act on", it.ID, it.Agent)
		}
		if it.Agent != "engineer" && it.Agent != "pentester" {
			t.Errorf("%s names an unknown agent %q", it.ID, it.Agent)
		}
	}
}

// Both agents must own something, or the checklist is a report rather than a worklist.
func TestBothAgentsOwnRows(t *testing.T) {
	seen := map[string]int{}
	for _, it := range Items() {
		seen[it.Agent]++
	}
	if seen["engineer"] == 0 || seen["pentester"] == 0 {
		t.Errorf("one of the agents owns no practices: %v", seen)
	}
}
