package icpcheck

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// evidence_rungs_test.go is the anti-drift half of ADR 0029 D2d.
//
// The marketing pages claimed we prove findings across code, cloud, identity, web, API and
// containers. The engine EXPLOITS on two of those surfaces, asks the provider on one, reads the code
// on one, and reports a scanner's word on the rest. Rewriting the copy fixes that once; a guard is
// what stops it drifting back, because the copy and the capability live in different files, are
// edited by different people, and nothing else compares them.
//
// So the ladder is DATA on both sides — pkg/types/evidencerung.go and frontend/lib/evidence-rungs.ts
// — and this test fails when they disagree in either direction:
//
//   - a rung advertised that the engine cannot reach is a claim we cannot back;
//   - a rung the engine gained that nobody advertised is a capability quietly withheld, which is the
//     smaller failure but the same defect.

// engineRungs is the authority. Sorted for comparison, not for ranking.
func engineRungs() []string {
	return []string{
		string(types.RungExploited),
		string(types.RungProviderConfirmed),
		string(types.RungReachabilityConfirmed),
		string(types.RungCorroborated),
		string(types.RungScannerReported),
	}
}

var rungIDRe = regexp.MustCompile(`(?m)^\s*id:\s*"([a-z_]+)"`)

func TestMarketingLadderMirrorsTheEngineLadder(t *testing.T) {
	root := frontendDir(t)
	path := filepath.Join(root, "lib", "evidence-rungs.ts")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v\nThe marketing ladder is the file this guard exists to compare against; "+
			"if it moved, move the guard with it rather than letting the comparison lapse.", path, err)
	}

	var advertised []string
	for _, m := range rungIDRe.FindAllStringSubmatch(string(src), -1) {
		advertised = append(advertised, m[1])
	}
	if len(advertised) == 0 {
		t.Fatal("found no rung ids in the marketing ladder — the pattern matched nothing, so this guard " +
			"would pass while checking absolutely nothing (§14.2 rule 6)")
	}

	want, got := engineRungs(), append([]string(nil), advertised...)
	sort.Strings(want)
	sort.Strings(got)

	if strings.Join(want, ",") != strings.Join(got, ",") {
		t.Errorf("the marketing evidence ladder and the engine's do not match.\n  engine:    %v\n  marketing: %v\n"+
			"A rung on the page that the engine cannot reach is a claim we cannot back; a rung the engine "+
			"has that the page omits is a capability withheld. Fix whichever side is wrong — do not "+
			"delete this guard.", want, got)
	}
}

func TestExactlyOneAdvertisedRungClaimsExploitability(t *testing.T) {
	// The whole point of the ladder is that ONE rung means someone got in. If the page marked two,
	// the distinction it exists to draw would be gone, and it would be gone in the direction of
	// claiming more than the engine does.
	root := frontendDir(t)
	src, err := os.ReadFile(filepath.Join(root, "lib", "evidence-rungs.ts"))
	if err != nil {
		t.Fatalf("read the marketing ladder: %v", err)
	}
	if n := strings.Count(string(src), "claimsExploitability: true"); n != 1 {
		t.Errorf("%d advertised rungs claim exploitability, want exactly 1. types.EvidenceRung."+
			"ClaimsExploitability() returns true for one rung and the page must agree.", n)
	}
}

func TestProductPageDoesNotClaimUniformProof(t *testing.T) {
	// The specific sentence that shipped, kept as a regression rather than a style rule: the hero said
	// the engine "proves it" across four named surfaces, which is true on two of them.
	files := copyFiles(t, frontendDir(t))
	page, ok := files["app/(marketing)/product/page.tsx"]
	if !ok {
		t.Fatal("the product page is not among the copy surfaces this guard reads — if it moved, " +
			"update copyFiles rather than losing the check")
	}
	// Matched as a CLASS, not as the one sentence that shipped. The first version of this guard
	// checked the exact hero string and passed while the META DESCRIPTION — the same claim, in the
	// search result — still said "proves it" after the same list of four surfaces. A guard written
	// against one instance of a defect finds one instance of it.
	for _, claim := range []string{"reach, proves it", "SaaS, proves it", "and SaaS, proves"} {
		if strings.Contains(page, claim) {
			t.Errorf("the product page claims %q — it proves what an attacker could reach, across code, "+
				"cloud, identity and SaaS. The engine exploits on web and API, provider-confirms on AWS, "+
				"and reasons elsewhere (ADR 0029 D2d). Say which rung, or say less.", claim)
		}
	}
	if !strings.Contains(page, "EVIDENCE_RUNGS") {
		t.Error("the product page no longer renders the evidence ladder. It is the page's answer to " +
			"\"what do you mean by proved\", and without it the surrounding copy reads as uniform proof.")
	}
}
