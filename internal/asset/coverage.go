package asset

import (
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// CoverageRulePrefix namespaces every coverage-disclosure finding.
//
// The prefix IS the contract, and it is what makes disclosure work as a category rather
// than as one hard-coded special case. Downstream, internal/coverage surfaces anything
// carrying it as a declared gap and — the part that matters — EXCLUDES it from the
// asset's finding count and its tools-with-findings list. Without that exclusion a
// declared gap would inflate the numbers that describe how well an asset was covered,
// so admitting we could not check something would make the asset look MORE scanned.
//
// A new CoverageReporter gets both behaviours by using the prefix; nothing downstream
// needs to learn its name.
const CoverageRulePrefix = "coverage::"

// CoverageReporter is an OPTIONAL handler interface for declaring what a scan could
// NOT check.
//
// The orchestrator calls it after normalization and appends whatever it returns, so a
// handler that does not implement it is unaffected — the same shape as EscalationPlanner,
// ReconPlanner and ChildAssetExtractor.
//
// WHY THIS IS A SEPARATE SEAM FROM DETECTION. Every other output of a scan answers "what
// did we find". This answers "what did we look for and fail to check", and the two cannot
// share a path, because the whole risk with the second one is that it quietly becomes
// nothing at all. A scan that skipped a check and says so is different from a scan that
// found the target clean, and if the two render identically the customer has been told
// their estate is clear when part of it was never examined — which is the §10 failure this
// codebase spends the most effort avoiding.
//
// A coverage finding asserts an ABSENCE OF TESTING, never the presence of a vulnerability.
// Its severity reflects that we do not know, which is why these are informational: a scan
// that could not run a check has no evidence for a severity, and inventing one would be the
// same overclaim pointed the other way.
type CoverageReporter interface {
	// CoverageGaps returns informational findings naming what could not be checked.
	// Called with the scan's final findings, so a handler sees everything the scan
	// actually observed. Returning nil is correct and common — it means the scan ran
	// what it set out to run.
	CoverageGaps(target types.Asset, findings []types.Finding) []types.Finding
}

// IsCoverageGap reports whether a finding is a coverage disclosure rather than a security
// finding. See CoverageRulePrefix.
func IsCoverageGap(f types.Finding) bool {
	return strings.HasPrefix(f.RuleID, CoverageRulePrefix)
}
