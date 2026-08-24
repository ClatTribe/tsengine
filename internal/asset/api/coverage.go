package api

import (
	"fmt"
	"strconv"

	"github.com/ClatTribe/tsengine/internal/asset"
	"github.com/ClatTribe/tsengine/internal/asset/common"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// specFoundRule is the info finding openapi_spec_ingest emits when it resolves a spec.
// Its ToolArgs["operations"] is the operation count — the grounded signal that there is
// something an authorization test could be pointed at.
const specFoundRule = "openapi_spec_ingest::spec-found"

// authzGapRule names the disclosure. Under asset.CoverageRulePrefix, so internal/coverage
// surfaces it as a declared gap and EXCLUDES it from FindingsCount and ToolsWithFindings —
// without that exclusion, admitting a gap would raise the numbers describing how well the
// asset was covered.
const authzGapRule = asset.CoverageRulePrefix + "api-authorization-untested"

// CoverageGaps declares the single largest thing an api scan does not do.
//
// OWASP API1 (Broken Object Level Authorization) and API5 (Broken Function Level
// Authorization) are the top and middle of the list, and this product has a real
// differential prober for both — internal/apiauthz, which replays a victim's request as
// an attacker and flags a bypass only on a proven 2xx-with-victim-data. It does not run
// here and cannot: a differential authz test needs TWO REAL IDENTITIES, and no scan can
// invent them. It runs from POST /v1/assets/{id}/authz-test/run once an owner has
// declared them.
//
// So a normal api scan silently omits the two items a reader is most likely to assume it
// covered. That omission is invisible in a result list — a scan that never tested
// authorization and a scan that tested it and found nothing render identically, which is
// the §10 failure the coverage layer exists to prevent. ADR 0026 records this as the
// highest-value gap on the OWASP map, and it is a product gap wearing an engineering
// costume: the capability exists and nothing offers it.
//
// GROUNDED. The disclosure fires only when a spec was really ingested and really declared
// operations, because that is what makes the offer concrete — it can name how many
// operations are waiting. No spec, or a spec with no operations, means there is nothing to
// point a test at and nothing is claimed. It asserts an ABSENCE OF TESTING and never a
// vulnerability, so it is informational by construction.
// CoverageGaps returns BOTH of this asset's disclosures. The threat-informed half was missing:
// api runs threat-informed escalation (httpx joined its anchor set precisely to fingerprint the
// server), so a KEV-listed CVE can match observed software and still be untestable because nuclei
// ships no template for it. On web, ip and domain that vanishing set is declared through
// common.ThreatInformedGaps; on api it silently disappeared, which is the §10 failure this layer
// exists to prevent — a capped probe plan reads as "we checked everything" instead of "we checked
// what we could".
//
// COMPOSED, NOT REPLACED. The obvious fix — "add the CoverageGaps reporter, web/ip/domain pattern" —
// overwrites this method and deletes the authorization disclosure below, trading one silent gap for
// another. An asset can have more than one thing it did not check.
func (h *Handler) CoverageGaps(_ types.Asset, findings []types.Finding) []types.Finding {
	gaps := common.ThreatInformedGaps(findings)
	return append(gaps, h.authzGap(findings)...)
}

// authzGap is the disclosure this asset had all along; see the type comment above.
func (h *Handler) authzGap(findings []types.Finding) []types.Finding {
	ops, ok := declaredOperations(findings)
	if !ok || ops == 0 {
		return nil
	}
	return []types.Finding{{
		RuleID:   authzGapRule,
		Tool:     "coverage",
		Severity: types.SeverityInfo,
		Title:    fmt.Sprintf("Authorization was not tested on %d declared operations", ops),
		Description: fmt.Sprintf(
			"This scan checked %d operations for known signatures, injection and over-broad "+
				"responses, but it did NOT test object-level or function-level authorization "+
				"(OWASP API1 and API5) — whether one user can read or act on another user's "+
				"objects. That test is differential: it needs two real identities to compare, "+
				"and a scan cannot invent them, so no result here says anything either way "+
				"about authorization. TensorShield can run it: declare two test identities on "+
				"this asset and the same %d operations become a BOLA/BFLA differential test "+
				"that flags a bypass only on a proven read of the victim's data.",
			ops, ops),
		ToolArgs: map[string]string{
			"owasp_api":  "API1,API5",
			"operations": strconv.Itoa(ops),
			// Names the exact remedy, so the disclosure is actionable rather than a
			// standing caveat someone learns to scroll past.
			"remediation": "configure two test identities: POST /v1/assets/{id}/authz-test",
		},
	}}
}

// declaredOperations reads the operation count from the spec-ingest finding. Returns
// ok=false when no spec was ingested — distinct from a spec declaring zero operations,
// because "we never found a spec" and "the spec was empty" are different facts and only
// the second means the target genuinely has nothing to test.
func declaredOperations(findings []types.Finding) (int, bool) {
	for _, f := range findings {
		if f.RuleID != specFoundRule {
			continue
		}
		n, err := strconv.Atoi(f.ToolArgs["operations"])
		if err != nil {
			// The count is the only thing that makes the disclosure concrete. Rather than
			// guess at it, say nothing: a gap announced without the number it turns on
			// reads as boilerplate.
			return 0, false
		}
		return n, true
	}
	return 0, false
}
